#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validator/check_logs.py — Sysmon/Operational 事件驗測工具

用法：
  python validator/check_logs.py --technique T1134.004 --child-pid 1234 --timestamp 2024-01-01T12:00:00Z
"""

import argparse
import ctypes
import ctypes.wintypes
import datetime
import json
import sys
from pathlib import Path

import win32evtlog

SYSMON_CHANNEL    = "Microsoft-Windows-Sysmon/Operational"
LOOK_AHEAD_SECS   = 60  # 延長至 60 秒，避免 Sysmon 非同步寫入延遲
START_BUFFER_SECS = 5   # exec_ts 前後各加緩衝，防止時鐘微偏
BASELINE_SECS     = 30  # exec_ts 前 30 秒作為 false-positive 基準視窗


def _find_root() -> Path:
    """上向搜尋包含 techniques/ 的專案根目錄，與 check_logs.py 放置位置無關"""
    current = Path(__file__).resolve().parent
    for _ in range(6):
        if (current / "techniques").is_dir():
            return current
        current = current.parent
    raise RuntimeError(f"找不到專案根目錄（從 {Path(__file__)} 往上找不到 techniques/）")


TECHNIQUES_DIR = _find_root() / "techniques"

# EvtQuery flags（部分舊版 pywin32 未匯出常數，直接宣告備用）
EVT_QUERY_CHANNEL_PATH = getattr(win32evtlog, "EvtQueryChannelPath",     0x1)
EVT_QUERY_FORWARD      = getattr(win32evtlog, "EvtQueryForwardDirection",  0x100)
EVT_QUERY_REVERSE      = getattr(win32evtlog, "EvtQueryReverseDirection",  0x200)
ERROR_NO_MORE_ITEMS    = 259
ERROR_TIMEOUT          = 1460   # EvtNext 在無結果時等待超時後拋出，需視為正常結束

# ── ctypes 直接呼叫 wevtapi.EvtRender，繞過 pywin32 wrapper 版本差異 ──────────
_wevtapi = ctypes.WinDLL("wevtapi")
_wevtapi.EvtRender.argtypes = [
    ctypes.c_void_p,                    # Context  (NULL → 使用預設)
    ctypes.c_void_p,                    # Fragment (事件 handle)
    ctypes.c_uint,                      # Flags    (1 = EvtRenderEventXml)
    ctypes.c_uint,                      # BufferSize (bytes)
    ctypes.c_void_p,                    # Buffer
    ctypes.POINTER(ctypes.c_uint),      # BufferUsed (out, bytes)
    ctypes.POINTER(ctypes.c_uint),      # PropertyCount (out)
]
_wevtapi.EvtRender.restype = ctypes.c_bool


def _render_xml(handle) -> str:
    """
    EvtRender を ctypes で直接呼び出し、イベントXML文字列を返す。
    pywin32 の EvtRender wrapper バージョン差異を完全に回避する。
    """
    _alive = handle          # PyHANDLE の GC を EvtRender 呼び出し完了まで防ぐ
    raw    = int(handle)     # Windows HANDLE 値（整数）
    buf_used   = ctypes.c_uint(0)
    prop_count = ctypes.c_uint(0)
    # 第一次呼叫：取得所需緩衝區大小（bytes），預期回傳 False + ERROR_INSUFFICIENT_BUFFER
    _wevtapi.EvtRender(None, raw, 1, 0, None,
                       ctypes.byref(buf_used), ctypes.byref(prop_count))
    size = buf_used.value
    if size == 0:
        return ""
    # c_ubyte（0-255）而非 c_byte（-128~127）才能直接轉為 bytes
    buf = (ctypes.c_ubyte * size)()
    # 第二次呼叫：實際渲染
    if not _wevtapi.EvtRender(None, raw, 1, size, buf,
                               ctypes.byref(buf_used), ctypes.byref(prop_count)):
        raise ctypes.WinError()
    # 回傳值為 UTF-16LE 編碼的 null-terminated 字串
    return bytes(buf[:buf_used.value]).decode("utf-16-le").rstrip("\x00")


# ── 輔助函式 ──────────────────────────────────────────────────────────────────

def load_expected(technique_id: str, evasion: bool = False) -> dict:
    """
    從對應 technique 資料夾讀取 expected_events.json 或 expected_events_evasion.json。
    evasion=True 時載入規避變體的預期定義，若該檔案不存在則 fallback 到標準版。
    """
    matches = list(TECHNIQUES_DIR.glob(f"{technique_id}*"))
    if not matches:
        raise FileNotFoundError(f"找不到 technique 資料夾：{technique_id}")
    folder = matches[0]
    if evasion:
        evasion_path = folder / "expected_events_evasion.json"
        if evasion_path.exists():
            return json.loads(evasion_path.read_text(encoding="utf-8"))
    json_path = folder / "expected_events.json"
    if not json_path.exists():
        raise FileNotFoundError(f"找不到 expected_events.json：{json_path}")
    return json.loads(json_path.read_text(encoding="utf-8"))


def build_xpath(event_ids: list[int], start: datetime.datetime, end: datetime.datetime) -> str:
    """
    建立 XPath 查詢：EventID 白名單 + 時間視窗。

    注意：
    - SystemTime 為 UTC，格式 YYYY-MM-DDTHH:MM:SS.NNNNNNNz（7 位小數）
    - XPath 做字串比較；end 時間使用 .9999999Z 確保同秒內的事件不被截斷
    - start 提前 START_BUFFER_SECS 秒，end 延後 START_BUFFER_SECS 秒，
      防止 exec_ts 與事件實際寫入時間有微小差距
    """
    id_clause = " or ".join(f"EventID={eid}" for eid in event_ids)
    buffered_start = start - datetime.timedelta(seconds=START_BUFFER_SECS)
    buffered_end   = end   + datetime.timedelta(seconds=START_BUFFER_SECS)
    # 起始用 0000000（含），結束用 9999999（含同秒所有 100ns 區間）
    s = buffered_start.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    e = buffered_end.strftime(  "%Y-%m-%dT%H:%M:%S.9999999Z")
    return (
        f"*[System[({id_clause}) and "
        f"TimeCreated[@SystemTime>='{s}' and @SystemTime<='{e}']]]"
    )


def query_events(xpath: str) -> list[str]:
    """
    用 EvtQuery / EvtNext / EvtRender 讀取 Sysmon channel。
    回傳所有符合條件的事件 XML 字串清單。
    """
    try:
        hq = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE,  # 從最新往舊掃，避免大型 log 正向掃描 timeout
            xpath,
        )
    except Exception as e:
        print(f"[-] EvtQuery 失敗（Sysmon 未安裝或無讀取權限）：{e}", file=sys.stderr)
        return []

    xml_list: list[str] = []
    while True:
        try:
            handles = win32evtlog.EvtNext(hq, 50, 1000, 0)
        except Exception as e:
            winerr = getattr(e, "winerror", None)
            # 259 = ERROR_NO_MORE_ITEMS：正常結束
            # 1460 = ERROR_TIMEOUT：查詢無結果時 EvtNext 等待超時，同樣視為正常結束
            if winerr in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT):
                break
            print(f"[-] EvtNext 失敗（winerror={winerr}）：{e}", file=sys.stderr)
            break
        if not handles:
            break
        for h in handles:
            try:
                xml = _render_xml(h)
                xml_list.append(xml)
            except Exception as e:
                print(f"[-] EvtRender 失敗：{e}", file=sys.stderr)

    return xml_list


def debug_recent_events(n: int = 3) -> None:
    """
    時間フィルタなしで最新 n 件の Sysmon 事件 (EventID + SystemTime) を stderr に表示。
    XPath 時間フィルタが正しいか診断するために使用。
    """
    try:
        hq = win32evtlog.EvtQuery(
            SYSMON_CHANNEL,
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE,  # 最新順
            "*",
        )
    except Exception as e:
        print(f"  [debug] EvtQuery 失敗：{e}", file=sys.stderr)
        return

    count = 0
    while count < n:
        try:
            handles = win32evtlog.EvtNext(hq, 1, 1000, 0)
        except Exception as e:
            if getattr(e, "winerror", None) in (ERROR_NO_MORE_ITEMS, ERROR_TIMEOUT):
                break
            print(f"  [debug] EvtNext 失敗：{e}", file=sys.stderr)
            break
        if not handles:
            break
        for h in handles:
            try:
                xml = _render_xml(h)
                eid = extract_event_id(xml)
                # 從 XML 取出 SystemTime 屬性值（Windows 使用單引號或雙引號）
                system_time = "unknown"
                for q in ('"', "'"):
                    marker = f"SystemTime={q}"
                    idx = xml.find(marker)
                    if idx != -1:
                        idx += len(marker)
                        system_time = xml[idx: xml.find(q, idx)]
                        break
                print(f"  [debug] #{count+1}  EventID={eid}  SystemTime={system_time}", file=sys.stderr)
                count += 1
            except Exception as e:
                print(f"  [debug] EvtRender 失敗：{e}", file=sys.stderr)


def extract_event_id(xml: str) -> int | None:
    """從事件 XML 字串快速取出 EventID（避免引入 lxml）"""
    tag = "<EventID>"
    s = xml.find(tag)
    if s == -1:
        return None
    s += len(tag)
    e = xml.find("</EventID>", s)
    if e == -1:
        return None
    try:
        return int(xml[s:e].strip())
    except ValueError:
        return None


def extract_field(xml: str, field_name: str) -> str | None:
    """從 Sysmon 事件 XML 取出特定 EventData/Data 欄位值（相容單引號與雙引號屬性）"""
    for q in ('"', "'"):
        marker = f"Name={q}{field_name}{q}>"
        idx = xml.find(marker)
        if idx != -1:
            start = idx + len(marker)
            end   = xml.find("<", start)
            if end != -1:
                return xml[start:end].strip()
    return None


# 各 Event ID 要擷取的關鍵欄位（供報表顯示用）
_KEY_FIELDS: dict[int, list[str]] = {
    1:  ["UtcTime", "ProcessId", "Image", "CommandLine",
         "ParentProcessId", "ParentImage", "User"],
    8:  ["UtcTime", "SourceProcessId", "SourceImage",
         "TargetProcessId", "TargetImage", "StartAddress"],
    10: ["UtcTime", "SourceProcessId", "SourceImage",
         "TargetProcessId", "TargetImage", "GrantedAccess"],
    25: ["UtcTime", "ProcessId", "Image", "Type", "User"],
}

# 各 Event ID 中無論如何都要高亮的鑑識關鍵欄位
_FORENSIC_HIGHLIGHT: dict[int, set[str]] = {
    1:  {"ParentImage", "ParentProcessId"},
    8:  {"TargetImage", "StartAddress"},
    10: {"GrantedAccess", "TargetImage"},
    25: {"Image", "Type"},
}


def _extract_event_fields(
    xml: str,
    eid: int,
    keywords: list[str],
    child_pid: int | None,
    technique_pid: int | None,
) -> dict:
    """從 XML 取出關鍵欄位並標記命中原因，供報表高亮顯示"""
    fields: dict[str, str] = {}
    hit_fields: set[str] = set()

    for name in _KEY_FIELDS.get(eid, []):
        value = extract_field(xml, name)
        if value is None:
            continue
        fields[name] = value
        if any(kw in value for kw in keywords):
            hit_fields.add(name)
        if name == "ProcessId" and child_pid is not None and value == str(child_pid):
            hit_fields.add(name)
        if name == "SourceProcessId" and technique_pid is not None and value == str(technique_pid):
            hit_fields.add(name)

    # 鑑識關鍵欄位：無論 match 原因為何都高亮
    hit_fields |= _FORENSIC_HIGHLIGHT.get(eid, set()) & fields.keys()

    return {
        "event_id":   eid,
        "fields":     fields,
        "hit_fields": sorted(hit_fields),
    }


# ── False-positive baseline check ────────────────────────────────────────────

def check_baseline(expected: dict, exec_ts: datetime.datetime) -> dict:
    """
    查詢 exec_ts 前 BASELINE_SECS 秒是否已有符合條件的事件。

    若有命中，代表偵測視窗可能受背景雜訊汙染，PASS 結果的可信度下降。
    這對應軟體測試中的 false positive 評估：在 SUT 尚未受到刺激前，
    test oracle 就已經回傳 "true" 的情況。
    """
    start = exec_ts - datetime.timedelta(seconds=BASELINE_SECS)
    end   = exec_ts

    id_clause = " or ".join(f"EventID={eid}" for eid in expected["expected_event_ids"])
    s = start.strftime("%Y-%m-%dT%H:%M:%S.0000000Z")
    e = end.strftime(  "%Y-%m-%dT%H:%M:%S.9999999Z")
    xpath = f"*[System[({id_clause}) and TimeCreated[@SystemTime>='{s}' and @SystemTime<='{e}']]]"

    xmls  = query_events(xpath)
    eids  = sorted({extract_event_id(x) for x in xmls} - {None})
    noise = len(xmls) > 0

    if noise:
        print(
            f"[!] Baseline noise: 執行前 {BASELINE_SECS}s 已有 {len(xmls)} 筆"
            f" EventID={eids}，PASS 結果可信度下降",
            file=sys.stderr,
        )
    else:
        print(f"[*] Baseline clean（前 {BASELINE_SECS}s 無背景雜訊）", file=sys.stderr)

    return {
        "baseline_noise":       noise,
        "baseline_hit_count":   len(xmls),
        "baseline_hit_eids":    eids,
        "baseline_window_secs": BASELINE_SECS,
    }


# ── 核心比對邏輯 ──────────────────────────────────────────────────────────────

def validate(
    expected: dict,
    event_xmls: list[str],
    child_pid: int | None,
    technique_pid: int | None = None,
) -> dict:
    """
    比對規則：
      event_id 在 expected_event_ids 內
      AND 以下任一條件成立：
        - keyword 出現在 XML 裡
        - Event 1：ProcessId == child_pid
        - Event 10：SourceProcessId == technique_pid（精確比對，防止背景雜訊誤判）
        - Event 25：ProcessId == child_pid（ProcessTampering 目標為 child process）
    """
    expected_ids   = set(expected["expected_event_ids"])
    keywords       = expected.get("keywords", [])
    detected_ids: set[int]      = set()
    matched_by_eid: dict[int, dict] = {}   # 每個 event_id 只保留一筆，優先 PID 精確命中

    for xml in event_xmls:
        eid = extract_event_id(xml)
        if eid not in expected_ids:
            continue

        keyword_hit = any(kw in xml for kw in keywords)

        # Event 1：ProcessId 欄位精確比對 child_pid
        event1_hit = (
            eid == 1
            and child_pid is not None
            and extract_field(xml, "ProcessId") == str(child_pid)
        )

        # Event 10：SourceProcessId 欄位精確比對 technique_pid
        event10_hit = (
            eid == 10
            and technique_pid is not None
            and extract_field(xml, "SourceProcessId") == str(technique_pid)
        )

        # Event 25：ProcessId 欄位精確比對 child_pid（被 hollow 的目標 process）
        event25_hit = (
            eid == 25
            and child_pid is not None
            and extract_field(xml, "ProcessId") == str(child_pid)
        )

        if keyword_hit or event1_hit or event10_hit or event25_hit:
            detected_ids.add(eid)
            is_precise = event1_hit or event10_hit or event25_hit
            # 尚無記錄 → 存入；已有 keyword 命中但現在是精確命中 → 覆蓋
            if eid not in matched_by_eid or is_precise:
                matched_by_eid[eid] = _extract_event_fields(
                    xml, eid, keywords, child_pid, technique_pid
                )

    matched_events = list(matched_by_eid.values())

    # Debug：若 Event 1 預期但未命中，印出查詢結果中 Event 1 的狀況
    if 1 in expected_ids and 1 not in detected_ids:
        ev1_xmls = [x for x in event_xmls if extract_event_id(x) == 1]
        print(f"  [debug] Event 1 在查詢結果中共 {len(ev1_xmls)} 筆", file=sys.stderr)
        for x in ev1_xmls:
            pid_val  = extract_field(x, "ProcessId")
            kw_hits  = [kw for kw in keywords if kw in x]
            print(
                f"  [debug] Event 1: ProcessId={pid_val!r}  "
                f"child_pid={child_pid}  kw_hits={kw_hits}",
                file=sys.stderr,
            )

    gap    = sorted(expected_ids - detected_ids)
    passed = len(gap) == 0

    return {
        "technique_id":       expected["technique_id"],
        "technique_name":     expected.get("mitre_name", ""),
        "expected_event_ids": sorted(expected_ids),
        "detected_event_ids": sorted(detected_ids),
        "passed":             passed,
        "gap":                gap,
        "matched_events":     matched_events,
        "keywords":           keywords,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Sysmon 事件驗測工具")
    parser.add_argument("--technique",     required=True,
                        help="MITRE ATT&CK ID，例如 T1134.004")
    parser.add_argument("--child-pid",     type=int, default=None,
                        help="technique 建立的子 process PID，用於 Event 1 精確比對")
    parser.add_argument("--technique-pid", type=int, default=None,
                        help="technique 本身的 PID，用於 Event 10 SourceProcessId 精確比對")
    parser.add_argument("--timestamp",     required=True,
                        help="technique 開始執行的時間（ISO 8601 UTC）")
    parser.add_argument("--evasion",       action="store_true",
                        help="載入 expected_events_evasion.json，測試規避變體")
    args = parser.parse_args()

    # 載入 expected_events.json（或 evasion 變體）
    try:
        expected = load_expected(args.technique, evasion=args.evasion)
    except FileNotFoundError as e:
        print(json.dumps({"error": str(e)}, ensure_ascii=False))
        sys.exit(1)

    # 解析時間視窗：timestamp → timestamp + 30s
    ts_str = args.timestamp.rstrip("Z")
    start  = datetime.datetime.fromisoformat(ts_str)
    end    = start + datetime.timedelta(seconds=LOOK_AHEAD_SECS)

    xpath = build_xpath(expected["expected_event_ids"], start, end)

    # ── debug：顯示目前 UTC 時間 vs 傳入時間戳，並印出最新 3 筆事件供比對 ──
    now_utc = datetime.datetime.utcnow()
    print(f"[debug] 目前 UTC     : {now_utc.strftime('%Y-%m-%dT%H:%M:%S')}",    file=sys.stderr)
    print(f"[debug] 傳入 timestamp : {args.timestamp}",                           file=sys.stderr)
    print(f"[debug] 查詢視窗     : {start - datetime.timedelta(seconds=START_BUFFER_SECS):%H:%M:%S}"
          f" ~ {end + datetime.timedelta(seconds=START_BUFFER_SECS):%H:%M:%S} UTC", file=sys.stderr)
    print(f"[debug] XPath        : {xpath}",                                      file=sys.stderr)
    print(f"[debug] Sysmon 最新 3 筆事件：",                                      file=sys.stderr)
    debug_recent_events(3)

    # ── false-positive baseline check：exec_ts 前 BASELINE_SECS 秒是否已有命中 ──
    baseline = check_baseline(expected, start)

    event_xmls = query_events(xpath)

    print(
        f"[*] 查到 {len(event_xmls)} 筆符合事件 "
        f"（視窗含緩衝：{LOOK_AHEAD_SECS + START_BUFFER_SECS * 2}s）",
        file=sys.stderr,
    )

    result = validate(expected, event_xmls, args.child_pid, args.technique_pid)
    result["timestamp"]    = args.timestamp
    result["evasion_test"] = args.evasion
    result.update(baseline)

    status = "PASS ✓" if result["passed"] else f"FAIL — gap: {result['gap']}"
    if result["baseline_noise"]:
        status += f"  ⚠ baseline noise ×{result['baseline_hit_count']}"
    print(f"[{'+'if result['passed'] else '-'}] {status}", file=sys.stderr)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
