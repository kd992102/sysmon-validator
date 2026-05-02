#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
validator/check_logs.py — Sysmon/Operational 事件驗測工具

用法：
  python validator/check_logs.py --technique T1134.004 --child-pid 1234 --timestamp 2024-01-01T12:00:00Z
"""

import argparse
import datetime
import json
import sys
from pathlib import Path

import win32evtlog

SYSMON_CHANNEL  = "Microsoft-Windows-Sysmon/Operational"
LOOK_AHEAD_SECS = 60    # 延長至 60 秒，避免 Sysmon 非同步寫入延遲
START_BUFFER_SECS = 5   # exec_ts 前後各加緩衝，防止時鐘微偏


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
EVT_RENDER_EVENT_XML   = getattr(win32evtlog, "EvtRenderEventXml",         1)
ERROR_NO_MORE_ITEMS    = 259
ERROR_TIMEOUT          = 1460   # EvtNext 在無結果時等待超時後拋出，需視為正常結束


# ── 輔助函式 ──────────────────────────────────────────────────────────────────

def load_expected(technique_id: str) -> dict:
    """從對應 technique 資料夾讀取 expected_events.json"""
    matches = list(TECHNIQUES_DIR.glob(f"{technique_id}*"))
    if not matches:
        raise FileNotFoundError(f"找不到 technique 資料夾：{technique_id}")
    json_path = matches[0] / "expected_events.json"
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
            EVT_QUERY_CHANNEL_PATH | EVT_QUERY_FORWARD,
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
                xml = win32evtlog.EvtRender(None, h, EVT_RENDER_EVENT_XML)
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
                xml = win32evtlog.EvtRender(None, h, EVT_RENDER_EVENT_XML)
                eid = extract_event_id(xml)
                # 從 XML 取出 SystemTime 屬性值
                marker = 'SystemTime="'
                idx = xml.find(marker)
                if idx != -1:
                    idx += len(marker)
                    system_time = xml[idx: xml.find('"', idx)]
                else:
                    system_time = "unknown"
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


# ── 核心比對邏輯 ──────────────────────────────────────────────────────────────

def validate(
    expected: dict,
    event_xmls: list[str],
    child_pid: int | None,
) -> dict:
    """
    比對規則（與 CLAUDE.md 一致）：
      event_id 在 expected_event_ids 內
      AND（至少一個 keyword 出現在 XML 裡 OR child_pid 出現在 XML 裡）
    """
    expected_ids = set(expected["expected_event_ids"])
    keywords     = expected.get("keywords", [])
    detected_ids: set[int] = set()

    for xml in event_xmls:
        eid = extract_event_id(xml)
        if eid not in expected_ids:
            continue

        keyword_hit  = any(kw in xml for kw in keywords)
        # child_pid 備援：Event 1 的 ProcessId 欄位
        pid_hit      = child_pid is not None and str(child_pid) in xml

        if keyword_hit or pid_hit:
            detected_ids.add(eid)

    gap    = sorted(expected_ids - detected_ids)
    passed = len(gap) == 0

    return {
        "technique_id":       expected["technique_id"],
        "technique_name":     expected.get("mitre_name", ""),
        "expected_event_ids": sorted(expected_ids),
        "detected_event_ids": sorted(detected_ids),
        "passed":             passed,
        "gap":                gap,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Sysmon 事件驗測工具")
    parser.add_argument("--technique",  required=True,
                        help="MITRE ATT&CK ID，例如 T1134.004")
    parser.add_argument("--child-pid",  type=int, default=None,
                        help="technique 建立的子 process PID（備援比對用）")
    parser.add_argument("--timestamp",  required=True,
                        help="technique 開始執行的時間（ISO 8601 UTC）")
    args = parser.parse_args()

    # 載入 expected_events.json
    try:
        expected = load_expected(args.technique)
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

    event_xmls = query_events(xpath)

    print(
        f"[*] 查到 {len(event_xmls)} 筆符合事件 "
        f"（視窗含緩衝：{LOOK_AHEAD_SECS + START_BUFFER_SECS * 2}s）",
        file=sys.stderr,
    )

    result = validate(expected, event_xmls, args.child_pid)
    result["timestamp"] = args.timestamp

    status = "PASS ✓" if result["passed"] else f"FAIL — gap: {result['gap']}"
    print(f"[{'+'if result['passed'] else '-'}] {status}", file=sys.stderr)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
