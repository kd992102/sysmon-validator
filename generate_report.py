#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate_report.py — 將 report.json 轉換為 HTML 覆蓋率報表（含 Log 詳細內容）

用法：
  python generate_report.py
  python generate_report.py --input r.json --output r.html
"""

import argparse
import html as _html
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

_EVENT_NAMES: dict[int, str] = {
    1:  "ProcessCreate",
    7:  "ImageLoad",
    8:  "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent",
    13: "RegistryEvent (Value set)",
    22: "DNSEvent",
    25: "ProcessTampering",
}

# ── HTML 模板（CSS 區塊的 { } 用 {{ }} 跳脫，Python 替換欄位用單 { }）─────────

_HTML = """\
<!DOCTYPE html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sysmon 偵測覆蓋率報表</title>
  <style>
    body  {{ font-family: "Microsoft JhengHei", "Segoe UI", sans-serif; margin: 40px; color: #222; }}
    h1    {{ color: #1a5276; border-bottom: 3px solid #1a5276; padding-bottom: 8px; }}
    .meta {{ color: #666; font-size: .9em; margin-bottom: 24px; }}

    .summary {{ display: flex; gap: 24px; margin-bottom: 32px; flex-wrap: wrap; }}
    .card         {{ background: #f4f6f8; border-radius: 8px; padding: 16px 24px; min-width: 130px; text-align: center; }}
    .card .num    {{ font-size: 2em; font-weight: bold; }}
    .card .label  {{ font-size: .85em; color: #555; }}
    .pass-color   {{ color: #1e8449; }}
    .fail-color   {{ color: #c0392b; }}
    .bar-wrap     {{ background: #ddd; border-radius: 4px; height: 10px; width: 180px; margin: 8px auto 0; }}
    .bar-fill     {{ background: #1e8449; border-radius: 4px; height: 10px; }}

    table {{ border-collapse: collapse; width: 100%; }}
    th    {{ background: #1a5276; color: #fff; padding: 10px 14px; text-align: left; white-space: nowrap; }}
    td    {{ padding: 10px 14px; border-bottom: 1px solid #ddd; vertical-align: top; }}
    tr:hover > td {{ background: #f9f9f9; }}

    .badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: .85em; font-weight: bold; }}
    .pass  {{ background: #d5f5e3; color: #1e8449; }}
    .fail  {{ background: #fdecea; color: #c0392b; }}
    .etag  {{ background: #eaf2ff; color: #1a5276; border-radius: 4px; padding: 2px 6px; font-size: .8em; margin-right: 3px; display: inline-block; }}
    .gtag  {{ background: #fdecea; color: #c0392b; border-radius: 4px; padding: 2px 6px; font-size: .8em; margin-right: 3px; display: inline-block; }}
    .none  {{ color: #aaa; }}

    /* ── Log 詳細欄位 ── */
    .detail-col {{ min-width: 220px; }}
    details summary {{
      cursor: pointer; color: #1a5276; font-size: .85em;
      user-select: none; list-style: none;
    }}
    details summary::before {{ content: "▶ "; font-size: .75em; }}
    details[open] summary::before {{ content: "▼ "; }}
    details summary:hover {{ text-decoration: underline; }}

    .evbox      {{ margin: 6px 0; border: 1px solid #c8d8e8; border-radius: 6px; overflow: hidden; }}
    .evbox-hdr  {{ background: #d6eaf8; padding: 5px 10px; font-size: .82em;
                   font-weight: bold; color: #1a5276; border-bottom: 1px solid #c8d8e8; }}
    .evbox table {{ margin: 0; width: 100%; }}
    .evbox td    {{ padding: 3px 10px; font-size: .8em; border-bottom: 1px solid #f0f0f0;
                    font-family: "Consolas", "Courier New", monospace; }}
    .evbox tr:last-child td {{ border-bottom: none; }}
    .evbox td.fname  {{ color: #555; white-space: nowrap; width: 150px;
                        background: #fafafa; font-weight: normal; font-family: inherit; }}
    .evbox tr.hit td       {{ background: #fffbea; }}
    .evbox tr.hit td.fname {{ background: #fef3cd; color: #7d4e00; font-weight: bold; }}
    mark {{ background: #ffe066; padding: 0 2px; border-radius: 2px; font-weight: bold; color: #000; }}

    /* ── Baseline noise 指示器 ── */
    .bl-ok   {{ display: block; margin-top: 4px; font-size: .75em; color: #1e8449; }}
    .bl-ok::before {{ content: "▸ "; }}
    .bl-warn {{ display: block; margin-top: 4px; font-size: .75em;
                color: #7d4e00; background: #fef3cd;
                border-radius: 4px; padding: 1px 6px; }}
    .bl-warn::before {{ content: "⚠ "; }}
  </style>
</head>
<body>
  <h1>Sysmon 偵測覆蓋率報表</h1>
  <p class="meta">產生時間：{generated_at}　｜　資料來源：{source_file}　｜　Sysmon {sysmon_version}　｜　Config: {config_file} <code>({config_sha256_short})</code></p>

  <div class="summary">
    <div class="card">
      <div class="num">{total}</div>
      <div class="label">Techniques</div>
    </div>
    <div class="card">
      <div class="num pass-color">{passed}</div>
      <div class="label">PASS</div>
    </div>
    <div class="card">
      <div class="num fail-color">{failed}</div>
      <div class="label">FAIL</div>
    </div>
    <div class="card">
      <div class="num">{pct}%</div>
      <div class="label">覆蓋率</div>
      <div class="bar-wrap"><div class="bar-fill" style="width:{pct}%"></div></div>
    </div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Technique ID</th>
        <th>名稱</th>
        <th>預期事件</th>
        <th>偵測到事件</th>
        <th>缺口</th>
        <th>狀態</th>
        <th>Log 詳細</th>
        <th>時間戳</th>
      </tr>
    </thead>
    <tbody>
{rows}
    </tbody>
  </table>
</body>
</html>
"""

_ROW = """\
      <tr>
        <td><code>{tid}</code></td>
        <td>{name}</td>
        <td>{expected}</td>
        <td>{detected}</td>
        <td>{gap}</td>
        <td><span class="badge {cls}">{label}</span>{baseline_badge}</td>
        <td class="detail-col">{details}</td>
        <td><small>{ts}</small></td>
      </tr>"""


# ── 輔助函式 ──────────────────────────────────────────────────────────────────

def _etags(ids: list[int]) -> str:
    if not ids:
        return '<span class="none">—</span>'
    return "".join(f'<span class="etag">Event&nbsp;{i}</span>' for i in ids)


def _gtags(ids: list[int]) -> str:
    if not ids:
        return '<span class="none">—</span>'
    return "".join(f'<span class="gtag">Event&nbsp;{i}</span>' for i in ids)


def _highlight(value: str, keywords: list[str]) -> str:
    """將 value 中的 keywords 用 <mark> 包起來（先 HTML escape 再替換）"""
    escaped = _html.escape(value)
    for kw in keywords:
        if kw in value:
            escaped = escaped.replace(_html.escape(kw),
                                      f"<mark>{_html.escape(kw)}</mark>")
    return escaped


def _format_matched_events(matched: list[dict], keywords: list[str]) -> str:
    """將 matched_events 清單渲染為可折疊的 HTML 詳細區塊"""
    if not matched:
        return '<span class="none">—</span>'

    blocks: list[str] = []
    for ev in matched:
        eid       = ev.get("event_id", 0)
        fields    = ev.get("fields", {})
        hit_set   = set(ev.get("hit_fields", []))
        ename     = _EVENT_NAMES.get(eid, f"Event {eid}")

        field_rows = []
        for fname, fvalue in fields.items():
            is_hit     = fname in hit_set
            row_class  = ' class="hit"' if is_hit else ''
            cell_value = _highlight(fvalue, keywords) if is_hit else _html.escape(fvalue)
            field_rows.append(
                f'<tr{row_class}>'
                f'<td class="fname">{_html.escape(fname)}</td>'
                f'<td>{cell_value}</td>'
                f'</tr>'
            )

        blocks.append(
            f'<div class="evbox">'
            f'<div class="evbox-hdr">Event {eid} — {_html.escape(ename)}</div>'
            f'<table>{"".join(field_rows)}</table>'
            f'</div>'
        )

    count   = len(matched)
    summary = f"{count} 筆匹配事件"
    return f'<details><summary>{summary}</summary>{"".join(blocks)}</details>'


def _baseline_badge(r: dict) -> str:
    """baseline_noise 欄位對應的小型指示器"""
    if "baseline_noise" not in r:
        return ""
    if r["baseline_noise"]:
        n    = r.get("baseline_hit_count", "?")
        eids = r.get("baseline_hit_eids", [])
        return f'<span class="bl-warn">baseline noise ×{n} (EventID {eids})</span>'
    return '<span class="bl-ok">baseline clean</span>'


def _row(r: dict) -> str:
    ok       = r.get("passed", False)
    keywords = r.get("keywords", [])
    matched  = r.get("matched_events", [])
    return _ROW.format(
        tid            = _html.escape(r.get("technique_id", "")),
        name           = _html.escape(r.get("technique_name", "")),
        expected       = _etags(r.get("expected_event_ids", [])),
        detected       = _etags(r.get("detected_event_ids", [])),
        gap            = _gtags(r.get("gap", [])),
        cls            = "pass" if ok else "fail",
        label          = "PASS ✓" if ok else "FAIL",
        baseline_badge = _baseline_badge(r),
        details        = _format_matched_events(matched, keywords),
        ts             = _html.escape(r.get("timestamp", "")),
    )


# ── 主程式 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="產生 HTML 覆蓋率報表")
    parser.add_argument("--input",  default="report.json",
                        help="輸入 JSON 檔案（預設：report.json）")
    parser.add_argument("--output", default="report.html",
                        help="輸出 HTML 檔案（預設：report.html）")
    args = parser.parse_args()

    root        = Path(__file__).resolve().parent
    input_path  = Path(args.input)  if Path(args.input).is_absolute()  else root / args.input
    output_path = Path(args.output) if Path(args.output).is_absolute() else root / args.output

    if not input_path.exists():
        print(f"[-] 找不到輸入檔案：{input_path}（請先執行 run_all.py）",
              file=sys.stderr)
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    results: list[dict] = data.get("results", data) if isinstance(data, dict) else data

    total  = len(results)
    passed = sum(1 for r in results if r.get("passed"))
    failed = total - passed
    pct    = round(passed / total * 100) if total else 0

    # 從 report.json 頂層讀取 sysmon / config 資訊（舊格式無此欄位則顯示 unknown）
    meta = data if isinstance(data, dict) else {}

    html = _HTML.format(
        generated_at        = _html.escape(meta.get("generated_at",
                                datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))),
        source_file         = _html.escape(input_path.name),
        sysmon_version      = _html.escape(meta.get("sysmon_version",      "unknown")),
        config_file         = _html.escape(meta.get("config_file",         "unknown")),
        config_sha256_short = _html.escape(meta.get("config_sha256_short", "unknown")),
        total               = total,
        passed              = passed,
        failed              = failed,
        pct                 = pct,
        rows                = "\n".join(_row(r) for r in results),
    )

    output_path.write_text(html, encoding="utf-8")
    print(f"[+] 報表已產生：{output_path}")
    print(f"    覆蓋率：{passed}/{total}（{pct}%）")


if __name__ == "__main__":
    main()
