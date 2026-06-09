#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
run_all.py — 批次執行所有 technique 並收集驗測結果
需以 Administrator 身份執行

輸出：
  - 終端機：逐 technique 進度 + 最終彙整表
  - report.json：所有驗測結果，供 generate_report.py 使用
"""

import ctypes
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# check_logs.py validate() 的固定輸出欄位——缺任一個就不是 validator 結果
_VALIDATOR_KEYS = {"technique_id", "expected_event_ids", "detected_event_ids", "passed", "gap"}


def find_validator_result(stdout_bytes: bytes) -> dict | None:
    """
    從 stdout 掃描所有 JSON 物件，回傳符合 validator 指紋的最後一筆。

    識別條件：同時含有 _VALIDATOR_KEYS 全部五個欄位。
    單獨依賴 'passed' 容易誤命中 technique.py 自己輸出的 JSON；
    五欄位組合是 check_logs.validate() 的唯一輸出，不會與其他輸出重疊。
    """
    text = stdout_bytes.decode("utf-8", errors="replace")
    decoder = json.JSONDecoder()
    idx = 0
    last_validator = None
    while idx < len(text):
        pos = text.find("{", idx)
        if pos == -1:
            break
        try:
            obj, end = decoder.raw_decode(text, pos)
            if isinstance(obj, dict) and _VALIDATOR_KEYS.issubset(obj.keys()):
                last_validator = obj
            idx = end
        except json.JSONDecodeError:
            idx = pos + 1
    return last_validator


def run_technique(technique_dir: Path) -> dict | None:
    """
    執行單一 technique，回傳 validator 結果 dict。
    stderr 直接顯示（讓使用者看到即時進度），stdout 捕獲供 JSON 解析。
    """
    script = technique_dir / "technique.py"
    if not script.exists():
        return None

    print(f"\n{'=' * 60}")
    print(f"[*] {technique_dir.name}")
    print("=" * 60, flush=True)

    env = os.environ.copy()
    env["PYTHONUTF8"] = "1"   # 強制子 process 以 UTF-8 寫入 stdout pipe

    TIMEOUT = 180   # 每個 technique 最多 3 分鐘（5s sleep + 60s validator + 緩衝）
    try:
        proc = subprocess.run(
            [sys.executable, str(script)],
            stdout=subprocess.PIPE,
            stderr=None,            # stderr 直接輸出到終端機
            env=env,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"[-] 執行逾時（>{TIMEOUT}s），強制終止", file=sys.stderr)
        tid = technique_dir.name.split("_")[0]
        return {"technique_id": tid, "technique_name": "", "passed": False,
                "expected_event_ids": [], "detected_event_ids": [], "gap": [],
                "error": "timeout"}

    result = find_validator_result(proc.stdout)

    if result is None:
        tid = technique_dir.name.split("_")[0]
        print(f"[-] 無法取得驗測結果（returncode={proc.returncode}）", file=sys.stderr)
        return {"technique_id": tid, "technique_name": "", "passed": False,
                "expected_event_ids": [], "detected_event_ids": [], "gap": [],
                "error": "no_validator_result"}

    status = "PASS ✓" if result["passed"] else f"FAIL  gap={result['gap']}"
    marker = "+" if result["passed"] else "-"
    print(f"[{marker}] {status}")
    return result


def print_summary(results: list[dict]) -> None:
    passed = sum(1 for r in results if r.get("passed"))
    total  = len(results)
    ts     = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    print(f"\n{'=' * 60}")
    print(f"  覆蓋率彙整報表　{ts}")
    print("=" * 60)
    print(f"  {'Technique':<38} 狀態")
    print(f"  {'-' * 56}")
    for r in results:
        label  = f"{r.get('technique_id', '')} {r.get('technique_name', '')}".strip()
        status = "PASS ✓" if r.get("passed") else f"FAIL  gap={r.get('gap', [])}"
        print(f"  {label:<38} {status}")
    print(f"  {'-' * 56}")
    print(f"  總計：{passed}/{total} 通過")
    print("=" * 60)


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    root           = Path(__file__).resolve().parent
    techniques_dir = root / "techniques"

    technique_dirs = sorted(
        d for d in techniques_dir.iterdir()
        if d.is_dir() and (d / "technique.py").exists()
    )

    if not technique_dirs:
        print("[-] 找不到任何 technique（請確認 techniques/ 資料夾）", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 找到 {len(technique_dirs)} 個 technique，開始執行...")

    results: list[dict] = []
    for td in technique_dirs:
        r = run_technique(td)
        if r is not None:
            results.append(r)

    print_summary(results)

    report = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total":   len(results),
        "passed":  sum(1 for r in results if r.get("passed")),
        "results": results,
    }
    report_path = root / "report.json"
    report_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"\n[*] 結果已寫入 {report_path}")


if __name__ == "__main__":
    main()
