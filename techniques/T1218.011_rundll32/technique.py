#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1218.011 — Signed Binary Proxy Execution: Rundll32
MITRE ATT&CK: https://attack.mitre.org/techniques/T1218/011/

使用 rundll32.exe 代理執行合法系統 DLL（advpack.dll）的匯出函式，
以 LOLBin 手法繞過直接執行惡意程式的偵測。
CommandLine 含識別標記，觸發 Sysmon Event 1（ProcessCreate）。

預期觸發：
  Event 1 — rundll32.exe ProcessCreate，CommandLine 含 T1218011_RUNDLL32_TEST
"""

import ctypes
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ── 常數 ──────────────────────────────────────────────────────────────────────

MARKER = "T1218011_RUNDLL32_TEST"

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def run_rundll32_lolbin() -> dict:
    """
    以 rundll32.exe advpack.dll,RegisterOCX <MARKER> 觸發 LOLBin 代理執行。

    Process 建立後立即以 kill() 終止：Sysmon Event 1 由 kernel callback 在建立瞬間觸發，
    early kill 不影響事件記錄，但可阻止 RegisterOCX 執行到 MessageBox 呼叫。

    觸發的 Sysmon 事件：
      Event 1：rundll32.exe ProcessCreate，CommandLine 含 T1218011_RUNDLL32_TEST
    """
    # 步驟 1：以 Popen 啟動 rundll32.exe，取得子 process PID
    # advpack.dll 是合法 Windows 系統 DLL；RegisterOCX 為其匯出函式
    # Sysmon Event 1 的 CommandLine 欄位將包含 MARKER，供 validator 識別
    cmd = ["rundll32.exe", "advpack.dll,RegisterOCX", MARKER]
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = proc.pid
    print(f"  [*] rundll32.exe 啟動，PID: {child_pid}", file=sys.stderr)

    # 步驟 2：立即終止 rundll32
    # Sysmon Event 1 由 PsSetCreateProcessNotifyRoutineEx kernel callback 在 process
    # 建立瞬間觸發，早於任何 user-mode 程式碼執行。因此立刻 kill() 仍可確保 Event 1 被記錄，
    # 同時避免 advpack.dll,RegisterOCX 在 LoadLibrary 失敗後呼叫 MessageBox。
    proc.kill()
    proc.wait()

    return {
        "child_pid": child_pid,
        "cmdline":   " ".join(cmd),
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    # 權限確認
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1218.011 — Signed Binary Proxy Execution: Rundll32")

    result = run_rundll32_lolbin()

    print(f"[+] rundll32.exe 執行完畢，PID: {result['child_pid']}")
    print(f"[+] CommandLine: {result['cmdline']}")
    print(f"[+] Sysmon Event 1 → rundll32.exe ProcessCreate，CommandLine 含 {MARKER}")

    output = {
        "technique_id":  "T1218.011",
        "executed":      True,
        "timestamp":     exec_ts,
        "technique_pid": os.getpid(),
        "details":       result,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))

    print("[*] 等待 Sysmon 寫入事件（5 秒）...", file=sys.stderr)
    time.sleep(5)

    # 向上找包含 techniques/ 的專案根目錄
    root = Path(__file__).resolve().parent
    for _ in range(6):
        if (root / "techniques").is_dir():
            break
        root = root.parent
    validator = root / "validator" / "check_logs.py"
    if not validator.exists():
        print(f"[-] 找不到 validator：{validator}", file=sys.stderr)
        return

    subprocess.run(
        [
            sys.executable, str(validator),
            "--technique",     "T1218.011",
            "--child-pid",     str(result["child_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
