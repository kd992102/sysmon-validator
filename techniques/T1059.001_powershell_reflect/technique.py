#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1059.001 — Command and Scripting Interpreter: PowerShell
MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/

呼叫 technique.ps1 執行 PowerShell 反射式載入：
  Add-Type 編譯暫存 DLL → 讀為 byte[] → 刪除磁碟檔案
  → Assembly.Load(bytes) 反射載入 → 呼叫 method（無落地執行）

預期觸發：
  Event 1 — powershell.exe ProcessCreate，CommandLine 含 T1059001_REFLECT_TEST
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

MARKER  = "T1059001_REFLECT_TEST"
PS1_REL = Path(__file__).parent / "technique.ps1"

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def run_powershell_reflect() -> dict:
    """
    以 subprocess.Popen 啟動 powershell.exe，呼叫 technique.ps1 -Marker <MARKER>。

    CommandLine 含 MARKER 字串，供 Sysmon Event 1 的 validator keyword 比對；
    child_pid 傳至 validator 做 ProcessId 精確比對。

    觸發的 Sysmon 事件：
      Event 1：powershell.exe ProcessCreate，CommandLine 含 T1059001_REFLECT_TEST
    """
    # 步驟 1：組合 PowerShell 呼叫命令
    # -Marker 參數使 MARKER 字串出現在 CommandLine，供 Sysmon Event 1 識別
    cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-File",    str(PS1_REL.resolve()),
        "-Marker",  MARKER,
    ]

    # 步驟 2：Popen 啟動，取得子 process PID
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = proc.pid
    print(f"  [*] powershell.exe 啟動，PID: {child_pid}", file=sys.stderr)

    # 步驟 3：等待 PowerShell 完成，印出輸出（逾時則強制終止）
    try:
        stdout, stderr = proc.communicate(timeout=30)
        if stdout:
            for line in stdout.decode("utf-8", errors="replace").splitlines():
                print(f"  [ps1] {line}", file=sys.stderr)
        if stderr:
            for line in stderr.decode("utf-8", errors="replace").splitlines():
                print(f"  [ps1:err] {line}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()

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

    if not PS1_REL.exists():
        print(f"[-] 找不到 technique.ps1：{PS1_REL}", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1059.001 — PowerShell 反射式執行")

    result = run_powershell_reflect()

    print(f"[+] powershell.exe 執行完畢，PID: {result['child_pid']}")
    print(f"[+] Sysmon Event 1 → powershell.exe ProcessCreate，CommandLine 含 {MARKER}")

    output = {
        "technique_id":  "T1059.001",
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
            "--technique",     "T1059.001",
            "--child-pid",     str(result["child_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
