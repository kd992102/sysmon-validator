#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1053.005 — Scheduled Task/Job: Scheduled Task
MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/

使用 schtasks.exe 建立一次性排程工作，模擬惡意程式設定持久化或延遲執行。
工作名稱含識別標記，執行後立即刪除，確保測試環境乾淨。

預期觸發：
  Event 1 — schtasks.exe ProcessCreate，CommandLine 含 T1053005_SCHTASK_TEST
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

MARKER    = "T1053005_SCHTASK_TEST"
TASK_NAME = MARKER

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def create_scheduled_task() -> dict:
    """
    以 schtasks.exe /create 建立一次性排程工作，觸發 Sysmon Event 1。

    工作名稱 = MARKER，使 CommandLine 含識別字串供 validator 比對。
    /st 00:00 /sd 2000/01/01 設定為過去時間，確保不會意外執行。
    建立後立即以 schtasks.exe /delete 刪除。

    觸發的 Sysmon 事件：
      Event 1 (ProcessCreate)：schtasks.exe，CommandLine 含 T1053005_SCHTASK_TEST
    """
    # 步驟 1：建立排程工作，工作名稱含 MARKER
    # /sc once /sd 2000/01/01 /st 00:00 → 觸發時間已過去，不會執行 calc.exe
    create_cmd = [
        "schtasks", "/create",
        "/tn", TASK_NAME,
        "/tr", r"C:\Windows\System32\notepad.exe",
        "/sc", "once",
        "/sd", "2000/01/01",
        "/st", "00:00",
        "/f",
    ]
    proc = subprocess.Popen(
        create_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    child_pid = proc.pid
    print(f"  [*] schtasks.exe /create 啟動，PID: {child_pid}", file=sys.stderr)

    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()

    print(f"  [*] Task '{TASK_NAME}' created", file=sys.stderr)

    # 步驟 2：立即刪除排程工作，確保不留持久化後門
    subprocess.run(
        ["schtasks", "/delete", "/tn", TASK_NAME, "/f"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    print(f"  [*] Task '{TASK_NAME}' deleted (cleanup)", file=sys.stderr)

    return {
        "child_pid": child_pid,
        "task_name": TASK_NAME,
        "cmdline":   " ".join(create_cmd),
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1053.005 — Scheduled Task Persistence")

    result = create_scheduled_task()

    print(f"[+] schtasks.exe 執行完畢，PID: {result['child_pid']}")
    print(f"[+] Sysmon Event 1 → schtasks.exe ProcessCreate，CommandLine 含 {MARKER}")

    output = {
        "technique_id":  "T1053.005",
        "executed":      True,
        "timestamp":     exec_ts,
        "technique_pid": os.getpid(),
        "details":       result,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))

    print("[*] 等待 Sysmon 寫入事件（5 秒）...", file=sys.stderr)
    time.sleep(5)

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
            "--technique",     "T1053.005",
            "--child-pid",     str(result["child_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
