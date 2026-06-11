#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1053.005 — Scheduled Task (Evasion Variant: COM API)
MITRE ATT&CK: https://attack.mitre.org/techniques/T1053/005/

規避手法：改用 Windows Task Scheduler COM API（Schedule.Service）建立排程工作，
完全不產生 schtasks.exe 子 process。

sysmon-modular 的 T1053.005 偵測依賴「schtasks.exe ProcessCreate」的 Event 1；
透過 COM API 操作 Task Scheduler 服務，繞過 process 層的偵測。

預期行為（evasion test）：
  Event 1 — 不觸發（無 schtasks.exe 子 process）→ gap=[1]
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

MARKER    = "T1053005_COM_EVASION"
TASK_NAME = MARKER

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def create_task_via_com() -> dict:
    """
    透過 COM API 建立排程工作，不產生 schtasks.exe 子 process。

    使用 Schedule.Service COM 物件直接呼叫 Task Scheduler 服務，
    整個操作在目前 process 的 address space 內完成（taskschd.dll in-proc COM）。
    無新 process 產生 → sysmon-modular 的 Event 1 偵測失效。

    規避的 Sysmon 事件：
      Event 1 (ProcessCreate)：schtasks.exe 不產生 → gap=[1]
    """
    import win32com.client

    # 步驟 1：連接 Task Scheduler 服務（in-proc COM，不產生子 process）
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    root_folder = scheduler.GetFolder("\\")
    print(f"  [*] Connected to Task Scheduler via COM (no child process)", file=sys.stderr)

    # 步驟 2：定義排程工作（觸發時間設為 2000 年，確保永不執行）
    task_def = scheduler.NewTask(0)
    task_def.RegistrationInfo.Description = MARKER

    trigger = task_def.Triggers.Create(1)   # TASK_TRIGGER_TIME
    trigger.StartBoundary = "2000-01-01T00:00:00"
    trigger.Enabled = True

    action = task_def.Actions.Create(0)     # TASK_ACTION_EXEC
    action.Path = r"C:\Windows\System32\notepad.exe"

    # 步驟 3：Register — 這是建立排程工作的核心 API 呼叫
    # 完全在目前 process 內完成，sysmon-modular 的 Event 1 不觸發
    root_folder.RegisterTaskDefinition(
        TASK_NAME,
        task_def,
        6,   # TASK_CREATE_OR_UPDATE
        "",  # user（當前使用者）
        "",  # password
        3,   # TASK_LOGON_INTERACTIVE_TOKEN
    )
    print(f"  [*] Task '{TASK_NAME}' registered via COM (schtasks.exe never spawned)", file=sys.stderr)

    # 步驟 4：立即刪除，確保不留持久化後門
    root_folder.DeleteTask(TASK_NAME, 0)
    print(f"  [*] Task '{TASK_NAME}' deleted (cleanup)", file=sys.stderr)

    return {
        "task_name": TASK_NAME,
        "method":    "COM API (Schedule.Service / taskschd.dll)",
        "child_pid": None,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1053.005 Evasion — COM API Scheduled Task（無 schtasks.exe）")

    result = create_task_via_com()

    print(f"[+] Task '{result['task_name']}' 建立並清除，無子 process 產生")
    print(f"[+] Event 1 預期缺失（schtasks.exe 未被呼叫）→ gap=[1]")

    output = {
        "technique_id":  "T1053.005",
        "executed":      True,
        "timestamp":     exec_ts,
        "technique_pid": os.getpid(),
        "evasion":       True,
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

    # --evasion：載入 expected_events_evasion.json
    # --child-pid 不傳（無子 process），純靠 keyword 比對確認 Event 1 不存在
    subprocess.run(
        [
            sys.executable, str(validator),
            "--technique",     "T1053.005",
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
            "--evasion",
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
