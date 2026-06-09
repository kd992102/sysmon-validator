#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
MITRE ATT&CK: https://attack.mitre.org/techniques/T1547/001/

在 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 寫入識別值，
模擬惡意程式設定自啟動持久化。
執行後清除該值，確保測試環境不留後門。

預期觸發：
  Event 13 — RegistryEvent (Value Set)，TargetObject 含 T1547001_PERSIST_TEST
"""

import ctypes
import datetime
import json
import os
import subprocess
import sys
import time
import winreg
from pathlib import Path

# ── 常數 ──────────────────────────────────────────────────────────────────────

MARKER    = "T1547001_PERSIST_TEST"
RUN_KEY   = r"Software\Microsoft\Windows\CurrentVersion\Run"
# 寫入值：偽裝為無害的系統路徑，但 ValueName 含標記供 validator 識別
RUN_VALUE = r"C:\Windows\System32\notepad.exe"

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def set_run_key() -> dict:
    """
    在 HKCU Run 機碼下寫入自啟動值，模擬持久化手法。

    觸發的 Sysmon 事件：
      Event 13 (RegistrySetValue)：
        TargetObject = HKCU\...\Run\T1547001_PERSIST_TEST
        Details      = C:\Windows\System32\notepad.exe
    """
    # 步驟 1：開啟 Run 機碼（HKCU，不需 Admin 即可寫入）
    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        RUN_KEY,
        0,
        winreg.KEY_SET_VALUE,
    )

    # 步驟 2：寫入持久化值，觸發 Sysmon Event 13
    # ValueName = MARKER，供 validator 在 TargetObject 欄位識別
    winreg.SetValueEx(key, MARKER, 0, winreg.REG_SZ, RUN_VALUE)
    winreg.CloseKey(key)
    print(f"  [*] Registry value set: HKCU\\...\\Run\\{MARKER}", file=sys.stderr)

    # 步驟 3：立即清除測試值，確保不留持久化後門
    cleanup_key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        RUN_KEY,
        0,
        winreg.KEY_SET_VALUE,
    )
    winreg.DeleteValue(cleanup_key, MARKER)
    winreg.CloseKey(cleanup_key)
    print(f"  [*] Registry value cleaned up", file=sys.stderr)

    return {
        "registry_key":   f"HKCU\\{RUN_KEY}",
        "value_name":     MARKER,
        "value_data":     RUN_VALUE,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1547.001 — Registry Run Key Persistence")

    result = set_run_key()

    print(f"[+] Registry 持久化值已寫入並清除")
    print(f"[+] Sysmon Event 13 → RegistrySetValue，TargetObject 含 {MARKER}")

    output = {
        "technique_id":  "T1547.001",
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
            "--technique",     "T1547.001",
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
