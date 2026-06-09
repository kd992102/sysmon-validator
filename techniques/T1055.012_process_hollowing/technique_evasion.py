#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1055.012 — Process Hollowing (Evasion Variant)
MITRE ATT&CK: https://attack.mitre.org/techniques/T1055/012/

規避手法：跳過 NtUnmapViewOfSection，直接以 WriteProcessMemory 覆寫目標映像。
NtUnmapViewOfSection 是 sysmon-modular 偵測 Event 25 的觸發點；
略去此步驟後，Event 25 (ProcessTampering) 不再產生，gap=[25]。

預期行為（evasion test）：
  Event 10 — 仍觸發（OpenProcess(PROCESS_ALL_ACCESS) 不變）
  Event 25 — 不觸發（NtUnmapViewOfSection 已略去）→ gap=[25]
"""

import ctypes
import ctypes.wintypes
import datetime
import json
import os
import subprocess
import sys
import time
from pathlib import Path

# ── 常數 ──────────────────────────────────────────────────────────────────────

CREATE_SUSPENDED   = 0x00000004
CREATE_NO_WINDOW   = 0x08000000
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT         = 0x00001000
MEM_RESERVE        = 0x00002000
MEM_RELEASE        = 0x00008000
PAGE_READWRITE     = 0x00000004

MARKER = "T1055012_HOLLOW_EVASION"

# ── ctypes 型別別名 ────────────────────────────────────────────────────────────

DWORD  = ctypes.wintypes.DWORD
WORD   = ctypes.wintypes.WORD
HANDLE = ctypes.wintypes.HANDLE
BOOL   = ctypes.wintypes.BOOL
LPWSTR = ctypes.wintypes.LPWSTR
LPVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t
LPBYTE = ctypes.POINTER(ctypes.c_ubyte)

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              DWORD), ("lpReserved", LPWSTR), ("lpDesktop",   LPWSTR),
        ("lpTitle",         LPWSTR), ("dwX",        DWORD),  ("dwY",         DWORD),
        ("dwXSize",         DWORD),  ("dwYSize",    DWORD),  ("dwXCountChars", DWORD),
        ("dwYCountChars",   DWORD),  ("dwFillAttribute", DWORD), ("dwFlags", DWORD),
        ("wShowWindow",     WORD),   ("cbReserved2", WORD),  ("lpReserved2", LPBYTE),
        ("hStdInput",       HANDLE), ("hStdOutput", HANDLE), ("hStdError",   HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE), ("hThread", HANDLE),
        ("dwProcessId", DWORD), ("dwThreadId", DWORD),
    ]


kernel32.CreateProcessW.restype  = BOOL
kernel32.CreateProcessW.argtypes = [
    LPWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.OpenProcess.restype      = HANDLE
kernel32.OpenProcess.argtypes     = [DWORD, BOOL, DWORD]
kernel32.VirtualAllocEx.restype   = LPVOID
kernel32.VirtualAllocEx.argtypes  = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]
kernel32.WriteProcessMemory.restype  = BOOL
kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T)]
kernel32.VirtualFreeEx.restype    = BOOL
kernel32.VirtualFreeEx.argtypes   = [HANDLE, LPVOID, SIZE_T, DWORD]
kernel32.TerminateProcess.restype = BOOL
kernel32.TerminateProcess.argtypes = [HANDLE, ctypes.c_uint]
kernel32.CloseHandle.restype      = BOOL
kernel32.CloseHandle.argtypes     = [HANDLE]


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def hollow_process_evasion(target_cmdline: str) -> dict:
    """
    Process Hollowing 規避變體：略去 NtUnmapViewOfSection。

    與標準手法的差異：
      標準版：OpenProcess → NtUnmapViewOfSection → VirtualAllocEx → WriteProcessMemory
      本變體：OpenProcess → VirtualAllocEx → WriteProcessMemory（無 Unmap 步驟）

    規避效果：
      Event 10 仍觸發（OpenProcess 不變）
      Event 25 不觸發（NtUnmapViewOfSection 已略去，無 ProcessTampering 記錄）
    """
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd_buf = ctypes.create_unicode_buffer(target_cmdline)

    # 步驟 1：建立目標 process（CREATE_SUSPENDED），觸發 Sysmon Event 1
    if not kernel32.CreateProcessW(
        None, cmd_buf, None, None, False,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        None, None, ctypes.byref(si), ctypes.byref(pi),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    target_pid = int(pi.dwProcessId)

    try:
        # 步驟 2：以 PROCESS_ALL_ACCESS 開啟目標，觸發 Sysmon Event 10
        h_target = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_target:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            # 步驟 3：規避關鍵——直接跳過 NtUnmapViewOfSection
            # 不清空原始映像，Event 25 (ProcessTampering) 因此不產生
            print("  [*] NtUnmapViewOfSection skipped (evasion)", file=sys.stderr)

            # 步驟 4：VirtualAllocEx + WriteProcessMemory（模擬 payload 注入前置）
            marker_bytes = MARKER.encode()
            alloc_addr = kernel32.VirtualAllocEx(
                h_target, None, len(marker_bytes),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            )
            if alloc_addr:
                written = SIZE_T(0)
                kernel32.WriteProcessMemory(
                    h_target, ctypes.c_void_p(alloc_addr),
                    marker_bytes, len(marker_bytes), ctypes.byref(written),
                )
                kernel32.VirtualFreeEx(h_target, ctypes.c_void_p(alloc_addr), 0, MEM_RELEASE)
        finally:
            kernel32.CloseHandle(h_target)
    finally:
        # 步驟 5：終止目標 process（不 ResumeThread）
        kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hProcess)
        kernel32.CloseHandle(pi.hThread)

    return {"target_pid": target_pid, "target_cmdline": target_cmdline}


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    target_cmdline = f"notepad.exe {MARKER}"
    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1055.012 Evasion — 跳過 NtUnmapViewOfSection")

    result = hollow_process_evasion(target_cmdline)

    print(f"[+] 目標 process 建立並終止，PID: {result['target_pid']}")
    print(f"[+] Event 10 預期觸發（OpenProcess 不變）")
    print(f"[+] Event 25 預期缺失（NtUnmapViewOfSection 已略去）→ gap=[25]")

    output = {
        "technique_id":  "T1055.012",
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

    subprocess.run(
        [
            sys.executable, str(validator),
            "--technique",     "T1055.012",
            "--child-pid",     str(result["target_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
            "--evasion",
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
