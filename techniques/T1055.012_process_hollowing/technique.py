#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1055.012 — Process Hollowing
MITRE ATT&CK: https://attack.mitre.org/techniques/T1055/012/

建立 notepad.exe（CREATE_SUSPENDED），以 PROCESS_ALL_ACCESS 開啟目標，
NtUnmapViewOfSection 清空映像，VirtualAllocEx + WriteProcessMemory 模擬 payload 注入，
最後 TerminateProcess 安全終止（不 ResumeThread，不執行任何注入程式碼）。

預期觸發：
  Event 1  — notepad.exe 以 CREATE_SUSPENDED 建立，CommandLine 含 T1055012_HOLLOW_TEST
  Event 10 — OpenProcess(PROCESS_ALL_ACCESS=0x1F0FFF) 存取目標 process
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

CREATE_SUSPENDED        = 0x00000004
CREATE_NO_WINDOW        = 0x08000000
PROCESS_ALL_ACCESS      = 0x1F0FFF
MEM_COMMIT              = 0x00001000
MEM_RESERVE             = 0x00002000
MEM_RELEASE             = 0x00008000
PAGE_READWRITE          = 0x00000004
ProcessBasicInformation = 0              # NtQueryInformationProcess class
PEB_IMAGE_BASE_OFFSET   = 16            # PEB.ImageBaseAddress 在 64-bit 下的偏移 (0x10)

# ── ctypes 型別別名 ────────────────────────────────────────────────────────────

DWORD    = ctypes.wintypes.DWORD
WORD     = ctypes.wintypes.WORD
HANDLE   = ctypes.wintypes.HANDLE
BOOL     = ctypes.wintypes.BOOL
LPWSTR   = ctypes.wintypes.LPWSTR
LPVOID   = ctypes.c_void_p
SIZE_T   = ctypes.c_size_t
LPBYTE   = ctypes.POINTER(ctypes.c_ubyte)
NTSTATUS = ctypes.c_long

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll    = ctypes.WinDLL("ntdll",    use_last_error=True)

# ── 結構定義 ──────────────────────────────────────────────────────────────────


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              DWORD),
        ("lpReserved",      LPWSTR),
        ("lpDesktop",       LPWSTR),
        ("lpTitle",         LPWSTR),
        ("dwX",             DWORD), ("dwY",             DWORD),
        ("dwXSize",         DWORD), ("dwYSize",         DWORD),
        ("dwXCountChars",   DWORD), ("dwYCountChars",   DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags",         DWORD),
        ("wShowWindow",     WORD),
        ("cbReserved2",     WORD),
        ("lpReserved2",     LPBYTE),
        ("hStdInput",       HANDLE),
        ("hStdOutput",      HANDLE),
        ("hStdError",       HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    HANDLE),
        ("hThread",     HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId",  DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    """NtQueryInformationProcess(ProcessBasicInformation) 回傳結構（64-bit）"""
    _fields_ = [
        ("ExitStatus",                    LPVOID),  # NTSTATUS
        ("PebBaseAddress",                LPVOID),  # PEB* — 目標 process 的 PEB 位址
        ("AffinityMask",                  LPVOID),
        ("BasePriority",                  LPVOID),
        ("UniqueProcessId",               SIZE_T),
        ("InheritedFromUniqueProcessId",  LPVOID),
    ]


# ── API 原型宣告 ───────────────────────────────────────────────────────────────

kernel32.CreateProcessW.restype  = BOOL
kernel32.CreateProcessW.argtypes = [
    LPWSTR, LPWSTR, LPVOID, LPVOID, BOOL, DWORD, LPVOID, LPWSTR,
    ctypes.POINTER(STARTUPINFOW), ctypes.POINTER(PROCESS_INFORMATION),
]

kernel32.OpenProcess.restype  = HANDLE
kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD]

kernel32.ReadProcessMemory.restype  = BOOL
kernel32.ReadProcessMemory.argtypes = [
    HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T),
]

kernel32.VirtualAllocEx.restype  = LPVOID
kernel32.VirtualAllocEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, DWORD]

kernel32.WriteProcessMemory.restype  = BOOL
kernel32.WriteProcessMemory.argtypes = [
    HANDLE, LPVOID, LPVOID, SIZE_T, ctypes.POINTER(SIZE_T),
]

kernel32.VirtualFreeEx.restype  = BOOL
kernel32.VirtualFreeEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD]

kernel32.TerminateProcess.restype  = BOOL
kernel32.TerminateProcess.argtypes = [HANDLE, ctypes.c_uint]

kernel32.CloseHandle.restype  = BOOL
kernel32.CloseHandle.argtypes = [HANDLE]

ntdll.NtQueryInformationProcess.restype  = NTSTATUS
ntdll.NtQueryInformationProcess.argtypes = [
    HANDLE, ctypes.c_int, LPVOID, ctypes.c_ulong,
    ctypes.POINTER(ctypes.c_ulong),
]

ntdll.NtUnmapViewOfSection.restype  = NTSTATUS
ntdll.NtUnmapViewOfSection.argtypes = [LPVOID, LPVOID]

# ── 輔助函式 ──────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    """確認目前 process 是否以 Administrator 身份執行"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def nt_success(status: int) -> bool:
    """NTSTATUS 0x00000000 ~ 0x3FFFFFFF 為 Success"""
    return 0 <= ctypes.c_long(status).value < 0x40000000


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def hollow_process(target_cmdline: str) -> dict:
    """
    以 Process Hollowing 模式操作目標 process（安全版：不 ResumeThread）。

    觸發的 Sysmon 事件：
      Event 1  : 目標 process 以 CREATE_SUSPENDED 建立
      Event 10 : OpenProcess(PROCESS_ALL_ACCESS) 對目標 process
    """
    # 步驟 1：建立目標 process（SUSPENDED，不會執行任何程式碼）
    # 觸發 Sysmon Event 1，CommandLine 含 T1055012_HOLLOW_TEST 供 validator 識別
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()
    cmd_buf = ctypes.create_unicode_buffer(target_cmdline)

    if not kernel32.CreateProcessW(
        None, cmd_buf, None, None, False,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        None, None,
        ctypes.byref(si), ctypes.byref(pi),
    ):
        raise ctypes.WinError(ctypes.get_last_error())

    target_pid = int(pi.dwProcessId)

    try:
        # 步驟 2：以 PROCESS_ALL_ACCESS 重新開啟目標，觸發 Sysmon Event 10
        # （攻擊者需要 VM_WRITE / VM_OPERATION 才能做記憶體注入）
        h_target = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_target:
            raise ctypes.WinError(ctypes.get_last_error())

        try:
            # 步驟 3：NtQueryInformationProcess 取得目標 process 的 PEB 位址
            pbi      = PROCESS_BASIC_INFORMATION()
            ret_len  = ctypes.c_ulong(0)
            status   = ntdll.NtQueryInformationProcess(
                h_target, ProcessBasicInformation,
                ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len),
            )
            if not nt_success(status):
                raise OSError(
                    f"NtQueryInformationProcess 失敗：NTSTATUS=0x{status & 0xFFFFFFFF:08X}"
                )

            peb_addr = pbi.PebBaseAddress
            print(f"  [*] PEB 位址：0x{peb_addr:016X}", file=sys.stderr)

            # 步驟 4：從 PEB + 0x10 讀取 ImageBaseAddress（64-bit 固定偏移）
            image_base  = ctypes.c_void_p(0)
            bytes_read  = SIZE_T(0)
            if not kernel32.ReadProcessMemory(
                h_target,
                ctypes.c_void_p(peb_addr + PEB_IMAGE_BASE_OFFSET),
                ctypes.byref(image_base),
                ctypes.sizeof(image_base),
                ctypes.byref(bytes_read),
            ):
                raise ctypes.WinError(ctypes.get_last_error())

            print(f"  [*] ImageBase：0x{image_base.value:016X}", file=sys.stderr)

            # 步驟 5：NtUnmapViewOfSection 清空目標映像（hollow 的關鍵動作）
            status    = ntdll.NtUnmapViewOfSection(h_target, image_base)
            unmap_ok  = nt_success(status)
            print(
                f"  [*] NtUnmapViewOfSection：0x{status & 0xFFFFFFFF:08X} "
                f"({'OK' if unmap_ok else 'FAIL'})",
                file=sys.stderr,
            )

            # 步驟 6：VirtualAllocEx 配置記憶體（模擬注入前置準備）
            marker     = b"T1055012_HOLLOW_TEST"
            alloc_addr = kernel32.VirtualAllocEx(
                h_target, None, len(marker),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE,
            )

            if alloc_addr:
                # 步驟 7：WriteProcessMemory 寫入標記（模擬 payload 注入）
                written = SIZE_T(0)
                kernel32.WriteProcessMemory(
                    h_target, ctypes.c_void_p(alloc_addr),
                    marker, len(marker), ctypes.byref(written),
                )
                print(f"  [*] WriteProcessMemory：{written.value} bytes", file=sys.stderr)
                kernel32.VirtualFreeEx(
                    h_target, ctypes.c_void_p(alloc_addr), 0, MEM_RELEASE
                )

        finally:
            kernel32.CloseHandle(h_target)

    finally:
        # 步驟 8：終止目標 process（不 ResumeThread，確保注入程式碼永不執行）
        kernel32.TerminateProcess(pi.hProcess, 1)
        kernel32.CloseHandle(pi.hProcess)
        kernel32.CloseHandle(pi.hThread)

    return {
        "target_pid":     target_pid,
        "target_cmdline": target_cmdline,
    }


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    # 權限確認
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    # 目標：notepad.exe，args 含 marker 供 validator 在 Event 1 CommandLine 識別
    target_cmdline = "notepad.exe T1055012_HOLLOW_TEST"

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 目標 process：{target_cmdline}")

    result = hollow_process(target_cmdline)

    print(f"[+] 目標 process 建立並終止，PID: {result['target_pid']}")
    print(f"[+] Sysmon Event 1  → notepad.exe 以 CREATE_SUSPENDED 建立，CommandLine 含 T1055012_HOLLOW_TEST")
    print(f"[+] Sysmon Event 10 → 本 process 以 PROCESS_ALL_ACCESS(0x1F0FFF) 存取目標")

    output = {
        "technique_id":  "T1055.012",
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
            "--technique",     "T1055.012",
            "--child-pid",     str(result["target_pid"]),
            "--technique-pid", str(os.getpid()),
            "--timestamp",     exec_ts,
        ],
        check=False,
    )


if __name__ == "__main__":
    main()
