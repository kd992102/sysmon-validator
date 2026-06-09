#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
T1059.001 — Command and Scripting Interpreter: PowerShell (Fileless Variant)
MITRE ATT&CK: https://attack.mitre.org/techniques/T1059/001/

改進版：Python 負責編譯與磁碟清理，PowerShell 純記憶體操作。
  1. csc.exe 編譯 C# payload → DLL bytes
  2. base64 encode → 刪除磁碟上的 .cs / .dll
  3. 將 base64 字串以 -PayloadB64 參數傳入 technique.ps1
  4. PowerShell：Assembly.Load(FromBase64String(...)) — 不落地

前版使用 Add-Type -OutputAssembly，DLL 會短暫存在於磁碟；
本版的 DLL 全程在 Python 的 TemporaryDirectory 內，technique.ps1 不接觸磁碟。

預期觸發：
  Event 1 — powershell.exe ProcessCreate，CommandLine 含 T1059001_REFLECT_TEST
"""

import base64
import ctypes
import datetime
import json
import os
import subprocess
import sys
import tempfile
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


def find_csc() -> Path | None:
    """尋找 .NET Framework 的 csc.exe（64-bit 優先，fallback 32-bit）"""
    candidates = [
        Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
        Path(r"C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe"),
    ]
    for p in candidates:
        if p.exists():
            return p
    # 嘗試 PATH
    try:
        r = subprocess.run(["where", "csc"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            return Path(r.stdout.strip().splitlines()[0])
    except Exception:
        pass
    return None


def compile_payload(marker: str) -> str:
    """
    在 TemporaryDirectory 內編譯最小化 C# payload。

    步驟：
      csc.exe 編譯 .cs → .dll
      讀取 .dll bytes → base64 encode
      TemporaryDirectory context exit 時自動刪除 .cs 與 .dll

    回傳 base64 字串（ASCII），由呼叫端以 -PayloadB64 傳入 PowerShell。
    PowerShell 整個執行週期中，磁碟上不存在此 DLL。
    """
    csc = find_csc()
    if csc is None:
        raise RuntimeError("找不到 csc.exe，請確認 .NET Framework 4.x 已安裝")

    cs_source = f"""\
using System;
public class T1059001Payload {{
    public static string Execute() {{ return "{marker}_OK"; }}
}}
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        src = Path(tmpdir) / "payload.cs"
        dll = Path(tmpdir) / "payload.dll"
        src.write_text(cs_source, encoding="utf-8")

        # 步驟 1：csc.exe 編譯（磁碟上短暫存在於 TemporaryDirectory）
        proc = subprocess.run(
            [str(csc), f"/out:{dll}", "/target:library", "/nologo", str(src)],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"csc.exe 編譯失敗：{proc.stderr.strip()}")

        # 步驟 2：讀取 bytes，base64 encode
        dll_bytes = dll.read_bytes()

    # 步驟 3：TemporaryDirectory 已在 context exit 時自動刪除 .cs + .dll
    b64 = base64.b64encode(dll_bytes).decode("ascii")
    print(f"  [*] Payload 編譯完成：{len(dll_bytes)} bytes → {len(b64)} chars base64", file=sys.stderr)
    print(f"  [*] 磁碟 DLL 已由 TemporaryDirectory 自動清除", file=sys.stderr)
    return b64


# ── 核心手法 ──────────────────────────────────────────────────────────────────


def run_powershell_reflect(payload_b64: str) -> dict:
    """
    以 -PayloadB64 傳入預先編譯的 base64 payload，
    PowerShell 透過 Assembly.Load(FromBase64String(...)) 直接載入——不落地。

    CommandLine 含 MARKER，供 Sysmon Event 1 識別。
    """
    # 步驟 1：組合命令，-PayloadB64 攜帶預編譯 payload
    cmd = [
        "powershell",
        "-ExecutionPolicy", "Bypass",
        "-NoProfile",
        "-File",        str(PS1_REL.resolve()),
        "-Marker",      MARKER,
        "-PayloadB64",  payload_b64,
    ]

    # 步驟 2：Popen 啟動，取得子 process PID
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    child_pid = proc.pid
    print(f"  [*] powershell.exe 啟動，PID: {child_pid}", file=sys.stderr)

    # 步驟 3：等待 PowerShell 完成，印出輸出
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

    return {"child_pid": child_pid}


# ── 主程式 ────────────────────────────────────────────────────────────────────


def main() -> None:
    if not is_admin():
        print("[-] 需要 Administrator 權限，請以系統管理員身份重新執行。", file=sys.stderr)
        sys.exit(1)

    if not PS1_REL.exists():
        print(f"[-] 找不到 technique.ps1：{PS1_REL}", file=sys.stderr)
        sys.exit(1)

    exec_ts = datetime.datetime.utcnow().isoformat() + "Z"
    print(f"[*] 執行 T1059.001 — PowerShell Fileless Reflective Execution")

    # Python 端編譯並清理磁碟，PowerShell 只收 base64 字串
    try:
        payload_b64 = compile_payload(MARKER)
    except RuntimeError as e:
        print(f"[-] {e}", file=sys.stderr)
        sys.exit(1)

    result = run_powershell_reflect(payload_b64)

    print(f"[+] powershell.exe 執行完畢，PID: {result['child_pid']}")
    print(f"[+] DLL 全程不落地：Python 編譯 → base64 → 傳入 PowerShell → Assembly.Load")
    print(f"[+] Sysmon Event 1 → CommandLine 含 {MARKER}")

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
