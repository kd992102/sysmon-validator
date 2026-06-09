# T1059.001 — PowerShell Fileless Reflective Execution
# Python 端已完成編譯與磁碟清理，本腳本只做記憶體內 Assembly.Load
param(
    [string]$Marker     = "T1059001_REFLECT_TEST",
    [string]$PayloadB64 = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($PayloadB64 -eq "") {
    Write-Host "[-] PayloadB64 is empty. Run via technique.py." -ForegroundColor Red
    exit 1
}

# 步驟 1：Base64 解碼為 byte[]（payload 由 Python 預先編譯，此處不接觸磁碟）
$bytes = [System.Convert]::FromBase64String($PayloadB64)
Write-Host "  [*] Decoded $($bytes.Length) bytes from base64" -ForegroundColor DarkGray

# 步驟 2：反射式載入（Assembly.Load 從記憶體直接載入，不依賴磁碟路徑）
$assembly = [System.Reflection.Assembly]::Load($bytes)
$type     = $assembly.GetType("T1059001Payload")
$result   = $type.GetMethod("Execute").Invoke($null, $null)

Write-Host "[+] Reflect result: $result"
