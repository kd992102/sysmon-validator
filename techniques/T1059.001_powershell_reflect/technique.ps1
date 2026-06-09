# T1059.001 — PowerShell Reflective Execution
# 流程：Add-Type 編譯暫存 DLL → 讀成 byte[] → 刪除磁碟檔案 → Assembly.Load 反射載入 → 呼叫 method
param(
    [string]$Marker = "T1059001_REFLECT_TEST"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# 步驟 1：以 Add-Type 將最小化 C# payload 編譯成暫存 DLL
# 使用 $Marker 作為識別標記，確保 CommandLine 中可見
$tempDll = [System.IO.Path]::Combine(
    [System.IO.Path]::GetTempPath(),
    "$Marker.dll"
)

Add-Type -TypeDefinition @"
using System;
public class T1059001Payload {
    public static string Execute() { return "${Marker}_OK"; }
}
"@ -OutputAssembly $tempDll -Language CSharp

Write-Host "  [*] Compiled: $tempDll" -ForegroundColor DarkGray

# 步驟 2：讀取 DLL 內容為 byte[]，模擬攻擊者從網路或 Base64 解碼取得 payload
$bytes = [System.IO.File]::ReadAllBytes($tempDll)
Write-Host "  [*] Read $($bytes.Length) bytes" -ForegroundColor DarkGray

# 步驟 3：刪除磁碟上的暫存 DLL（模擬無落地執行）
Remove-Item $tempDll -Force -ErrorAction SilentlyContinue
Write-Host "  [*] Disk DLL removed" -ForegroundColor DarkGray

# 步驟 4：反射式載入（Assembly.Load 從記憶體直接載入，不依賴磁碟路徑）
$assembly = [System.Reflection.Assembly]::Load($bytes)
$type     = $assembly.GetType("T1059001Payload")
$result   = $type.GetMethod("Execute").Invoke($null, $null)

Write-Host "[+] Reflect result: $result"
