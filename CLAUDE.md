# Sysmon Validator — 專案說明

## 專案目的
驗測 Sysmon + sysmon-modular config 對各種攻擊手法的偵測覆蓋率。
每個 technique 模擬真實攻擊行為，比對 Windows Event Log 是否出現預期的 Sysmon 事件。

---

## 環境

- OS：Windows Server 2022（VMware 隔離 VM，無對外網路）
- Python：3.10+（需以 Administrator 身份執行）
- 相依套件：pywin32、lxml
- Sysmon config：config/sysmon-modular.xml（Olaf Hartong 版）
- 版控：Git（本地），每個 technique 完成並驗測後 commit

---

## 目錄結構

sysmon-validator/
├── .git/
├── .gitignore
├── CLAUDE.md
├── config/
│   └── sysmon-modular.xml
├── techniques/
│   └── TXXXX_technique_name/
│       ├── technique.py          # Python 主腳本
│       ├── technique.ps1         # PowerShell 版（如適用）
│       ├── technique_cs/         # C# 專案資料夾（如適用）
│       │   └── Main.cs
│       └── expected_events.json
├── validator/
│   └── check_logs.py
├── report/
│   └── generate_report.py
└── run_all.py

---

## Technique 腳本語言規則

支援三種語言，依手法性質選擇：

Python（預設）
- 一般模擬、呼叫 Windows API 用 ctypes
- 適合：LOLBins 呼叫、Registry 操作、檔案行為

PowerShell
- 用 subprocess 從 Python 呼叫：subprocess.run(["powershell", "-File", "technique.ps1"])
- 適合：反射式載入、WMI、COM 物件操作
- 加上 -ExecutionPolicy Bypass 參數

C#（需要直接呼叫 Win32 API 時）
- 用 csc.exe 編譯或 Add-Type 動態編譯
- 適合：Process Injection、APC Injection、Handle 操作
- 放在 technique_cs/ 子資料夾

每個 technique 資料夾至少要有 Python 版本作為主腳本。
其他語言版本視手法需要增加。

---

## Technique 腳本規則

- 對應一個 MITRE ATT&CK ID（格式：T1234 或 T1234.001）
- 可獨立執行：python techniques/TXXXX_.../technique.py
- 執行完畢 print JSON 結果：
  {"technique_id": "T1134.004", "executed": true, "timestamp": "..."}
- 禁止硬編碼路徑，使用 pathlib.Path
- 每個步驟必須有繁體中文註解說明目的
- 執行前檢查是否有 Admin 權限，沒有就提示並退出

---

## expected_events.json 格式

{
  "technique_id": "T1134.004",
  "mitre_name": "Parent PID Spoofing",
  "expected_event_ids": [1, 10],
  "keywords": ["ParentProcessId", "PROCESS_CREATE"],
  "notes": "Event 1 應出現 ParentProcessId 異常；Event 10 為 process access"
}

---

## Validator 規則

- 使用 pywin32 的 win32evtlog 讀取 Microsoft-Windows-Sysmon/Operational
- 查詢範圍：technique 執行後 30 秒內
- 比對：event_id 存在 + 至少一個 keyword 出現在 Event XML 裡
- 輸出 JSON 給 generate_report.py 匯整

---

## Git 工作流程

初始化（只做一次）：
  git init
  git add .
  git commit -m "init: project structure and CLAUDE.md"

每個 technique 完成後：
  git add techniques/TXXXX_*/
  git commit -m "feat(T1134.004): add Parent PID Spoofing technique and expected events"

Commit 訊息格式：
  feat(TXXXX): 新增 technique
  fix(TXXXX): 修正腳本問題
  test(TXXXX): 更新 expected_events
  docs: 更新文件

---

## 報表輸出格式

JSON，欄位：
- technique_id、technique_name
- expected_event_ids（list）
- detected_event_ids（list）
- passed（bool）
- gap（list，預期有但沒抓到的 Event ID）
- timestamp

---

## 禁止事項

- 不要修改 validator/ 核心邏輯，除非我明確要求
- technique 腳本禁止任何網路連線
- 不使用第三方 C2 框架
- 每次只做一個 technique

---

## 當前優先順序

1. T1134.004 — Parent PID Spoofing（進行中）
2. T1055.012 — Process Hollowing
3. T1218.011 — Rundll32（LOLBin）
4. T1059.001 — PowerShell 反射式執行

---

## 給 Claude 的工作指引

- 生成 technique 前，先列出用到的 Windows API 和對應 Sysmon Event
- 程式碼加繁體中文註解
- 如果呼叫的 API 可能觸發 AV，先提示我
- 完成後提醒需要 Admin 執行
- 完成後給我對應的 git commit 指令
