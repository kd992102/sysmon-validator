# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案目的

驗測 Sysmon + sysmon-modular config 對各種攻擊手法的偵測覆蓋率。
每個 technique 模擬真實攻擊行為，比對 Windows Event Log 是否出現預期的 Sysmon 事件。

---

## 環境

- OS：Windows Server 2022（VMware 隔離 VM，無對外網路）
- Python：3.10+（需以 Administrator 身份執行）
- 相依套件：pywin32、lxml
- Sysmon config：`config/sysmon-modular.xml`（Olaf Hartong 版）

---

## 執行指令

```powershell
# 執行單一 technique（需 Admin）
python techniques/TXXXX_name/technique.py

# 執行所有 technique 並產生報表
python run_all.py

# 驗測特定 technique 的 Sysmon 事件
python validator/check_logs.py --technique T1134.004
```

---

## Technique 腳本語言規則

依手法性質選擇語言，每個資料夾至少要有 Python 版：

| 語言 | 使用時機 |
|------|---------|
| Python（預設） | LOLBins 呼叫、Registry 操作、檔案行為；Windows API 用 ctypes |
| PowerShell | 反射式載入、WMI、COM 物件；由 Python 以 `subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-File", "technique.ps1"])` 呼叫 |
| C# | Process Injection、APC Injection、Handle 操作；放 `technique_cs/`，用 `csc.exe` 或 `Add-Type` 編譯 |

---

## Technique 腳本規則

- 對應一個 MITRE ATT&CK ID（格式：T1234 或 T1234.001）
- 執行完畢 print JSON 結果：
  ```json
  {"technique_id": "T1134.004", "executed": true, "timestamp": "..."}
  ```
- 禁止硬編碼路徑，使用 `pathlib.Path`
- 每個步驟必須有**繁體中文**註解說明目的
- 執行前檢查 Admin 權限，沒有則提示並退出

---

## expected_events.json 格式

```json
{
  "technique_id": "T1134.004",
  "mitre_name": "Parent PID Spoofing",
  "expected_event_ids": [1, 10],
  "keywords": ["ParentProcessId", "PROCESS_CREATE"],
  "notes": "Event 1 應出現 ParentProcessId 異常；Event 10 為 process access"
}
```

---

## Validator 行為

- 使用 pywin32 的 `win32evtlog` 讀取 `Microsoft-Windows-Sysmon/Operational`
- 查詢範圍：technique 執行後 30 秒內
- 比對條件：event_id 存在 **且** 至少一個 keyword 出現在 Event XML 裡
- 輸出 JSON 給 `generate_report.py` 匯整

---

## 報表輸出格式（JSON）

欄位：`technique_id`、`technique_name`、`expected_event_ids`（list）、`detected_event_ids`（list）、`passed`（bool）、`gap`（list，預期有但沒抓到的 Event ID）、`timestamp`

---

## Commit 訊息格式

```
feat(TXXXX): 新增 technique
fix(TXXXX): 修正腳本問題
test(TXXXX): 更新 expected_events
docs: 更新文件
```

每個 technique 完成後：
```powershell
git add techniques/TXXXX_*/
git commit -m "feat(T1234.001): add <technique name> technique and expected events"
```

---

## 禁止事項

- 不要修改 `validator/` 核心邏輯，除非明確要求
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

- 生成 technique 前，先列出用到的 Windows API 和對應 Sysmon Event ID
- 如果呼叫的 API 可能觸發 AV，先提示使用者
- 完成後提醒需以 Admin 執行，並提供對應的 git commit 指令
