# T1055.012 — Process Hollowing：Sysmon Config 缺口分析

## 缺口：Event 1（ProcessCreate）未記錄 notepad.exe

### 症狀

執行 `technique.py` 後，validator 回報 `gap: [1]`。
sysmon-modular 預設 config 的 ProcessCreate exclude 規則將 `notepad.exe` 排除在記錄範圍外，
導致目標 process 的建立事件未寫入 log。

### 根本原因

sysmon-modular 的 `sysmon-modular.xml` 在 ProcessCreate 段落包含類似以下的 exclude rule：

```xml
<ProcessCreate onmatch="exclude">
  ...
  <Image condition="end with">notepad.exe</Image>
  ...
</ProcessCreate>
```

此規則旨在減少低優先度應用的雜訊，但同時遮蔽了攻擊者使用 notepad.exe 作為 hollow 目標的偵測機會。

### 補救方案（二選一）

#### 方案 A：在 config 中新增 ProcessCreate include 覆蓋 exclude

在 `config/sysmon-modular.xml` 的 ProcessCreate exclude 段落之前新增：

```xml
<ProcessCreate onmatch="include">
  <!-- 以 CREATE_SUSPENDED 建立的 notepad.exe 為 Process Hollowing 典型目標 -->
  <Image condition="end with">notepad.exe</Image>
</ProcessCreate>
```

重新套用 config：
```powershell
sysmon64.exe -c config\sysmon-modular.xml
```

#### 方案 B（已採用）：改偵測 Event 25（ProcessTampering）

Event 25 是 Sysmon v13+ 新增的 ProcessTampering 事件，由 `NtUnmapViewOfSection` 觸發，
**直接偵測 hollowing 行為本身**，不依賴 ProcessCreate 是否被記錄。

`expected_events.json` 已更新為 `expected_event_ids: [10, 25]`，
validator 以 `child_pid` 精確比對 Event 25 的 `ProcessId` 欄位。

### 比較

| 事件 | 觸發條件 | 偵測精確度 |
|------|---------|-----------|
| Event 1 (ProcessCreate) | 建立目標 process | 低（任何 process 建立都觸發） |
| Event 10 (ProcessAccess) | OpenProcess 高權限存取 | 中（需搭配 access mask 篩選） |
| Event 25 (ProcessTampering) | NtUnmapViewOfSection / 映像替換 | **高（直接對應 hollowing 動作）** |

### 結論

採用方案 B（Event 25）更能準確反映 T1055.012 的本質行為，
且不需要修改 config 即可偵測。Event 1 的缺口記錄在此供參考。
