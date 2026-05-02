# T1134.004 — Sysmon Config Remediation

## 問題

`sysmon-modular` 預設的 `ProcessAccess`（Event 10）規則僅 include 已知高風險 access mask：

| Access Mask | 用途 |
|-------------|------|
| `0x1F0FFF` | PROCESS_ALL_ACCESS |
| `0x1410`   | VM_READ + QUERY_INFORMATION（常見 injection 前置動作）|
| `0x1010`   | VM_READ + QUERY_LIMITED_INFORMATION |

Parent PID Spoofing 只需要 `PROCESS_CREATE_PROCESS (0x0080)`，完全不在上述清單內，因此 Event 10 不觸發。

---

## 修正方式

在 `config/sysmon-modular.xml` 的 `<EventFiltering>` 內，找到 `ProcessAccess` 的 include 區塊，加入以下規則：

```xml
<!--
  T1134.004 Parent PID Spoofing detection
  攻擊者需以 PROCESS_CREATE_PROCESS (0x80) 開啟目標 process 才能偽造父 PID。
  此 access mask 在正常操作中極少對 explorer / winlogon 使用，誤報率低。
-->
<ProcessAccess onmatch="include">
  <Rule name="T1134.004_ParentSpoof_explorer" groupRelation="and">
    <GrantedAccess condition="is">0x80</GrantedAccess>
    <TargetImage   condition="end with">explorer.exe</TargetImage>
  </Rule>
  <Rule name="T1134.004_ParentSpoof_winlogon" groupRelation="and">
    <GrantedAccess condition="is">0x80</GrantedAccess>
    <TargetImage   condition="end with">winlogon.exe</TargetImage>
  </Rule>
  <Rule name="T1134.004_ParentSpoof_svchost" groupRelation="and">
    <GrantedAccess condition="is">0x80</GrantedAccess>
    <TargetImage   condition="end with">svchost.exe</TargetImage>
  </Rule>
</ProcessAccess>
```

### 為何用 `groupRelation="and"` + TargetImage 限縮

- 單獨 `GrantedAccess=0x80` 可能產生大量雜訊（例如某些 Windows 元件正常存取）。
- 限定 TargetImage 為常被偽裝的 parent（explorer、winlogon、svchost），精準度高。
- 若想更完整覆蓋（接受較多雜訊），可改為無 TargetImage 限制的寬鬆規則：

```xml
<!-- 寬鬆版：覆蓋任意 target，雜訊較多 -->
<ProcessAccess onmatch="include">
  <Rule name="T1134.004_ParentSpoof_any" groupRelation="or">
    <GrantedAccess condition="is">0x80</GrantedAccess>
  </Rule>
</ProcessAccess>
```

---

## 套用後的偵測邏輯

補上規則後，完整偵測需關聯兩個事件：

```
Event 10：SourceImage=<攻擊者>  TargetImage=explorer.exe  GrantedAccess=0x80
                   ↓  TargetProcessId == Event 1 的 ParentProcessId
Event 1 ：ParentImage=explorer.exe  CommandLine=<可疑指令>
           但 真實父（透過 ETW / kernel callback）≠ explorer.exe
```

單一 Event 10（GrantedAccess=0x80 對 explorer）可作為低可信度告警；
與後續 Event 1 的 ParentProcessId 關聯後升級為高可信度。

---

## 套用指令

```powershell
# 重新載入 Sysmon config（需 Admin）
sysmon64.exe -c config\sysmon-modular.xml
```

套用後重新執行驗測確認 Event 10 是否出現：

```powershell
python techniques\T1134.004_parent_pid_spoofing\technique.py
```
