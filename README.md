# sysmon-validator

Automated framework for validating Sysmon detection coverage against MITRE ATT&CK techniques.

Simulates real attack behaviors, queries Windows Event Log, and reports which Sysmon events were (or were not) captured — including evasion variants that deliberately bypass specific detection rules.

## Requirements

- Windows Server 2022 (isolated VM recommended)
- Python 3.10+ (must run as Administrator)
- `pywin32`, `lxml`
- Sysmon with [sysmon-modular](https://github.com/olafhartong/sysmon-modular) config loaded

## Usage

```powershell
# Run a single technique (Admin required)
python techniques/T1218.011_rundll32/technique.py

# Run all techniques and generate report.json
python run_all.py

# Convert report.json to HTML coverage report
python generate_report.py

# Validate Sysmon events for a specific technique
python validator/check_logs.py --technique T1134.004
```

## Implemented Techniques

| Technique | ID | Tactic | Expected Events | Evasion Variant |
|---|---|---|---|---|
| Parent PID Spoofing | T1134.004 | Defense Evasion | Event 1, 10 | — |
| Process Hollowing | T1055.012 | Defense Evasion | Event 10, 25 | Skip NtUnmapViewOfSection → gap=[25] |
| Rundll32 LOLBin | T1218.011 | Defense Evasion | Event 1 | — |
| PowerShell Fileless | T1059.001 | Execution | Event 1 | — |
| Registry Run Key | T1547.001 | Persistence | Event 13 | — |
| Scheduled Task | T1053.005 | Persistence | Event 1 | COM API Schedule.Service → gap=[1] |

## Project Structure

```
techniques/
  T<ID>_<name>/
    technique.py              # Attack simulation
    technique_evasion.py      # Evasion variant (where applicable)
    expected_events.json      # Test oracle: expected Sysmon event IDs + keywords
    expected_events_evasion.json
    remediation.md            # Detection gap and suggested config fix (where applicable)
validator/
  check_logs.py               # Queries Sysmon log via win32evtlog, compares against oracle
run_all.py                    # Runs all techniques, collects results
generate_report.py            # Converts results to HTML coverage report
```

## How It Works

1. `technique.py` executes the attack, records its own PID and child PID, then calls `check_logs.py`
2. `check_logs.py` queries `Microsoft-Windows-Sysmon/Operational` for events in the 30 seconds after execution
3. Events are filtered by PID (not just keyword) to exclude background noise
4. Results are compared against `expected_events.json` — any expected event ID that did not appear becomes a `gap`
5. A baseline check queries the 30 seconds *before* execution to flag pre-existing events that could cause false positives

## Result Types

| Result | Meaning |
|---|---|
| `PASS` | All expected event IDs detected |
| `EVADED` | Expected events not detected — gap correctly identifies which detection rule was bypassed |
| `FAIL` | Unexpected outcome |
