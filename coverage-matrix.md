# MITRE ATT&CK Coverage Matrix

Detections mapped to the MITRE ATT&CK framework. This matrix tracks which tactics and techniques the lab currently has detection coverage for.

| Detection | Tactic | Technique | Data Source | Status |
|-----------|--------|-----------|-------------|--------|
| [01 – New Account Created and Promoted to Admin](detections/01-new-admin-account.md) | Persistence, Privilege Escalation | T1136.001, T1098 | Windows Security Events (4720, 4732) | Live |
| [02 – Encoded PowerShell Execution](detections/02-encoded-powershell.md) | Execution | T1059.001 | Sysmon Event 1 (Process Create) | Live |

## Planned Coverage
| Technique | Tactic | Planned Detection |
|-----------|--------|-------------------|
| T1558.003 – Kerberoasting | Credential Access | Service ticket requests for svc_backup |
| T1110 – Brute Force | Credential Access | Repeated failed logon attempts (4625) |
| T1053.005 – Scheduled Task | Persistence | Suspicious scheduled task creation |
| T1070 – Indicator Removal | Defense Evasion | Security log cleared (1102) |
