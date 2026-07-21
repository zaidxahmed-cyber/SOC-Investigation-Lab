# MITRE ATT&CK Coverage Matrix

Detections mapped to the MITRE ATT&CK framework. This matrix tracks which tactics and techniques the lab currently has detection coverage for.

| Detection | Tactic | Technique | Data Source | Status |
|-----------|--------|-----------|-------------|--------|
| [01 – New Account Created and Promoted to Admin](detections/01-new-admin-account.md) | Persistence, Privilege Escalation | T1136.001, T1098 | Windows Security Events (4720, 4732) | Live |
| [02 – Encoded PowerShell Execution](detections/02-encoded-powershell.md) | Execution | T1059.001 | Sysmon Event 1 (Process Create) | Live |
| [03 – Security Log Cleared](detections/03-security-log-cleared.md) | Defense Evasion | T1070.001 | Windows Security Events (1102) | Live |
| [04 – Brute Force (Multiple Failed Logons)](detections/04-brute-force.md) | Credential Access | T1110 | Windows Security Events (4625) | Live |
| [05 – Kerberoasting (Service Ticket RC4 Request)](detections/05-kerberoasting.md) | Credential Access | T1558.003 | Windows Security Events (4769) | Live |

## Coverage Summary

These five detections form the complete detection set for this lab. They were chosen to span distinct detection techniques rather than to maximise count: event correlation (01), process-command parsing (02), high-fidelity single-event (03), threshold-based aggregation (04), and event-data XML parsing to isolate an attack from benign noise (05). Together they cover four MITRE tactics: Execution, Persistence/Privilege Escalation, Defense Evasion, and Credential Access.

## Roadmap

- **Detection set:** complete (5 detections, above).
- **Incident reports:** complete — a full investigation writeup for each detection, in [`incident-reports/`](incident-reports/), covering timeline, evidence, assessment, and response.
- **AI-assisted investigation experiment:** complete — an LLM was given each detection's raw event as a SOC analyst and its output critiqued against ground truth. See [ai-investigation-experiment.md](docs/ai-investigation-experiment.md).
- **Final polish:** repository presentation.
