# SOC Investigation Lab

A hands-on detection engineering lab demonstrating blue-team skills: attack simulation, detection authoring, incident investigation, and MITRE ATT&CK mapping.

## Architecture
- **SIEM:** Microsoft Sentinel (Log Analytics workspace)
- **Endpoints:** Windows Server 2022 domain controller + Windows 11 domain-joined workstation (VMware Workstation)
- **Telemetry:** Sysmon (SwiftOnSecurity config), PowerShell script-block logging, and Windows Security events, forwarded to Sentinel via Azure Monitor Agent over Azure Arc
- **Detections:** Custom KQL scheduled analytics rules

## Lessons Learned
- Root-caused a complete loss of guest VM internet to a VMware host-only subnet (192.168.10.0/24) colliding with the physical home router at 192.168.10.1, which poisoned NAT return traffic on the host. Re-subnetting the lab network to 192.168.100.0/24 resolved it. Ruled out DNS, duplicate MAC, and firewall first.

## Detections
| # | Name | Tactic | Technique |
|---|------|--------|-----------|
| 01 | New Account Created and Promoted to Admin | Persistence, Privilege Escalation | T1136.001, T1098 |
| 02 | Encoded PowerShell Execution | Execution | T1059.001 |

_More detections in progress._
