# SOC Investigation Lab – Complete Project Overview

A full walkthrough of the environment, how it was built, how the pieces connect, and what has been done. This is the master reference for the project.

![Network Diagram](network-diagram.svg)

## 1. What This Project Is

This is a hands-on Security Operations Center (SOC) detection engineering lab. It exists to practice the full defensive workflow the way it happens in a real SOC: an attacker performs a technique, that activity produces logs, the logs are centralized in a SIEM, and a custom detection rule catches the activity and raises an incident that an analyst investigates.

The goal is not to run pre-built tools and collect screenshots. It is to build each detection from scratch: execute a genuine attack, find the exact evidence it leaves behind, write the detection logic, prove it fires, and document it honestly including its weaknesses. Every detection is mapped to the MITRE ATT&CK framework, which is the industry-standard catalogue of adversary techniques.

The environment simulates a small corporate Windows network: a domain controller, a user workstation, and an attacker machine, all wired into a cloud SIEM.

## 2. Physical Host

Everything runs on one physical computer.

- Operating system: Windows 11
- Memory: 16 GB RAM
- Virtualization software: VMware Workstation Pro 17.5

Two host-level settings were disabled because they interfered with VMware networking: Hyper-V and Memory Integrity (Core Isolation). On this hardware, leaving them on caused guest network failures. With them off, networking is stable.

The 16 GB memory limit is the main constraint on the lab. Three virtual machines cannot all run comfortably at once, so the environment is designed to run at most two VMs simultaneously, powering on the attacker only while an attack is in progress.

## 3. The Virtual Machines

Three VMs make up the lab. Each has a distinct role.

### DC01 – Domain Controller
- Operating system: Windows Server 2022
- Hostname: WIN-8D6STUT9KU3 (kept as the auto-generated name because it is registered to Azure under this name and renaming would break that link)
- Roles: Active Directory Domain Services, DNS
- Domain: lab.local

DC01 is the identity backbone of the network. It holds all the domain user accounts, authenticates logons, and issues Kerberos tickets. In attack terms, it is the credential and identity surface: attacks like Kerberoasting, brute force, and domain privilege escalation all target this machine. A service account with a Service Principal Name was deliberately created here as a Kerberoasting target.

### WIN11 – Workstation
- Operating system: Windows 11 Enterprise (Evaluation)
- Hostname: DESKTOP-NV93RGT
- Domain-joined to lab.local

WIN11 represents a normal employee workstation. It is the endpoint and execution surface: attacks that run on a user's machine (malicious PowerShell, log clearing, scheduled task abuse) are executed and detected here.

### Kali-Attacker – Attacker
- Operating system: Kali Linux (2026.2 prebuilt VMware image)
- Memory: 2 GB, 2 virtual CPUs
- Role: offensive machine

Kali is the attacker's laptop in the story. It runs the offensive tooling (notably Impacket) used to launch network- and identity-based attacks against the domain. It was added to the lab specifically for the identity-attack phase. Because of the host's memory limit, Kali is only powered on while actively attacking; the rest of the time it stays off to free RAM for the Windows machines.

## 4. How the Machines Connect (Networking)

The lab uses two independent networks. This separation is deliberate: the attack traffic must stay isolated from the outside world, but the machines still need internet access for updates and for reaching the cloud SIEM.

### The LAB network — 192.168.100.0/24
This is a host-only, isolated network inside VMware (the VMnet2 virtual switch). All three VMs sit on it and talk to each other here. This is where attacks travel and where the domain operates. It has no gateway to the internet and no DHCP server, so every machine is given a fixed, manually assigned address:

| Machine | Role | LAB IP Address |
|---------|------|----------------|
| DC01 | Domain Controller / DNS | 192.168.100.10 |
| WIN11 | Workstation | 192.168.100.20 |
| Kali-Attacker | Attacker | 192.168.100.30 |

The two Windows machines are told to use DC01 (192.168.100.10) as their DNS server, which is what lets them find and join the `lab.local` domain. The Kali machine was assigned its static LAB address through Linux NetworkManager so the setting survives reboots rather than resetting each time.

### The NAT network — internet access
Each machine also has a second network adapter connected to VMware's NAT network, which shares the host's internet connection. The Windows VMs use this path to talk to Azure (sending their logs to the cloud). Kali uses it to download and update its tools. Crucially, actual attack traffic never uses this path; it stays on the isolated LAB network. The NAT link is only for maintenance and cloud telemetry.

So each VM has two network cards: one on the isolated LAB network for lab activity, and one on NAT for internet.

### The networking problem that was solved (lessons learned)
Early in the build, the guest machines completely lost internet access. After ruling out DNS, duplicate MAC addresses, and firewall settings, the root cause was found: the VMware host-only network had originally been assigned the subnet 192.168.10.0/24, which collided with the physical home router's address of 192.168.10.1. That overlap poisoned the NAT return traffic on the host, breaking connectivity. Moving the lab to the 192.168.100.0/24 subnet removed the collision and fixed everything. This is a genuine troubleshooting lesson: an address-space overlap between a virtual lab and the real home network can silently break routing.

## 5. How Logs Get Collected (The Telemetry Pipeline)

A detection is only as good as the data feeding it. Here is exactly how activity on a VM becomes a searchable event in the SIEM.

### What the machines log
Both Windows VMs are configured to produce rich security telemetry:
- Windows Security event logs, with command-line auditing turned on so process-creation events include the full command that was run.
- Sysmon (System Monitor) using the well-known SwiftOnSecurity configuration, which adds detailed process, network, and file event logging.
- PowerShell script-block logging and module logging, which capture what PowerShell actually executed.
- On DC01 specifically, Kerberos and account auditing, which produces the events used to detect identity attacks.

### How the logs reach the cloud
The pipeline has several stages:

1. **Azure Monitor Agent (AMA)** is installed on both Windows VMs. This agent collects the configured logs and forwards them to Azure. (Note: the agent runs as background processes rather than a single named Windows service, so the usual service-name check does not find it; this is normal.)
2. **Azure Arc** is what connects these on-premises VMs to Azure in the first place. Arc registers each machine into the cloud so it can be managed and can send data, even though the VMs live on a laptop rather than in Azure.
3. **Data Collection Rules (DCRs)** define what the agent actually collects. There are two: one for Windows Security events and one for Sysmon plus PowerShell logs. Both apply to both machines.
4. **Log Analytics workspace** is the cloud database where all this telemetry lands. It has a 1 GB per day ingestion cap and a small budget alert to keep the free Azure account from incurring cost.
5. **Microsoft Sentinel** is the SIEM layer sitting on top of the workspace. It is where detection rules live and where alerts and incidents are raised. It is now managed through the Microsoft Defender portal.

### The full path of a single event
```
Attack executed on a VM
  -> event written to Windows Security log / Sysmon / PowerShell log
    -> Azure Monitor Agent picks it up (machine connected via Azure Arc)
      -> Data Collection Rule decides it should be collected
        -> event lands in the Log Analytics workspace
          -> Microsoft Sentinel analytics rule (written in KQL) evaluates it
            -> if it matches, an Alert is raised
              -> the Alert becomes an Incident for investigation
```

### The cloud account
The environment runs on a free Azure account with trial credit. All resources live in one resource group, in a single Log Analytics workspace located in the East US region. (Data Collection Rules must be created in the same region as the workspace, which is a common setup gotcha.) The account is capped and budget-alerted so it stays free.

## 6. How Detections Are Built (Methodology)

Every detection in this lab follows the same six-step loop. This consistency is intentional and is itself part of the portfolio: it shows a repeatable engineering process rather than one-off lucky rules.

1. **Attack.** Run the real technique against the correct machine. Endpoint techniques run on WIN11; identity techniques run against DC01, launched from Kali.
2. **Confirm the telemetry.** Query the SIEM to verify the event arrived, and find the exact fields that distinguish the attack from normal activity.
3. **Write the rule.** Author a KQL (Kusto Query Language) detection that isolates the attack pattern and maps the involved host and account as "entities" so they show up in the incident.
4. **Tune.** Identify what would cause false positives and document how the rule handles them or how it would be tuned in a noisier real environment.
5. **Validate.** Turn the rule on, re-run the attack so a fresh event lands inside the rule's time window, and confirm it produces an incident.
6. **Document.** Write the detection up with a summary, MITRE mapping, data sources, the KQL logic, false-positive analysis, tuning notes, validation evidence, and a response runbook (the steps an analyst would take).

Each finished detection lives as its own document in the `detections/` folder, and the overall coverage is tracked in `coverage-matrix.md`.

## 7. Detections Built So Far

Five detections are live, deliberately spanning both attack surfaces.

### Detection 01 — New Account Created and Promoted to Admin
- Technique: T1136.001 (Create Account) and T1098 (Account Manipulation)
- Idea: An attacker who gains a foothold often creates a new account and quickly adds it to an admin group for persistence. Individually, account creation and group changes are normal. The two happening back-to-back within five minutes is the anomaly.
- Logic: Correlates Security Event 4720 (account created) with 4732 (added to a privileged group) on the same host within a five-minute window.
- Surface: Endpoint / domain (WIN11).

### Detection 02 — Encoded PowerShell Execution
- Technique: T1059.001 (PowerShell)
- Idea: Attackers hide PowerShell commands by base64-encoding them so the real command is not visible at a glance. The encoding flags themselves are the signal.
- Logic: Flags Sysmon process-creation events where the command line contains encoded-command indicators (`-enc`, `-EncodedCommand`, `FromBase64String`). Documented as intentionally broad, with a planned enhancement to decode the payload and alert on intent rather than just the flag.
- Surface: Endpoint (WIN11).

### Detection 03 — Security Log Cleared
- Technique: T1070.001 (Clear Windows Event Logs)
- Idea: Clearing the Security event log is a deliberate act to destroy evidence, with almost no legitimate reason on a normal machine. The act of clearing generates its own event, so it cannot be done silently.
- Logic: Fires on Security Event 1102 (audit log cleared). High severity, very low false-positive rate.
- Surface: Endpoint (WIN11).

### Detection 05 — Kerberoasting (Service Ticket RC4 Request)
- Technique: T1558.003 (Kerberoasting)
- Idea: In Active Directory, any domain user can request a service ticket for any account that has a Service Principal Name. The ticket is encrypted with that service account's password hash, which the attacker then cracks offline. Attackers force the weak RC4 encryption because it cracks far faster than AES. A service-account ticket requested with RC4 is the attack's fingerprint.
- Logic: Reads Security Event 4769, parses the event's XML to extract the service name, encryption type, requesting account, and source IP, then flags requests using RC4 encryption (type 0x17) against user service accounts, excluding machine accounts. This isolates the attack from the constant background of normal Kerberos ticket requests.
- Validation: Executed for real from Kali using Impacket, authenticating as a low-privilege domain user to roast a planted service account. The attack produced the crackable ticket hash and generated a high-severity incident tracing back to the attacker's IP.
- Surface: Identity / domain controller (DC01, attacked from Kali). This is the most technically involved detection in the lab.

### Detection 04 — Brute Force (Multiple Failed Logons)
- Technique: T1110 (Brute Force)
- Idea: A single failed logon is normal; many failures from one source in a short time is a password-guessing attack. The pattern, not any single event, is the signal.
- Logic: Aggregates failed logons (Security Event 4625) by source IP and alerts when one source produces five or more failures within a five-minute window. Surfaces the attacker's source IP as the key investigative pivot.
- Validation: Executed for real from Kali using NetExec, spraying wrong passwords at a domain user. Eight rapid failures from one source were aggregated into a single finding tracing back to the attacker's IP.
- Surface: Identity / domain controller (DC01, attacked from Kali).

## 8. What Has Been Accomplished

- A complete, isolated Active Directory lab with a domain controller and workstation.
- A Kali attacker machine built, dual-homed onto the lab network and the internet, with offensive tooling installed.
- A full cloud telemetry pipeline: agents, Azure Arc onboarding, data collection rules, a Log Analytics workspace, and Microsoft Sentinel.
- Four working detections spanning endpoint execution, defense evasion, persistence/privilege escalation, and identity credential theft, each mapped to MITRE ATT&CK and fully documented.
- A real, end-to-end identity attack (Kerberoasting) executed from the attacker machine and caught by a custom detection.
- A full incident-investigation report for each detection, documenting timeline, evidence, assessment, and recommended response — demonstrating triage and analytical reasoning, not just rule authoring.
- A documented, repeatable methodology and an organized repository (per-detection writeups, incident reports, coverage matrix, screenshots, and this architecture reference).

## 9. What Comes Next (Roadmap)

The detection set (five detections) and the incident-investigation reports (one per detection) are complete. Remaining work:

- **AI investigation layer**: feed raw logs to a language model, have it draft an investigation summary and response plan, then verify and critique its output — framed as an AI-versus-analyst comparison.
- **Final polish**: a network diagram and repository presentation.

## 10. Design Principles

A few decisions shape the whole project:

- **Real attacks, real evidence.** Nothing is faked. Each detection is validated by actually performing the technique and catching the resulting telemetry.
- **Honesty about weaknesses.** Detections document their false positives and tuning needs. A rule that admits where it would misfire in production demonstrates more skill than one that pretends to be perfect.
- **Signal over noise.** The hardest and most valuable part of detection is separating an attack from normal activity, which is why detections like Kerberoasting focus on precise indicators rather than broad matches.
- **Reproducibility.** The same six-step loop and the same documentation template are used every time, so the work is consistent and any detection can be understood and rebuilt from its writeup.
