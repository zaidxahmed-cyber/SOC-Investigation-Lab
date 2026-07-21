# Incident Report 03: Encoded PowerShell Execution

**Detection rule:** Encoded PowerShell Execution (T1059.001)
**Severity:** Medium
**Status at triage:** Active, Unassigned
**Analyst:** Zaid Ahmed
**Report date:** July 2026

---

## 1. Executive Summary

A medium-severity alert fired for PowerShell being executed with an encoded command on the workstation `DESKTOP-NV93RGT`, run by the account `LAB\Administrator`. Encoding is commonly used to obscure the true contents of a command. Investigation of the decoded payload is required to determine intent. In this case the decoded command was benign, but the technique itself always warrants review because it is frequently used to hide malicious activity.

## 2. Timeline

| Time (Jul 16, 2026) | Event |
|---------------------|-------|
| ~4:21 PM | PowerShell launched with an encoded command (`-enc`) on `DESKTOP-NV93RGT` by `LAB\Administrator`; captured by Sysmon Event 1. |
| ~4:31 PM | Analytics rule evaluated the window and raised the alert; incident created. |

## 3. What Triggered the Alert

The detection rule flags process-creation events where PowerShell is run with encoded-command indicators (`-enc`, `-EncodedCommand`, or inline base64 decoding). Attackers encode PowerShell to hide the real command from casual inspection and simple string-based controls, so the presence of encoding is treated as suspicious pending review of what was actually run.

## 4. Investigation

### 4.1 Entities involved
- **Host:** `DESKTOP-NV93RGT` — the workstation where PowerShell ran.
- **Account:** `LAB\Administrator` — the account that executed the command.
- **Parent process:** `powershell.exe` — the command was launched from another PowerShell session.

### 4.2 Key evidence
- Command line contained `-enc` followed by a base64 blob.
- Executed under an administrative account.
- Captured by Sysmon process-creation logging with full command line.

### 4.3 Analytical reasoning
- **Encoding is a red flag, not a verdict.** The correct first step is to decode the base64 payload and read the actual command. Intent cannot be judged from the encoding alone.
- **Context matters.** The command ran under `LAB\Administrator`. Administrative context raises the stakes if the command were malicious, but administrators also legitimately run encoded commands, so context alone is not conclusive.
- **Decoded result.** Decoding the payload in this case revealed a benign output command (a simple string write) with no download, no in-memory execution, and no obfuscation beyond the encoding itself.

### 4.4 Questions a full investigation would pursue
- What exactly did the decoded command do? (Primary question — always decode.)
- Was the parent process expected, or was PowerShell spawned by something suspicious (an Office application, a script host, an unknown binary)?
- Did the command make any network connections or spawn child processes?

## 5. Assessment

Assessed as a **benign true positive**: the detection correctly identified encoded PowerShell (the technique was genuinely used), but the decoded command was harmless. This is the expected majority outcome for a broad detection of this kind, which is why the rule is documented as needing analyst triage rather than automatic escalation. The value of the detection is that it forces a human to decode and confirm intent rather than letting encoded commands pass unseen.

## 6. Response and Recommendations

**Immediate:**
1. Decode and read the payload (done — benign).
2. Confirm the executing account and host are expected.

**Follow-up:**
3. If the command had been malicious: isolate the host, capture related process and network telemetry, and investigate how the encoded command was introduced.

**Detection improvement:**
4. Enhance the rule to decode the base64 in-query and alert on suspicious decoded content (for example `DownloadString`, `IEX`, hidden window, nested decoding), which would reduce benign alerts while still catching malicious use. This is tracked as a planned enhancement for the detection.

## 7. Note on Environment

This incident was generated in a controlled detection-engineering lab. The encoded command was executed intentionally to validate the detection. The investigation is written as it would be performed against a real alert.
