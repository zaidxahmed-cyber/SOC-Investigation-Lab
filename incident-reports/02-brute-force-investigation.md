# Incident Report 02: Brute Force Against jsmith

**Detection rule:** Brute Force – Multiple Failed Logons (T1110)
**Severity:** Medium
**Status at triage:** Active, Unassigned
**Analyst:** Zaid Ahmed
**Report date:** July 2026

---

## 1. Executive Summary

A medium-severity alert fired for a password brute-force attack. A single source host, `192.168.100.30`, generated eight failed logon attempts against the domain account `jsmith` in under one second. The volume and speed from a single source are consistent with an automated password-guessing tool rather than a user mistyping a password. No successful logon followed the failures. Recommended response is to confirm whether the source host is authorised, review the `jsmith` account, and verify account lockout policy.

## 2. Timeline

| Time (Jul 21, 2026) | Event |
|---------------------|-------|
| 1:43:39–1:43:40 PM | Eight failed logons (Event 4625) against `jsmith` from source `192.168.100.30`, all within roughly one second. |
| ~1:48 PM | Analytics rule evaluated the window, threshold exceeded, alert raised and incident created. |

## 3. What Triggered the Alert

The detection rule aggregates failed logons (Event 4625) by source IP and alerts when a single source produces five or more failures within a five-minute window. One or two failed logons are normal background noise; a rapid burst from one source is the brute-force signature. This event count (eight in about one second) is well above the threshold and far faster than human typing.

## 4. Investigation

### 4.1 Entities involved
- **Source host:** `192.168.100.30` — the origin of all eight failed attempts.
- **Targeted account:** `jsmith` — a standard domain user.
- **Domain controller:** `WIN-8D6STUT9KU3.lab.local` — where the authentication attempts were processed and logged.

### 4.2 Key evidence
- FailureCount: 8, all from one IP
- Time span: first to last attempt roughly one second apart
- Targeted account: `jsmith` (single account, not spread across many)
- Logon type: network (SMB authentication)

### 4.3 Analytical reasoning
- **Speed rules out human error.** Eight distinct authentication attempts in about one second cannot be manual. This is scripted or tool-driven.
- **Single source, single target.** All failures came from one IP against one account. This is a targeted brute force against `jsmith`, as opposed to password spraying (which would show few attempts each across many accounts).
- **Outcome check is critical.** The key investigative question for any brute force is whether it eventually succeeded. Here, no successful logon (Event 4624) from the same source or account followed the failures, so the attack appears to have failed to guess the password.

### 4.4 Questions a full investigation would pursue
- Is `192.168.100.30` a recognised host? An unknown source strengthens the case for a genuine attack.
- Did the same source attempt other accounts before or after (spraying), or focus only on `jsmith`?
- Is account lockout policy configured? Eight attempts with no lockout suggests the policy may be missing or too permissive.

## 5. Assessment

Assessed as a **true positive** brute-force attempt that did **not** succeed. The pattern (eight rapid failures, one source, one target, no subsequent success) is a clear automated password-guessing attack that failed to obtain valid credentials. Because no compromise occurred, severity remains Medium: this is an attempted attack to investigate and contain, not an active breach.

## 6. Response and Recommendations

**Immediate:**
1. Confirm whether `192.168.100.30` is an authorised host. If not, treat as hostile and block it.
2. Review the `jsmith` account for any signs of prior or subsequent suspicious activity.

**Follow-up:**
3. Confirm no successful logon occurred from the source after the failures (verified in this case, but standard practice).
4. Check whether the same source targeted other accounts.

**Hardening:**
5. Verify account lockout policy is enabled and reasonable (for example, lock after a small number of failures for a set period), which would stop this style of attack automatically.
6. Consider network controls limiting which hosts can authenticate to the domain controller over SMB.

## 7. Note on Environment

This incident was generated in a controlled detection-engineering lab. The source host `192.168.100.30` is a Kali VM, and the attack was executed intentionally using NetExec to validate the detection. The investigation is written as it would be performed against a real alert.
