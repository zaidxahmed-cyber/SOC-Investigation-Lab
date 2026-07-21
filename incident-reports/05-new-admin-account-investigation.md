# Incident Report 05: New Account Created and Promoted to Admin

**Detection rule:** New Account Created and Promoted to Admin (T1136.001, T1098)
**Severity:** Medium
**Status at triage:** Active, Unassigned
**Analyst:** Zaid Ahmed
**Report date:** July 2026

---

## 1. Executive Summary

A medium-severity alert fired when a new account was created and added to a privileged group within a few minutes on `DESKTOP-NV93RGT`. Rapid create-then-elevate is a common technique for establishing a persistent, privileged foothold after initial access. The correlation of account creation and immediate privilege escalation, rather than either event alone, is what makes this suspicious. Investigation should confirm whether the account creation was authorised.

## 2. Timeline

| Time | Event |
|------|-------|
| T+0 | New account created on `DESKTOP-NV93RGT` (Event 4720). |
| within 5 min | Same account added to a privileged group — Administrators (Event 4732). |
| shortly after | Analytics rule correlated the two events within the window and raised the alert; incident created. |

## 3. What Triggered the Alert

The detection rule correlates Event 4720 (account created) with Event 4732 (member added to a privileged group) on the same host within a five-minute window. Each event alone is normal: onboarding creates accounts, and role changes modify group membership. The two happening back-to-back is the anomaly, because it matches the attacker pattern of creating a controlled account and immediately granting it the privileges needed for persistence and escalation.

## 4. Investigation

### 4.1 Entities involved
- **Host:** `DESKTOP-NV93RGT` — where the account was created and elevated.
- **New account:** the freshly created account that was added to the privileged group.
- **Creator account:** the account that performed the creation and the group addition (captured in the events).

### 4.2 Key evidence
- Event 4720 (account creation) and Event 4732 (privileged group addition) for the same target account.
- Both events occurred within a five-minute window on the same host.

### 4.3 Analytical reasoning
- **Correlation is the signal.** The strength of this detection is that it does not fire on account creation or group changes individually, which are common, but only on the tight sequence of both, which is uncommon and matches malicious behaviour.
- **The creator account is the pivot.** If the creation was malicious, the creator account was either compromised or attacker-controlled. Identifying it is central to scoping the incident.
- **Authorisation is the deciding factor.** A legitimate IT provisioning action can look identical. The determination rests on whether there is a corresponding change ticket or known automation, and whether the creator account and timing are expected.

### 4.4 Questions a full investigation would pursue
- Was the account creation backed by an authorised change (ticket, onboarding, known provisioning)?
- Is the creator account behaving normally, or does it show signs of compromise?
- Were other accounts created recently by the same creator, suggesting broader activity?
- What did the new account do after being granted privileges?

## 5. Assessment

Assessed as a **true positive** for the pattern, with intent depending on authorisation context. In a real environment, the verdict hinges on whether the creation was sanctioned. If unauthorised, this represents an attacker establishing persistent privileged access and should be escalated immediately. The detection correctly surfaces the behaviour for that determination to be made quickly.

## 6. Response and Recommendations

**Immediate:**
1. Determine whether the account creation was authorised (change ticket, onboarding record).
2. If unauthorised, disable the new account immediately.

**Follow-up:**
3. Investigate the creator account for compromise and review its recent activity.
4. Review the new account's activity from creation onward for any actions taken.
5. Check for other recently created accounts on the host or by the same creator.

**Hardening:**
6. Restrict and monitor who can create accounts and modify privileged group membership.
7. Require that privileged group changes follow a documented approval process, making unauthorised additions easier to spot.

## 7. Note on Environment

This incident was generated in a controlled detection-engineering lab. The account was created and elevated intentionally to validate the detection. The investigation is written as it would be performed against a real alert.
