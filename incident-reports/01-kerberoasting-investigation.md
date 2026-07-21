# Incident Report 01: Kerberoasting Against svc_backup

**Incident ID:** 24
**Detection rule:** Kerberoasting – Service Ticket RC4 Request (T1558.003)
**Severity:** High
**Status at triage:** Active, Unassigned
**Analyst:** Zaid Ahmed
**Report date:** July 2026

---

## 1. Executive Summary

A high-severity alert fired for a Kerberoasting attack against the domain. A domain user account, `jsmith`, requested a Kerberos service ticket for the service account `svc_backup` using RC4 encryption — the signature of a ticket-extraction attack intended for offline password cracking. The request originated from a single host at `192.168.100.30`. The evidence is consistent with an attacker using a low-privileged domain account to harvest a service-account credential. Recommended response is to reset the targeted service account's password and investigate the source host and the `jsmith` account for compromise.

## 2. Timeline

| Time (Jul 16, 2026) | Event |
|---------------------|-------|
| 7:34:03 PM | Kerberos service ticket (Event 4769) requested for `svc_backup` with RC4 encryption, from source `192.168.100.30`, by account `jsmith@LAB.LOCAL`. |
| 7:44:28 PM | Analytics rule evaluated the window and raised the alert; incident created. |

The delay between the activity and the alert reflects the scheduled rule's five-minute run interval plus log ingestion time. In a production tuning exercise this detection latency would be noted; for this attack type, near-real-time alerting is desirable and could be tightened.

## 3. What Triggered the Alert

The detection rule looks for Event ID 4769 (a Kerberos service ticket request) where the ticket encryption type is `0x17` (RC4) and the requested service is a user service account rather than a machine account. Normal Kerberos activity overwhelmingly uses AES encryption; a service-account ticket requested with RC4 is anomalous and is the defining indicator of Kerberoasting, because attacker tooling deliberately requests the weaker RC4 ticket to make offline cracking faster.

## 4. Investigation

### 4.1 Entities involved
- **Requesting account:** `jsmith@LAB.LOCAL` — a standard, low-privileged domain user.
- **Targeted service account:** `svc_backup` — a service account with a registered Service Principal Name (SPN), which is what makes it a valid Kerberoasting target.
- **Source host:** `192.168.100.30` — the IP from which the ticket request originated.
- **Domain controller:** `WIN-8D6STUT9KU3.lab.local` — where the request was processed and logged.

### 4.2 Key evidence from the 4769 event
- ServiceName: `svc_backup`
- TicketEncryptionType: `0x17` (RC4)
- Client account: `jsmith@LAB.LOCAL`
- Client address: `192.168.100.30`

### 4.3 Analytical reasoning
Three facts together make this a high-confidence detection rather than noise:

1. **RC4 was requested for a service account.** In a modern domain, tickets are normally AES. An RC4 request for an account with an SPN is the specific behaviour Kerberoasting tools produce, because RC4-encrypted tickets are far cheaper to crack offline.
2. **The requesting account is low-privileged.** This matches the Kerberoasting threat model exactly: an attacker does not need admin rights to roast. Any authenticated domain user can request a ticket for any SPN, then attack the resulting hash offline. `jsmith` being an ordinary user is consistent with a foothold account being abused.
3. **The source is a single identifiable host.** The request came from one address, `192.168.100.30`, giving a concrete pivot point for containment and further investigation.

### 4.4 Questions a full investigation would pursue
- Is `192.168.100.30` a known, expected workstation, or an unrecognised host on the network?
- Was the `jsmith` account itself recently compromised (unusual logon times, source, or preceding failed-logon or phishing activity)?
- Was more than one SPN requested, which would indicate broad roasting rather than a targeted single-account attack?
- Has the extracted `svc_backup` ticket already been cracked and the credential reused elsewhere (look for subsequent successful logons using `svc_backup`)?

## 5. Assessment

This is assessed as a **true positive**. The combination of an RC4-encrypted service-ticket request for a user service account, made by a low-privileged account from a single host, is a textbook Kerberoasting attack and not explainable by normal domain activity. The targeted account (`svc_backup`) should be considered to have an exposed, crackable credential from the moment of the request.

Impact if unaddressed: if the `svc_backup` password is weak, the attacker can crack it offline and gain the account's privileges, enabling lateral movement or privilege escalation depending on what `svc_backup` can access.

## 6. Response and Recommendations

**Immediate:**
1. Reset the `svc_backup` password to a long, random value (25+ characters) to render any extracted ticket uncrackable in a useful timeframe.
2. Investigate the source host `192.168.100.30` — identify what it is, who uses it, and whether it shows signs of compromise.
3. Investigate the `jsmith` account — review recent authentication activity and determine whether the account was compromised and used as a foothold.

**Follow-up:**
4. Check for evidence of success: search for any successful logons using `svc_backup` after the ticket request, and for additional SPN requests from the same source.
5. Review all service accounts with SPNs for weak passwords and excessive privilege; service accounts are the entire attack surface for this technique.

**Hardening:**
6. Move service accounts to AES-only encryption, or to Group Managed Service Accounts (gMSA), which removes the RC4 attack surface and uses automatically managed strong passwords.
7. Consider tightening the detection's run interval for faster alerting on this high-impact technique.

## 7. Note on Environment

This incident was generated in a controlled detection-engineering lab. The "attacker" host `192.168.100.30` is a Kali VM, and the attack was executed intentionally using Impacket's GetUserSPNs to validate the detection. The investigation above is written as it would be performed against a real alert, to demonstrate the triage and reasoning process end to end.
