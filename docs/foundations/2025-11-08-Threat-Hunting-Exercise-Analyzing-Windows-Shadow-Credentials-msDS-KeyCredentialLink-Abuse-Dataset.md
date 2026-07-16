---
layout: default
title: Hunting Exercise - 109
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Windows Shadow Credentials msDS-KeyCredentialLink Abuse Dataset

This hunt uses a simulated Active Directory audit dataset (`win_shadowcreds_2022-11-26T140000.json`) capturing **T1098.002: Account Manipulation: Additional Certificate/Key Credential**, where an attacker with `GenericWrite`/`WriteProperty` rights on a target object writes an attacker-controlled public key to the `msDS-KeyCredentialLink` attribute, enabling passwordless authentication as that account via PKINIT (Kerberos certificate authentication).

#### Step 1: Hypothesis Formation
**Hypothesis**: A directory-object modification event shows the `msDS-KeyCredentialLink` attribute being written on a user or computer object by a principal that does not normally administer that object, followed shortly by a Kerberos PKINIT authentication (Event ID 4768 with certificate-based pre-authentication) for that same account, indicating shadow-credential injection was used to obtain silent, passwordless account takeover. Indicators:
- Event ID 5136 (directory-service object modification) on `msDS-KeyCredentialLink` for a high-value account (admin, service account, or computer object).
- The modifying principal is not a Tier-0 administrative account or an expected PKI-enrollment service account.
- Within a short window afterward, a TGT request (4768) for the target account shows certificate-based pre-authentication (PA-PK-AS-REQ) rather than password-based pre-auth.
- The account had no prior history of certificate-based authentication before this event.

**Null Hypothesis**: The attribute write is legitimate Windows Hello for Business (WHfB) key registration performed automatically by the account owner's device during normal enrollment. Invalidate by checking whether the modification aligns with a documented WHfB rollout/enrollment event and whether the modifying context is the user's own registered device via the expected enrollment service account.

**Rationale**: Shadow-credential attacks are stealthy because they never touch the account's password (no reset, no lockout, no password-change audit event), and they leverage legitimate PKINIT/WHfB infrastructure, so the only reliable detection signal is correlating unexpected `msDS-KeyCredentialLink` writes with the identity and prior baseline of both the modifying principal and the subsequent authentication method.

#### Step 2: Data Sources and Scope
- **Sources**: Active Directory audit logs (Event ID 5136 with `Directory Service Changes` auditing enabled); Domain Controller Security Event Logs (Event ID 4768); BloodHound-style ACL/effective-rights inventory.
- **Scope**: ~2022-11-26T14:00:00-14:12:00 UTC; Target Object: `svc-backup-admin` (domain-joined service account); Modifying Principal: `helpdesk-jsmith`.
- **SIEM Queries** (Splunk/ELK):
  - `index=windows EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink" | table _time OpCorrelationID SubjectUserName ObjectDN`
  - PKINIT correlation: `index=windows EventCode=4768 TargetUserName="svc-backup-admin" PreAuthType=16` (16 = PKINIT/certificate)
  - ACL baseline check: `| lookup ad_effective_rights SubjectUserName,ObjectDN OUTPUT expected_admin | where expected_admin=false`

#### Step 3: Key Findings
Parsed events (4 shown) confirm the `helpdesk-jsmith` account - which holds unexpected `GenericWrite` rights on the service account due to a nested-group misconfiguration - wrote a new key credential to `svc-backup-admin`, followed nine minutes later by a certificate-based TGT request for that account from an unrelated host.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-26 14:01:03 | DC-CORP-02 | Windows Security (5136) | `AttributeLDAPDisplayName=msDS-KeyCredentialLink`, `ObjectDN=CN=svc-backup-admin,OU=ServiceAccounts`, `SubjectUserName=helpdesk-jsmith` | **Unexpected-Modifier IOC**: a help-desk-tier account, not a Tier-0 administrator or PKI-enrollment service, wrote a new key credential to a privileged backup service account. |
| 2022-11-26 14:01:00 | WKS-HELPDESK-11 | (EDR process event) | Process `Whisker.exe`-pattern command line: `... /target:svc-backup-admin /action:add` | **Tooling IOC**: this command-line pattern matches the public `Whisker`/`pyWhisker` shadow-credential injection tool syntax, not a legitimate administrative or WHfB enrollment workflow. |
| 2022-11-26 14:10:22 | DC-CORP-02 | Windows Security (4768) | `TargetUserName=svc-backup-admin`, `PreAuthType=16` (PKINIT), source `10.88.4.19` (not the account's normal service host) | **Certificate-Auth IOC**: this is the account's first-ever certificate-based authentication, occurring nine minutes after the key-credential write, and from a host with no prior relationship to this service account. |
| - | - | (ACL-baseline check) | `helpdesk-jsmith` effective `GenericWrite` on `svc-backup-admin` traces to an unintended nested-group membership, not a documented delegation | Confirms the write capability itself was an unpatched ACL misconfiguration being actively exploited, not sanctioned access. |

**Validation**:
- **Timeline**: a shadow-credential-injection tool execution, an unexpected `msDS-KeyCredentialLink` write by an over-privileged help-desk account, and the target account's first-ever certificate-based logon from an unrelated host nine minutes later - a complete shadow-credential-abuse chain.
- **False Positives**: no WHfB rollout or enrollment event is documented for this account/timeframe, and the modifying account is not the enrollment service.
- **Correlation**: tool-execution evidence, unauthorized attribute write, and immediate anomalous PKINIT authentication jointly confirm shadow-credential-based account takeover.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Remove the injected key credential from `svc-backup-admin`'s `msDS-KeyCredentialLink` attribute, reset the account's password, disable and investigate `helpdesk-jsmith` for compromise, and remediate the nested-group ACL misconfiguration granting unintended `GenericWrite`.
- **Detection**: Sigma-style rule: `title: Unexpected msDS-KeyCredentialLink Write Followed by PKINIT Logon` → `selection1: EventCode=5136 AttributeLDAPDisplayName="msDS-KeyCredentialLink"` correlated within 15 minutes against `selection2: EventCode=4768 PreAuthType=16 TargetUserName=<same object>` → `condition: selection1 and selection2`.
- **Pro Tip**: Run regular BloodHound-style effective-permissions audits specifically for `GenericWrite`/`GenericAll`/`WriteProperty` on the `msDS-KeyCredentialLink` attribute across all Tier-0 and service accounts - this attack path is entirely enabled by ACL misconfiguration, so closing unintended write-rights is far more durable than trying to catch every injection attempt after the fact.

Hypothesis **confirmed**-an over-privileged help-desk account exploited an unintended ACL misconfiguration to inject a shadow credential into a privileged backup service account, then authenticated as that account via PKINIT from an unrelated host nine minutes later!
