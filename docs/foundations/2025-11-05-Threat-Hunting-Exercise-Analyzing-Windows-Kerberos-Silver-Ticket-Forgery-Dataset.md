---
layout: default
title: Hunting Exercise - 106
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Windows Kerberos Silver Ticket Forgery Dataset

This hunt uses a simulated Windows Security Event Log dataset (`win_silver_ticket_2022-11-20T101500.json`) capturing **T1558.002: Steal or Forge Kerberos Tickets: Silver Ticket**, where an attacker who has obtained a service account's NTLM hash forges a Kerberos service ticket (TGS) directly, bypassing the domain controller and Kerberos TGT-issuance entirely for access to that specific service.

#### Step 1: Hypothesis Formation
**Hypothesis**: A service-ticket-authenticated access event occurs for a given service account (e.g., a SQL or file-share SPN) with no corresponding TGT request (Event ID 4768) or TGS request (Event ID 4769) logged at the domain controller immediately prior, indicating the ticket was forged offline using the service account's stolen hash rather than legitimately issued by the KDC. Indicators:
- A service logon (Event ID 4624, Logon Type 3) occurs referencing a Kerberos-authenticated service ticket, but no matching 4769 TGS-Request exists on any domain controller for that account/time.
- The PAC (Privilege Attribute Certificate) validation is absent or the ticket's encryption type/key version does not match current KDC-issued values.
- The ticket's lifetime or renewal fields deviate from domain-default Kerberos policy (commonly a 10-year default in forged tickets from tools like Mimikatz).
- Access pattern shows immediate, broad access to the target service inconsistent with the compromised account's normal usage baseline.

**Null Hypothesis**: The absence of a logged 4769 event is due to DC audit-log gaps, log rotation, or replication delay rather than ticket forgery. Invalidate by checking DC audit-policy health, log-forwarding pipeline status, and confirming the gap is consistent (not just a single missing event) across all DCs.

**Rationale**: Silver tickets are especially dangerous because they never touch the domain controller at all during forged-ticket use, making DC-centric detections (like abnormal 4769 patterns) blind; detection instead relies on correlating service-side access logs against the complete absence of expected DC-side ticket-issuance events for that access.

#### Step 2: Data Sources and Scope
- **Sources**: Windows Security Event Logs (target service server and all domain controllers); Kerberos ticket-lifetime GPO baseline; service-account access-baseline analytics.
- **Scope**: ~2022-11-20T10:15:00-10:22:00 UTC; Target Service: SQL-PROD-04 (SPN `MSSQLSvc/SQL-PROD-04.corp.local:1433`); Source Host: 10.66.12.201 (unmanaged/rogue).
- **SIEM Queries** (Splunk/ELK):
  - `index=windows host="SQL-PROD-04" EventCode=4624 LogonType=3 AuthenticationPackageName=Kerberos | table _time src_ip account_name`
  - DC cross-check: `index=windows source="DC-*" EventCode=4769 ServiceName="MSSQLSvc/SQL-PROD-04*" earliest=-10m` (expect zero results)
  - Ticket-lifetime anomaly: `index=windows EventCode=4624 | eval ticket_age_days=... | where ticket_age_days > domain_max_lifetime`

#### Step 3: Key Findings
Parsed events (4 shown) confirm a Kerberos-authenticated logon to SQL-PROD-04 occurred with no corresponding TGS request at any of the organization's three domain controllers, and the ticket carried a non-standard 10-year lifetime.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-20 10:19:47 | SQL-PROD-04 | Windows Security (4624) | Logon Type 3, `AuthenticationPackageName=Kerberos`, `AccountName=svc-sql-backup`, source `10.66.12.201` | **Unexpected-Source IOC**: the service account authenticated from an unmanaged host with no prior authentication history, atypical for a backup service account that normally connects only from the backup server. |
| 2022-11-20 10:15:00 - 10:22:00 | DC-CORP-01/02/03 | Windows Security (4769 sweep) | Zero `TGS-Request` events for `MSSQLSvc/SQL-PROD-04` across all three domain controllers in this window | **Missing-TGS IOC**: a Kerberos-authenticated service logon with no corresponding domain-controller ticket-issuance record is the defining signature of an offline-forged silver ticket. |
| 2022-11-20 10:19:47 | SQL-PROD-04 | Windows Security (4624, ticket detail) | Ticket lifetime field: 3,650 days (10 years); domain default Kerberos policy max lifetime: 10 hours | **Lifetime-Anomaly IOC**: this ticket lifetime vastly exceeds domain policy and matches the well-known default forged-ticket lifetime produced by Mimikatz `kerberos::golden`/`silver` modules. |
| 2022-11-20 10:19:50 | SQL-PROD-04 | (SQL Audit Log) | `svc-sql-backup` executed `xp_cmdshell` and queried `sys.sql_logins` immediately after logon | **Post-Access IOC**: immediate use of a high-privilege stored procedure to enumerate credentials is inconsistent with the account's normal automated-backup-only usage baseline. |

**Validation**:
- **Timeline**: an unexpected-source Kerberos logon with an anomalous 10-year ticket lifetime, zero corresponding DC-side TGS-issuance record, and immediate high-privilege SQL command execution - a complete silver-ticket forgery-and-abuse chain.
- **False Positives**: all three domain controllers were confirmed healthy and actively logging during the window, ruling out an audit-log gap explanation.
- **Correlation**: source-host anomaly, missing-TGS confirmation, non-standard ticket lifetime, and post-access behavior jointly confirm silver ticket forgery using the `svc-sql-backup` account's stolen NTLM hash.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Reset the `svc-sql-backup` account password twice in succession (to invalidate the underlying NTLM hash used for forgery), isolate the source host 10.66.12.201, and audit SQL-PROD-04 for any data accessed or modified during the session.
- **Detection**: Sigma-style rule: `title: Kerberos Service Logon Without Matching TGS-Request` → `selection1: EventCode=4624 AuthenticationPackageName=Kerberos` correlated against `selection2: EventCode=4769 ServiceName=<same SPN>` on all DCs within a matching window → `condition: selection1 and not selection2`.
- **Pro Tip**: Rotate service-account (SPN-associated) account passwords on a regular, automated schedule - silver tickets remain valid for as long as the underlying hash is valid, so routine credential rotation is the only control that reliably invalidates already-forged tickets without requiring the attacker's presence to be detected first.

Hypothesis **confirmed**-an attacker forged a Kerberos silver ticket for the `svc-sql-backup` service account using its stolen NTLM hash, authenticating directly to SQL-PROD-04 with a 10-year ticket lifetime and no domain-controller ticket-issuance record!
