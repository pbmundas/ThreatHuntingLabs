---
layout: default
title: Hunting Exercise - 110
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Windows RDP Session Hijacking Tscon Dataset

This hunt uses a simulated Windows Security Event Log dataset (`win_tscon_hijack_2022-11-28T112000.json`) capturing **T1563.002: Remote Service Session Hijacking: RDP Hijacking**, where an attacker with SYSTEM-level access uses the built-in `tscon.exe` utility to reconnect to another user's disconnected RDP session without supplying that user's credentials, inheriting their full authentication context.

#### Step 1: Hypothesis Formation
**Hypothesis**: A `tscon.exe` process is executed with a target session ID argument by a process running as SYSTEM (commonly via a scheduled task or PsExec-spawned service), immediately followed by a session-reconnect event where the resulting desktop session's authenticated user changes to a different, higher-privileged account without a corresponding logon/credential-entry event - indicating RDP session hijacking rather than a normal user-initiated reconnect. Indicators:
- Process creation event for `tscon.exe <session_id> /dest:<session_name>` with a parent process running as `NT AUTHORITY\SYSTEM`.
- Windows Terminal Services event log shows a session reconnect (Event ID 25) where the resulting logged-on user differs from the user who initiated the `tscon` command.
- No corresponding interactive logon (Event ID 4624 Logon Type 10) with credential entry precedes the session takeover.
- The `tscon` execution follows shortly after the attacker obtained SYSTEM privileges via an unrelated technique (e.g., PsExec, scheduled task, or service creation).

**Null Hypothesis**: An IT administrator is performing an authorized, documented remote-session-recovery action (e.g., helping a user recover a stuck disconnected session) using approved SYSTEM-level tooling. Invalidate by checking for a matching change/support ticket and confirming the administrator's identity and authorization for that specific target session.

**Rationale**: `tscon.exe`-based session hijacking is a "living off the land" technique that requires no exploit or malware - because `tscon` run as SYSTEM does not need the target user's password, the entire attack is invisible to credential-based detections and can only be caught by correlating the SYSTEM-context session-reconnect command with the absence of an expected interactive logon event.

#### Step 2: Data Sources and Scope
- **Sources**: Windows Security Event Logs (Event ID 4688 Process Creation, Event ID 4624); Terminal Services-LocalSessionManager Operational log (Event ID 25); IT change/support-ticket system.
- **Scope**: ~2022-11-28T11:20:00-11:21:30 UTC; Host: JUMP-ADMIN-02 (10.5.9.14); Hijacked Session: RDP Session ID 3 (belonging to `da-jsmith`, a Domain Admin).
- **SIEM Queries** (Splunk/ELK):
  - `index=windows EventCode=4688 NewProcessName="*tscon.exe*" | table _time host CommandLine ParentUser`
  - Session-reconnect correlation: `index=windows source="*TerminalServices-LocalSessionManager*" EventCode=25 | table _time host SessionID UserName`
  - Missing-logon check: `index=windows EventCode=4624 LogonType=10 TargetUserName="da-jsmith" host="JUMP-ADMIN-02" earliest=-5m` (expect zero results)

#### Step 3: Key Findings
Parsed events (4 shown) confirm an attacker who had already obtained SYSTEM via a scheduled task ran `tscon.exe` to hijack a Domain Admin's disconnected RDP session with no corresponding interactive logon.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-28 11:19:40 | JUMP-ADMIN-02 | Windows Security (4688) | `schtasks.exe` created task running as SYSTEM, executing `cmd.exe /c tscon.exe 3 /dest:rdp-tcp#5` | **SYSTEM-Context IOC**: `tscon.exe` executed with a target session ID, launched via a SYSTEM-level scheduled task rather than an interactive administrative session - the standard mechanism for the `tscon` hijacking technique, since SYSTEM can reconnect to any session without credentials. |
| 2022-11-28 11:19:52 | JUMP-ADMIN-02 | TerminalServices-LSM (25, Session Reconnect) | Session ID 3 reconnected; `UserName` on the resulting active session: `CORP\da-jsmith` | **Session-Takeover IOC**: the reconnected session's authenticated user is a Domain Admin account, while the process that triggered the reconnect ran under a completely different, lower-privileged context. |
| 2022-11-28 11:15:00 - 11:21:30 | JUMP-ADMIN-02 | Windows Security (4624 sweep) | Zero Logon Type 10 (RemoteInteractive) events for `da-jsmith` in this window | **Missing-Credential IOC**: no interactive logon with credential entry occurred for the Domain Admin account, confirming the session was inherited via `tscon`, not re-authenticated. |
| - | - | (Change-ticket check) | No IT support ticket references session recovery for `da-jsmith` or JUMP-ADMIN-02 in this timeframe | Confirms this was not an authorized administrative session-recovery action. |

**Validation**:
- **Timeline**: SYSTEM-context privilege escalation via scheduled task, immediate `tscon`-based reconnect to a Domain Admin's session, and a complete absence of any corresponding credentialed logon - a definitive RDP session-hijacking chain.
- **False Positives**: no support ticket or documented administrative justification exists for this session-recovery action.
- **Correlation**: SYSTEM-context tscon execution, session-owner change without credential entry, and missing interactive-logon event jointly confirm unauthorized RDP session hijacking of a Domain Admin account.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Terminate the hijacked session immediately, force a password reset and full session/Kerberos-ticket invalidation for `da-jsmith`, isolate JUMP-ADMIN-02, and audit how the attacker initially obtained SYSTEM-level scheduled-task creation rights.
- **Detection**: Sigma-style rule: `title: RDP Session Hijack via Tscon` → `selection: NewProcessName="*tscon.exe*" ParentUser="NT AUTHORITY\\SYSTEM"` correlated against `TerminalServices-LSM EventCode=25` where the resulting session UserName differs from the SYSTEM-task-triggering context → `condition: selection`.
- **Pro Tip**: Restrict and monitor scheduled-task and service creation on privileged jump hosts (require `Local Service`/least-privilege execution contexts rather than SYSTEM by default) and enable Restricted Admin Mode / disable session reconnection for privileged accounts on shared jump servers - this collapses the specific SYSTEM-plus-`tscon` prerequisite that makes this credential-free hijacking technique possible.

Hypothesis **confirmed**-an attacker escalated to SYSTEM via a scheduled task on a shared jump server and used `tscon.exe` to silently hijack a Domain Admin's disconnected RDP session, inheriting full authenticated access with no credential entry!
