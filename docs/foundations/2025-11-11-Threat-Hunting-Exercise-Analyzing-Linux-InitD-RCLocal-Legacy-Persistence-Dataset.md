---
layout: default
title: Hunting Exercise - 112
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Linux Init.d/RC.local Legacy Persistence Dataset

This hunt uses a simulated Linux auditd dataset (`linux_rclocal_persist_2022-12-02T023000.json`) capturing **T1037.004: Boot or Logon Initialization Scripts: RC Scripts**, where an attacker appends a malicious command to `/etc/rc.local` or drops a script into `/etc/init.d/`, relying on legacy SysV-init compatibility layers still present on many modern Linux distributions to achieve boot persistence.

#### Step 1: Hypothesis Formation
**Hypothesis**: The `/etc/rc.local` file is modified to append a command referencing a suspicious binary/script path, or a new script is added to `/etc/init.d/` with a corresponding `update-rc.d`/`chkconfig` registration, by a process other than the system's package manager or configuration-management agent, indicating legacy boot-script abuse for persistence. Indicators:
- File-modification event on `/etc/rc.local` (append or overwrite) or file-creation event under `/etc/init.d/` outside a package-installation transaction.
- The appended/added content references a script or binary in a world-writable or temporary directory.
- `chmod +x` is applied to the new init.d script, followed by `update-rc.d <script> defaults` or `chkconfig --add <script>` to register it for the appropriate runlevels.
- No corresponding software-installation log entry (dpkg/rpm transaction) exists for the modification.

**Null Hypothesis**: A system administrator is legitimately configuring a legacy service for compatibility reasons, or a configuration-management tool is deploying an approved rc.local entry as documented in the server build standard. Invalidate by checking source of the modifying process against the CM agent and any documented server-hardening/build exceptions.

**Rationale**: Even though systemd has largely replaced SysV-init, most modern distributions retain rc.local/init.d execution for backward compatibility, and because these paths are rarely monitored as closely as systemd units, they remain an effective, lower-visibility persistence mechanism that only file-integrity monitoring on legacy boot paths will reliably catch.

#### Step 2: Data Sources and Scope
- **Sources**: Linux auditd file-write rules on `/etc/rc.local` and `/etc/init.d/`; process-execution logs; package-manager transaction logs (dpkg/rpm history).
- **Scope**: ~2022-12-02T02:30:00-02:31:40 UTC; Host: SVR-DB-08 (10.22.14.55); Modified File: `/etc/rc.local`.
- **SIEM Queries** (Splunk/ELK):
  - `index=auditd path="/etc/rc.local" type=PATH (nametype=CREATE OR nametype=NORMAL) syscall=openat`
  - Init.d creation: `index=auditd path="/etc/init.d/*" type=PATH nametype=CREATE`
  - Package-transaction correlation: `index=dpkg_history OR index=rpm_history host="SVR-DB-08" earliest=-10m` (expect zero results)

#### Step 3: Key Findings
Parsed events (4 shown) confirm an attacker appended a reverse-shell invocation to `/etc/rc.local` on a database server, disguising it among the file's existing legitimate startup commands.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-02 02:30:11 | SVR-DB-08 | auditd (execve) | `echo "/bin/bash -c '/var/tmp/.x/upd.sh &' " >> /etc/rc.local`, run by `mysql` service account | **Anomalous-Writer IOC**: the MySQL service account has no legitimate reason to modify system boot scripts; this indicates the account was compromised via a SQL-injection-to-OS-command escalation. |
| 2022-12-02 02:30:11 | SVR-DB-08 | (File content diff) | New line appended before the file's final `exit 0`, referencing `/var/tmp/.x/upd.sh` | **Path-Anomaly IOC**: the referenced script resides in a world-writable temp directory under a hidden `.x` folder, not any standard application installation path. |
| 2022-12-02 02:30:14 | SVR-DB-08 | auditd (execve) | `chmod +x /var/tmp/.x/upd.sh` | **Preparation IOC**: making the dropped script executable immediately after the rc.local append completes the persistence chain, ensuring it runs with root privileges at next boot (rc.local executes as root by default). |
| - | - | (Package-transaction correlation) | No dpkg/rpm transaction is logged for SVR-DB-08 in this window | Confirms this modification did not originate from any legitimate software installation or update process. |

**Validation**:
- **Timeline**: a compromised database service account appended a reverse-shell-invoking line to `/etc/rc.local` and made the referenced script executable - a complete legacy boot-persistence chain, contingent only on the next reboot to activate with root privileges.
- **False Positives**: no package-manager transaction or configuration-management run corresponds to this change.
- **Correlation**: anomalous service-account modifier, suspicious script path, and executable-permission preparation jointly confirm deliberate rc.local persistence installation.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Remove the appended line from `/etc/rc.local`, delete `/var/tmp/.x/`, do not reboot the host until the persistence mechanism is fully removed and verified, and investigate the MySQL service for the SQL-injection or misconfiguration that allowed OS command execution.
- **Detection**: Sigma-style rule: `title: RC.local Modified by Non-Admin Service Account` → `selection: path="/etc/rc.local" syscall IN (openat,write) AND uid NOT IN (root_admin_uids)` → `condition: selection`.
- **Pro Tip**: Apply file-integrity monitoring with alerting (not just logging) on `/etc/rc.local`, `/etc/init.d/`, and `/etc/rc*.d/` symlinks across all Linux hosts, and where rc.local is unused by the organization's build standard, disable/remove the compatibility shim entirely - legacy boot paths are frequently excluded from EDR/systemd-unit-focused monitoring, making them a persistent blind spot.

Hypothesis **confirmed**-a compromised MySQL service account appended a reverse-shell-launching command to `/etc/rc.local` and staged the referenced script for root-level execution at the next system reboot!
