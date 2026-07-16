---
layout: default
title: Hunting Exercise - 114
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Linux Auditd Rule Deletion Log Tampering Dataset

This hunt uses a simulated Linux auditd/syslog dataset (`linux_auditd_tamper_2022-12-06T193000.json`) capturing **T1562.001 / T1070.002: Impair Defenses / Indicator Removal: Clear Linux or Mac System Logs**, where an attacker with root access flushes or disables the Linux audit framework to blind subsequent forensic and detection capability before continuing their intrusion.

#### Step 1: Hypothesis Formation
**Hypothesis**: A root-context process executes `auditctl -D` (delete all rules), `auditctl -e 0` (disable auditing), or stops/masks the `auditd` service, and this action is not part of a scheduled, documented maintenance window, indicating deliberate defense-evasion to prevent further audit-trail generation. Indicators:
- Execution of `auditctl -D`, `auditctl -e 0`, `systemctl stop auditd`, or `service auditd stop` by a non-maintenance process/session.
- The action occurs after other suspicious activity has already been logged (e.g., privilege escalation, suspicious binary execution) rather than at a documented patch/maintenance time.
- A gap in `/var/log/audit/audit.log` entries follows immediately, confirmed by comparing expected baseline log volume against actual.
- The `auditd` service is subsequently re-enabled shortly after the attacker's sensitive actions are complete, attempting to minimize detection of the disable-window itself.

**Null Hypothesis**: A system administrator is legitimately performing scheduled audit-subsystem maintenance (e.g., rule reloading during a patch cycle) as part of an approved change window. Invalidate by checking the action against the change-management calendar and confirming the administrator's identity via a secondary authentication factor/session record.

**Rationale**: Because auditd is frequently the sole source of detailed process-execution and file-access telemetry on Linux hosts without a full EDR agent, disabling it - even briefly - creates a forensic blind spot that attackers exploit deliberately to mask their most sensitive follow-on actions (credential theft, lateral movement, data staging).

#### Step 2: Data Sources and Scope
- **Sources**: `/var/log/audit/audit.log` (for the disable event itself, if captured before the gap) or syslog/journald (if forwarding is separate from auditd); centralized log-forwarding pipeline (to detect ingestion gaps even if local logs are wiped); change-management calendar.
- **Scope**: ~2022-12-06T19:30:00-19:52:00 UTC; Host: SVR-APP-31 (10.9.18.44).
- **SIEM Queries** (Splunk/ELK):
  - `index=auditd type=CONFIG_CHANGE op="remove_rule" OR op="feature_change"` (captures `auditctl -D`/`-e 0` before the gap)
  - Log-volume-gap detection: `index=auditd host="SVR-APP-31" | timechart span=5m count | where count=0` compared to a rolling 7-day baseline.
  - Change-calendar check: `| lookup change_calendar host,timeframe OUTPUT is_approved | where is_approved=false`

#### Step 3: Key Findings
Parsed events (5 shown) confirm a root shell disabled the audit subsystem on SVR-APP-31 for 22 minutes, immediately after a suspicious `sudo` privilege-escalation event, and re-enabled it afterward to minimize the visible gap.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-06 19:28:14 | SVR-APP-31 | auditd (SYSCALL) | `sudo -u root /bin/bash` executed by `svc-monitoring` account (not in the sudoers group per baseline) | **Precursor IOC**: an unexpected successful privilege escalation immediately precedes the audit-disable action, suggesting the attacker moved quickly to cover their tracks after gaining root. |
| 2022-12-06 19:29:47 | SVR-APP-31 | auditd (CONFIG_CHANGE, last entry before gap) | `op=remove_rule`, `res=success`, command `auditctl -D` | **Direct-Disable IOC**: this is the explicit "delete all audit rules" command, the standard first step in blinding the Linux audit framework. |
| 2022-12-06 19:29:47 - 19:51:36 | SVR-APP-31 | (Log-forwarding pipeline) | Zero audit.log events ingested for SVR-APP-31 across 22 minutes, versus a 7-day baseline average of ~40 events/5min | **Gap IOC**: this statistically significant silence, against an otherwise consistently active host, directly evidences the disable command's effect. |
| 2022-12-06 19:51:36 | SVR-APP-31 | auditd (CONFIG_CHANGE, first entry after gap) | `op=set` `auid=0` re-loading the default audit rule set | **Re-Enable IOC**: audit was restored shortly after the gap, a pattern consistent with an attacker attempting to minimize the visible disable-window rather than leaving auditing permanently off (which would itself draw immediate attention). |
| - | - | (Change-calendar check) | No approved maintenance window covers SVR-APP-31 in this timeframe | Confirms this was not sanctioned administrative activity. |

**Validation**:
- **Timeline**: an unauthorized privilege escalation, immediate audit-subsystem disable, a 22-minute total logging blackout, and a deliberate re-enable form a complete defense-evasion chain consistent with covering sensitive follow-on actions.
- **False Positives**: no change-management record authorizes this maintenance action.
- **Correlation**: precursor privilege escalation, explicit disable command, corroborated logging gap, and calculated re-enable jointly confirm deliberate audit tampering to evade detection.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Treat the 22-minute gap as a maximum-suspicion window requiring full manual forensic review (memory capture, file-timestamp analysis, network-flow cross-reference) since no audit trail exists for it, isolate SVR-APP-31, and rotate credentials for `svc-monitoring` and any account with root access during the window.
- **Detection**: Sigma-style rule: `title: Auditd Disabled or Rules Flushed` → `selection: op IN ("remove_rule","feature_change") AND command IN ("auditctl -D","auditctl -e 0")` → `condition: selection`. Pair with a separate log-volume anomaly detector for silent gaps in case the disable command itself isn't captured.
- **Pro Tip**: Configure `auditd` with `-e 2` (immutable mode, requiring a reboot to change audit configuration) and ensure all audit logs are forwarded to a remote, write-once log-aggregation target in near-real-time - local log tampering becomes irrelevant once the authoritative copy lives off-host and any local disable attempt is itself immediately visible as a gap in the remote stream.

Hypothesis **confirmed**-an attacker who escalated to root via an unauthorized `sudo` path immediately disabled the Linux audit subsystem for 22 minutes to mask follow-on activity, then re-enabled it to minimize the visible logging gap!
