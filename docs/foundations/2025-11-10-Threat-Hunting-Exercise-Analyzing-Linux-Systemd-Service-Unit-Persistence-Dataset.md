---
layout: default
title: Hunting Exercise - 111
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Linux Systemd Service Unit Persistence Dataset

This hunt uses a simulated Linux auditd/systemd dataset (`linux_systemd_persist_2022-11-30T063000.json`) capturing **T1543.002: Create or Modify System Process: Systemd Service**, where an attacker installs a malicious systemd unit file disguised with a legitimate-sounding name to achieve reboot-persistent execution with root privileges.

#### Step 1: Hypothesis Formation
**Hypothesis**: A new `.service` unit file is written to a systemd unit directory (`/etc/systemd/system/`, `/usr/lib/systemd/system/`) by a non-package-manager process, immediately followed by `systemctl daemon-reload` and `systemctl enable --now` on that unit, indicating deliberate persistence installation rather than legitimate software deployment. Indicators:
- File-creation event for a `.service` unit outside of an active `apt`/`yum`/`dnf` package-installation transaction.
- The unit's `ExecStart=` directive references a binary in a non-standard path (`/tmp`, `/var/tmp`, a hidden dotfile directory) rather than `/usr/bin` or `/usr/sbin`.
- `systemctl daemon-reload` and `enable --now` commands execute within seconds of the file write, run by a user/process without a corresponding change-ticket or deployment-pipeline association.
- The service unit name mimics a legitimate system service (typosquatting, e.g., `systemd-networkd-resolved.service`) to blend into `systemctl list-units` output.

**Null Hypothesis**: A legitimate application or configuration-management tool (Ansible, Puppet, Chef) is deploying an approved systemd service as part of a scheduled configuration run. Invalidate by checking the writing process against the approved configuration-management agent and cross-referencing the deployment against a change ticket.

**Rationale**: Systemd service persistence is attractive because it survives reboots, runs as root by default unless explicitly restricted, and a well-named unit blends into the dozens of legitimate services already present on any Linux host, so detection depends on unit-file provenance (who wrote it, from where) rather than the unit name alone.

#### Step 2: Data Sources and Scope
- **Sources**: Linux auditd file-write rules on systemd unit directories; process-execution logs (`execve` via auditd); configuration-management agent logs.
- **Scope**: ~2022-11-30T06:30:00-06:31:15 UTC; Host: SVR-WEB-22 (10.14.6.9); Unit: `systemd-networkd-resolved.service`.
- **SIEM Queries** (Splunk/ELK):
  - `index=auditd path IN ("/etc/systemd/system/*.service","/usr/lib/systemd/system/*.service") type=PATH nametype=CREATE`
  - Non-standard ExecStart: `| rex field=file_content "ExecStart=(?<exec_path>\S+)" | where NOT match(exec_path,"^/usr/(bin|sbin)/")`
  - Config-mgmt correlation: `index=ansible_logs OR index=puppet_logs host="SVR-WEB-22" earliest=-10m` (expect zero results)

#### Step 3: Key Findings
Parsed events (5 shown) confirm a malicious systemd unit disguised as a network-resolution service was written, enabled, and started on SVR-WEB-22 by a web-shell-spawned process, with its `ExecStart` pointing to a hidden binary in `/var/tmp`.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-30 06:30:02 | SVR-WEB-22 | auditd (PATH, CREATE) | File created: `/etc/systemd/system/systemd-networkd-resolved.service`, owner `www-data` | **Typosquat IOC**: this filename closely mimics the legitimate `systemd-resolved.service`, but was written by the web-server user rather than the package manager during a system update. |
| 2022-11-30 06:30:02 | SVR-WEB-22 | (File content) | `ExecStart=/var/tmp/.cache/.sysupd -d`, `Restart=always`, `User=root` | **ExecStart-Anomaly IOC**: the unit runs a hidden, dot-prefixed binary from `/var/tmp` as root with `Restart=always` - a persistence-and-resilience pattern with no legitimate system-service precedent. |
| 2022-11-30 06:30:05 | SVR-WEB-22 | auditd (execve) | `systemctl daemon-reload` executed by `www-data` (parent: `sh` spawned from `apache2`) | **Enable-Chain IOC**: a web-server worker process invoking `systemctl` directly is never expected in normal application behavior and indicates a web shell is issuing OS-level persistence commands. |
| 2022-11-30 06:30:07 | SVR-WEB-22 | auditd (execve) | `systemctl enable --now systemd-networkd-resolved.service` | **Activation IOC**: immediate enable-and-start confirms deliberate persistence installation, not a staged or reviewed deployment. |
| - | - | (Config-mgmt correlation) | No Ansible/Puppet run is logged for SVR-WEB-22 in this window | Confirms this was not a legitimate configuration-management-driven deployment. |

**Validation**:
- **Timeline**: a web-server worker process (indicating prior web-shell compromise) wrote a disguised systemd unit, reloaded the daemon, and enabled/started it within 5 seconds - a complete persistence-installation chain.
- **False Positives**: no configuration-management agent activity corresponds to this change.
- **Correlation**: typosquatted unit name, anomalous root-context `ExecStart` path, web-process-driven `systemctl` invocation, and immediate activation jointly confirm malicious systemd persistence.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Disable and remove the malicious unit (`systemctl disable --now systemd-networkd-resolved.service`), delete the hidden binary and its parent directory, isolate SVR-WEB-22, and investigate the web application for the initial web-shell/RCE vulnerability that enabled `www-data` to reach `systemctl`.
- **Detection**: Sigma-style rule: `title: Systemd Unit Written and Enabled by Web-Server Process` → `selection1: path="/etc/systemd/system/*.service" type=CREATE process_name IN ("www-data","apache2","nginx")` correlated against `selection2: execve comm="systemctl" args="enable"` within 30s → `condition: selection1 and selection2`.
- **Pro Tip**: Apply file-integrity monitoring (FIM) with real-time alerting specifically on systemd unit directories, and run web-application service accounts (`www-data`, `nginx`) with no `sudo`/`systemctl` capability at all via least-privilege OS hardening - this removes the specific escalation-and-persistence path a compromised web process would otherwise use.

Hypothesis **confirmed**-a compromised web application spawned a shell that wrote a typosquatted systemd service unit running a hidden root-level backdoor binary from `/var/tmp`, then enabled it for reboot-persistent execution!
