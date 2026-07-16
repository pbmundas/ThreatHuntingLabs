---
layout: default
title: Hunting Exercise - 108
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Windows BYOVD Malicious Kernel Driver Loading Dataset

This hunt uses a simulated Windows Security/System Event Log dataset (`win_byovd_2022-11-24T091000.json`) capturing **T1068 / T1211: Exploitation for Privilege Escalation via BYOVD (Bring Your Own Vulnerable Driver)**, where an attacker loads a legitimately-signed but known-vulnerable third-party kernel driver to gain arbitrary kernel-mode code execution, typically to disable or blind EDR/AV products.

#### Step 1: Hypothesis Formation
**Hypothesis**: A kernel driver from a known-vulnerable-driver list (e.g., `LOLDrivers` catalog entries such as `RTCore64.sys`, `WinRing0x64.sys`, `dbutil_2_3.sys`) is loaded on a host shortly before EDR/AV telemetry gaps or process/service terminations occur, indicating BYOVD abuse to obtain kernel-level privileges for security-tool tampering. Indicators:
- Driver-load event (Event ID 6 / Sysmon or System log Service Control Manager 7045) references a driver filename matching a published vulnerable-driver catalog, regardless of valid signature.
- The driver is loaded from a non-standard path (e.g., `%TEMP%`, `%APPDATA%`, or a freshly-created service) rather than its typical `%SystemRoot%\System32\drivers` installation location.
- EDR/AV agent process termination, service-stop, or telemetry-gap events occur within minutes of the driver load.
- No corresponding legitimate software installation (the driver's parent application, e.g., a hardware-monitoring utility) is present on the host.

**Null Hypothesis**: The driver is a legitimate, currently-installed hardware/utility driver (e.g., an OEM diagnostic tool) that happens to appear on the vulnerable-driver list but is being used for its intended, benign purpose. Invalidate by checking whether the parent application is installed and in active, expected use on this specific host class.

**Rationale**: BYOVD is effective specifically because the driver carries a valid Microsoft or vendor signature and therefore passes Driver Signature Enforcement, so detection must rely on driver-identity/hash matching against known-vulnerable-driver catalogs and load-path/context anomalies rather than signature validity alone.

#### Step 2: Data Sources and Scope
- **Sources**: Windows System Event Log (Service Control Manager 7045, Sysmon Event ID 6 Driver Loaded); EDR agent health/heartbeat telemetry; known-vulnerable-driver catalog (LOLDrivers).
- **Scope**: ~2022-11-24T09:10:00-09:14:30 UTC; Host: WKS-IT-091 (10.41.3.28); Driver: `RTCore64.sys`.
- **SIEM Queries** (Splunk/ELK):
  - `index=windows EventCode=6 (ImageLoaded="*RTCore64.sys*" OR ImageLoaded="*WinRing0*" OR ImageLoaded="*dbutil*")`
  - Path-anomaly check: `| eval is_temp_path=if(match(ImageLoaded,"(?i)\\\\(temp|appdata)\\\\"),1,0) | where is_temp_path=1`
  - EDR-gap correlation: `index=edr_health host="WKS-IT-091" | timechart span=1m count` (look for a drop to zero immediately following driver load)

#### Step 3: Key Findings
Parsed events (5 shown) confirm a known-vulnerable driver (`RTCore64.sys`, CVE-2019-16098) was loaded from a temp directory on WKS-IT-091, followed within 90 seconds by termination of the EDR agent's protected process.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-24 09:10:14 | WKS-IT-091 | System (7045, Service Install) | Service `RTCore64` created, `ImagePath=C:\Users\Public\AppData\Local\Temp\RTCore64.sys`, `StartType=DEMAND_START` | **Vulnerable-Driver IOC**: `RTCore64.sys` is a catalog-listed driver (CVE-2019-16098) that exposes arbitrary kernel read/write via an unauthenticated IOCTL, widely abused for BYOVD attacks. |
| 2022-11-24 09:10:15 | WKS-IT-091 | Sysmon (6, Driver Loaded) | `ImageLoaded=C:\Users\Public\AppData\Local\Temp\RTCore64.sys`, `Signed=true`, `Signature=MSI (valid, unrevoked)` | **Path-Anomaly IOC**: despite carrying a valid vendor signature, the driver was loaded from a user-writable temp path rather than a standard driver installation directory, indicating manual/malicious staging. |
| 2022-11-24 09:10:22 | WKS-IT-091 | (Process event) | `RTCore64` service process issued repeated IOCTL calls to `\\.\RTCore64`, consistent with the published kernel read/write exploit primitive | **Exploitation IOC**: this IOCTL pattern matches the publicly documented exploitation method for CVE-2019-16098 to achieve arbitrary kernel memory read/write. |
| 2022-11-24 09:11:47 | WKS-IT-091 | EDR Health Telemetry | EDR agent process `SenseIR.exe` terminated unexpectedly; agent heartbeat gap begins | **Impact IOC**: the EDR agent's protected process was terminated approximately 90 seconds after the vulnerable driver achieved kernel read/write, consistent with using kernel access to disable security tooling (T1562.001). |
| - | - | (Software-inventory check) | No corresponding "MSI Afterburner" or RTCore-related hardware-monitoring application is installed on WKS-IT-091 | Confirms the driver has no legitimate parent-application context on this host. |

**Validation**:
- **Timeline**: temp-path driver installation, exploitation IOCTL sequence, and EDR-agent termination within 90 seconds form a complete BYOVD privilege-escalation-and-defense-evasion chain.
- **False Positives**: no legitimate parent application justifying this driver's presence exists on the host.
- **Correlation**: vulnerable-driver catalog match, anomalous load path, exploitation IOCTL pattern, and immediate EDR-agent termination jointly confirm BYOVD abuse.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-IT-091 (network isolation may need to occur via a secondary control path if the EDR agent is disabled), manually verify security-tool status on the host, remove the driver and its service, and assume the attacker gained SYSTEM-equivalent kernel access during the outage window.
- **Detection**: Sigma-style rule: `title: Known Vulnerable Driver Loaded From Non-Standard Path` → `selection: EventCode=6 ImageLoaded IN (loldrivers_hash_list) AND ImageLoaded MATCHES "(?i)\\\\(temp|appdata|public)\\\\"` → `condition: selection`.
- **Pro Tip**: Enable Microsoft's Vulnerable Driver Blocklist (`HVCI`/`Smart App Control` driver blocklist, enforced via `Microsoft recommended driver block rules`) domain-wide - this blocks known-vulnerable drivers by hash at the OS level regardless of valid signature, closing the BYOVD path without requiring detection-layer visibility to catch it after the fact.

Hypothesis **confirmed**-an attacker staged a known-vulnerable, validly-signed kernel driver from a temp directory on an IT workstation, exploited it for kernel read/write access, and used that access to terminate the EDR agent within 90 seconds!
