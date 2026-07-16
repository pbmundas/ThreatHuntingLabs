---
layout: default
title: Hunting Exercise - 100
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Firewall Low-and-Slow Idle-Session C2 Beacon Dataset

This hunt uses a simulated perimeter firewall dataset (`fw_idle_session_c2_2022-11-08T000000.json`) capturing **T1071.001 / T1029: Scheduled Transfer**, where a C2 implant deliberately holds open a long-lived, low-traffic outbound session and only exchanges small heartbeat packets at extended, jittered intervals to evade both volumetric detection and short session-timeout-based monitoring.

#### Step 1: Hypothesis Formation
**Hypothesis**: A host maintains a single outbound TCP session to an external IP for an unusually long duration (many hours) while transferring only small amounts of data at irregular, widely-spaced intervals, indicating a long-lived C2 channel using a low-and-slow beaconing pattern rather than a legitimate long-poll or streaming application. Indicators:
- Single session duration exceeds typical application timeouts (e.g., >6 hours) without renegotiation.
- Total bytes transferred are minimal (a few KB) relative to session duration.
- Data transfer occurs in small, irregular bursts rather than a steady stream (ruling out legitimate streaming/VoIP).
- Destination is a low-reputation or newly-observed IP/ASN with no corresponding sanctioned-application entry.

**Null Hypothesis**: The session is a legitimate long-poll application (e.g., a chat client, monitoring agent, or webhook listener) that intentionally keeps connections open with minimal keepalive traffic. Invalidate by checking the destination against the sanctioned-application inventory and the process/binary initiating the connection.

**Rationale**: Low-and-slow C2 channels are designed specifically to defeat both volume-based (bytes-transferred) and duration-based (session-timeout) detection thresholds simultaneously, so they require combining long-session-duration analytics with byte-count and burst-interval irregularity to surface.

#### Step 2: Data Sources and Scope
- **Sources**: Perimeter firewall/NGFW session logs with duration and byte-count fields; endpoint process-network correlation (EDR); sanctioned-application inventory.
- **Scope**: ~2022-11-08T00:00:00-13:40:00 UTC; Host: WKS-OPS-039 (10.77.2.14); Destination: 185.220.101.47:443 (bulletproof-hosted ASN).
- **SIEM Queries** (Splunk/ELK):
  - `index=firewall dest_port=443 | eval duration_hrs=(session_end-session_start)/3600 | where duration_hrs > 6 AND bytes_total < 51200`
  - Burst-interval analysis: `index=firewall src_ip="10.77.2.14" dest_ip="185.220.101.47" | streamstats window=2 range(_time) as gap by _time | stats avg(gap) stdev(gap)`
  - Process correlation: `index=edr host="WKS-OPS-039" dest_ip="185.220.101.47" | table _time process_name parent_process`

#### Step 3: Key Findings
Parsed events (5 shown) confirm WKS-OPS-039 maintained a single 13-hour-40-minute outbound TLS session to a bulletproof-hosted IP, exchanging only 38 KB total in irregular micro-bursts.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-08 00:00:12 | WKS-OPS-039 | Firewall (session start) | TCP/443 session opened to 185.220.101.47, ASN "Unallocated/Bulletproof Hosting" | **Reputation IOC**: destination ASN has no corresponding sanctioned-application entry and is associated with bulletproof hosting in threat-intel feeds. |
| 2022-11-08 00:00:12 - 13:40:47 | WKS-OPS-039 | Firewall (aggregate) | Single unbroken session, 13h40m duration, 38 KB total bytes transferred | **Duration/Volume IOC**: a 13+ hour session carrying only 38 KB is inconsistent with any legitimate streaming or bulk-transfer use case; it matches a beaconing implant's keepalive pattern. |
| 2022-11-08 00:00:12 - 13:40:47 | WKS-OPS-039 | Firewall (burst analysis) | 41 distinct micro-bursts of 200-900 bytes each, inter-burst gaps ranging 8-34 minutes (jittered) | **Jitter IOC**: irregular, randomized intervals between small data bursts are the signature of a jittered sleep/beacon C2 implant rather than a fixed-interval keepalive or heartbeat protocol. |
| 2022-11-08 00:00:05 | WKS-OPS-039 | (EDR process event) | `rundll32.exe` with no command-line arguments spawned by `explorer.exe`, established the outbound connection | **Tooling IOC**: `rundll32.exe` with an empty command line and no legitimate DLL export is a common LOLBIN C2-loader pattern. |
| - | - | (App-inventory check) | 185.220.101.47 has no entry in the sanctioned SaaS/webhook/long-poll application list | Confirms no legitimate business purpose is associated with the destination. |

**Validation**:
- **Timeline**: an anomalous `rundll32.exe` process opened a single long session that persisted for over 13 hours with jittered micro-bursts, matching a deliberate low-and-slow C2 pattern rather than any known application behavior.
- **False Positives**: destination is absent from the sanctioned-application and webhook inventory.
- **Correlation**: session duration, minimal/irregular byte transfer, jittered burst timing, and suspicious process lineage jointly confirm a covert C2 channel.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-OPS-039, capture full packet capture (if available) for the session, block the destination IP/ASN at the perimeter, and hunt for other internal hosts communicating with the same ASN.
- **Detection**: Sigma-style rule: `title: Low-and-Slow Long-Duration C2 Session` → `selection: session_duration_hrs > 6 AND bytes_total < 51200 AND dest_asn_reputation="low"` → `condition: selection`.
- **Pro Tip**: Build a UEBA analytic on session-duration-to-byte-count ratio combined with inter-burst timing variance (jitter) rather than relying on byte-volume thresholds alone - pure volume-based egress alerting is blind to implants specifically engineered to stay under any reasonable transfer-size limit.

Hypothesis **confirmed**-a workstation process with no legitimate DLL export maintained a 13-hour-40-minute jittered micro-burst session to a bulletproof-hosted IP, consistent with a low-and-slow C2 beacon evading volumetric detection!
