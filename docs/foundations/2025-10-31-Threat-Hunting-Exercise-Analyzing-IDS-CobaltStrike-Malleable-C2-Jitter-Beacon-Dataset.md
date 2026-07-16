---
layout: default
title: Hunting Exercise - 101
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing IDS Cobalt Strike Malleable C2 Jitter Beacon Dataset

This hunt uses a simulated IDS/IPS alert dataset (`ids_cs_malleable_2022-11-10T091000.json`) capturing **T1071.001: Web Protocols (Cobalt Strike Malleable C2)**, where a compromised host beacons to a C2 profile disguised as legitimate-looking HTTP/S traffic (e.g., mimicking a CDN or analytics service) but exhibits the characteristic fixed-interval-plus-jitter timing of a Cobalt Strike beacon.

#### Step 1: Hypothesis Formation
**Hypothesis**: A host generates repeated outbound HTTP/S requests to the same destination at a statistically regular base interval with a bounded random jitter percentage, and the request/response structure (URI patterns, headers, response size) matches a known Cobalt Strike malleable-C2 profile signature, indicating an active beacon rather than legitimate polling traffic. Indicators:
- IDS signature match on known malleable-C2 URI/header patterns (e.g., specific `Content-Type`, cookie-naming conventions, or fixed URI stems like `/jquery-3.3.1.min.js`).
- Beacon interval clusters tightly around a fixed value (e.g., 60s) with jitter bounded within a fixed percentage (e.g., ±20%).
- Response payload sizes are unusually consistent/small regardless of the URI requested, atypical of real web content.
- The requesting process is not a browser (no accompanying rendering/DOM activity, non-browser process image).

**Null Hypothesis**: The traffic is a legitimate polling application (e.g., a monitoring agent or SaaS heartbeat) that happens to use a regular interval and a CDN-style URI structure. Invalidate by checking the process image against known-good software inventory and confirming the destination domain's legitimacy via passive DNS/WHOIS history.

**Rationale**: Malleable C2 profiles are purpose-built to make Cobalt Strike traffic resemble benign web traffic to a human analyst reviewing raw logs, so detection depends on statistical beacon-interval analysis and payload-consistency signatures rather than surface-level URI/domain inspection alone.

#### Step 2: Data Sources and Scope
- **Sources**: IDS/IPS signature alerts (Suricata/Snort with ET/CS malleable-profile rules); perimeter proxy logs; endpoint process-network correlation (EDR).
- **Scope**: ~2022-11-10T09:10:00-11:55:00 UTC; Host: WKS-DEV-071 (10.30.9.44); Destination: `cdn-assets-edge.net` (185.199.108.201).
- **SIEM Queries** (Splunk/ELK):
  - `index=ids signature="ET MALWARE Cobalt Strike Beacon Profile" | table _time src_ip dest_ip signature`
  - Interval regularity: `index=proxy dest_domain="cdn-assets-edge.net" | streamstats window=2 range(_time) as gap by src_ip | stats avg(gap) stdev(gap) count`
  - Process correlation: `index=edr host="WKS-DEV-071" dest_ip="185.199.108.201" | table _time process_name process_hash`

#### Step 3: Key Findings
Parsed events (5 shown) confirm WKS-DEV-071 beaconed to a spoofed "CDN" domain every ~60 seconds (±18% jitter) for nearly 3 hours, with response sizes matching a known Cobalt Strike default profile.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-10 09:10:03 | WKS-DEV-071 | IDS Alert | `ET MALWARE Cobalt Strike Beacon Profile (jquery URI + cookie pattern)` triggered on GET `/jquery-3.3.1.min.js` | **Signature IOC**: this specific URI-plus-cookie combination matches a widely-reused default/leaked Cobalt Strike malleable-C2 profile. |
| 2022-11-10 09:10:03 - 11:54:58 | WKS-DEV-071 | Proxy (aggregate) | 166 requests to `cdn-assets-edge.net`, mean interval 60.4s, stdev 10.8s (~18% jitter) | **Beacon-Interval IOC**: this tight statistical clustering around a fixed base interval with bounded jitter is characteristic of automated beaconing, not human-driven or event-driven browsing. |
| 2022-11-10 09:10:03 - 11:54:58 | WKS-DEV-071 | Proxy (aggregate) | Response body size fixed at exactly 2,048 bytes across all 166 requests regardless of URI queried | **Payload-Consistency IOC**: real CDN-hosted JS libraries vary in size and rarely return an identical byte count on every request; this indicates a synthetic C2 response, not real content. |
| 2022-11-10 09:10:00 | WKS-DEV-071 | (EDR process event) | Process `rundll32.exe`, no window/UI thread, hash matches known Cobalt Strike beacon.dll loader | **Non-Browser IOC**: the requesting process has no rendering engine or DOM activity, ruling out a legitimate browser-based fetch. |
| - | - | (Passive DNS check) | `cdn-assets-edge.net` registered 6 days prior; no historical resolution before registration; not a recognized CDN provider | Confirms the domain is attacker-registered infrastructure impersonating a CDN, not legitimate third-party content delivery. |

**Validation**:
- **Timeline**: a non-browser process began issuing statistically regular, jittered requests to a newly-registered domain with fixed-size synthetic responses matching a known C2 profile - a complete beacon-detection chain.
- **False Positives**: process image does not match any known-good monitoring/polling software, and the domain has no legitimate CDN history.
- **Correlation**: IDS signature match, beacon-interval statistics, payload-size consistency, and process/domain provenance jointly confirm active Cobalt Strike C2.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-DEV-071, extract and submit the beacon DLL/hash for reverse engineering to recover the full C2 profile and any embedded configuration, and block the destination domain/IP at the proxy and DNS layers.
- **Detection**: Sigma-style rule: `title: Regular-Interval Beacon to Low-Age Domain` → `selection: dest_domain_age_days < 30 | streamstats window=2 range(_time) as gap by src_ip,dest_domain | stats stdev(gap) as jitter, avg(gap) as interval, count | where count > 20 AND jitter < (interval*0.3)` → `condition: selection`.
- **Pro Tip**: Extract and fingerprint the malleable-C2 profile characteristics (fixed response size, header ordering, cookie-naming convention) into a dedicated detection rule set - malleable profiles are frequently reused or lightly modified from publicly leaked templates, so a profile fingerprint can catch future campaigns even after the domain and interval change.

Hypothesis **confirmed**-a developer workstation was beaconing every ~60 seconds to a newly-registered domain impersonating a CDN, using a Cobalt Strike malleable-C2 profile with fixed synthetic response sizes to blend into normal web traffic!
