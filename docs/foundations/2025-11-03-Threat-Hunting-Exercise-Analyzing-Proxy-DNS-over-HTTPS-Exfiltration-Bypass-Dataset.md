---
layout: default
title: Hunting Exercise - 104
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Proxy DNS-over-HTTPS Exfiltration Bypass Dataset

This hunt uses a simulated web-proxy dataset (`proxy_doh_bypass_2022-11-16T112000.json`) capturing **T1071.004: DNS combined with T1048: Exfiltration Over Alternative Protocol**, where an attacker uses a public DNS-over-HTTPS (DoH) resolver to both bypass DNS-layer security controls and covertly tunnel data, since DoH traffic is encrypted HTTPS and often invisible to traditional DNS monitoring.

#### Step 1: Hypothesis Formation
**Hypothesis**: A host establishes repeated HTTPS connections to a known public DoH resolver endpoint (e.g., Cloudflare `1.1.1.1`/`cloudflare-dns.com`, Google `dns.google`) from a process other than the operating system's configured DNS stack or an approved browser, with request/response sizes and cadence inconsistent with normal name resolution, indicating DoH is being used to bypass DNS security controls and/or tunnel data. Indicators:
- HTTPS POST/GET requests to a known public DoH endpoint's resolution path (e.g., `/dns-query`) from a non-browser or non-OS-resolver process.
- The organization's DNS security/filtering solution shows a corresponding gap - no matching standard DNS query was logged for the same lookups.
- Request sizes or frequency exceed what normal name-resolution traffic would require (query volume disproportionate to actual browsing/application activity).
- The host's local DNS client settings show DoH was manually enabled or a proxy/relay tool is present.

**Null Hypothesis**: A modern browser with DoH enabled by default (e.g., Firefox, Chrome with secure-DNS) is performing legitimate encrypted name resolution as part of standard, policy-permitted browsing. Invalidate by confirming the process is a sanctioned browser and that DoH usage is covered by existing security policy/monitoring exceptions.

**Rationale**: DoH collapses DNS queries into ordinary-looking HTTPS traffic, which defeats DNS-layer security controls (sinkholing, RPZ, DNS-based threat-intel blocking) entirely unless the organization explicitly inspects or blocks DoH endpoints, making it an attractive both reconnaissance-evasion and low-bandwidth exfiltration channel.

#### Step 2: Data Sources and Scope
- **Sources**: Web/forward-proxy logs with SNI and URI-path visibility; endpoint DNS-client configuration telemetry; standard DNS query logs (for gap analysis).
- **Scope**: ~2022-11-16T11:20:00-12:05:00 UTC; Host: SVR-DEVOPS-06 (10.90.4.17); Destination: `cloudflare-dns.com/dns-query`.
- **SIEM Queries** (Splunk/ELK):
  - `index=proxy uri_path="/dns-query" dest_domain IN ("cloudflare-dns.com","dns.google","doh.opendns.com")`
  - Non-browser check: `index=edr host="SVR-DEVOPS-06" dest_domain="cloudflare-dns.com" | table _time process_name`
  - DNS-gap correlation: `index=dns host="SVR-DEVOPS-06" | stats count as std_dns_queries` compared against proxy DoH request count in the same window.

#### Step 3: Key Findings
Parsed events (5 shown) confirm SVR-DEVOPS-06 issued 2,140 DoH requests over 45 minutes from a non-browser scripting process, with query lengths far exceeding normal hostname sizes.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-16 11:20:08 | SVR-DEVOPS-06 | Proxy | POST `https://cloudflare-dns.com/dns-query`, `Content-Type: application/dns-message`, body 412 bytes | **Volume/Size IOC**: DoH query bodies are typically under 100 bytes for a standard hostname lookup; a 412-byte body suggests an oversized, encoded subdomain payload rather than a real name-resolution request. |
| 2022-11-16 11:20:08 - 12:05:41 | SVR-DEVOPS-06 | Proxy (aggregate) | 2,140 POST requests to the same DoH endpoint in 45 minutes, avg. interval 1.3s | **Cadence IOC**: this request volume and near-constant interval vastly exceeds what any legitimate application's name-resolution needs would generate. |
| 2022-11-16 11:20:05 | SVR-DEVOPS-06 | (EDR process event) | Process `python3` executing script `dns_exfil.py`, no browser process present | **Process IOC**: the requests originate from a custom Python script rather than a sanctioned browser or the OS DNS client, ruling out legitimate secure-DNS browsing. |
| 2022-11-16 11:20:00 - 12:05:41 | SVR-DEVOPS-06 | Standard DNS Logs | Zero standard UDP/53 DNS queries logged for this host in the same window | **Gap IOC**: a complete absence of standard DNS activity, combined with heavy DoH traffic, confirms DoH is being used to fully bypass the organization's DNS-layer security stack, not supplement it. |
| - | - | (Payload analysis) | Decoded DoH query names follow the pattern `<base32-chunk>.exfil.attacker-domain.net`, consistent with DNS-tunneling encoding | Confirms the DoH channel is carrying encoded exfiltration data rather than genuine hostname lookups. |

**Validation**:
- **Timeline**: a scripted process began issuing oversized, high-frequency DoH requests encoding tunneled data, with a complete absence of corresponding standard DNS traffic - a complete DoH-based exfiltration chain.
- **False Positives**: the source process is a custom script, not a sanctioned browser, ruling out legitimate default secure-DNS usage.
- **Correlation**: oversized query bodies, abnormal request cadence, non-browser process origin, DNS-log gap, and base32-encoded query-name structure jointly confirm DoH tunneling for data exfiltration.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate SVR-DEVOPS-06, block outbound access to public DoH endpoints at the proxy/firewall for non-approved processes, capture and decode the full DoH query set to scope data loss, and identify how `dns_exfil.py` was introduced.
- **Detection**: Sigma-style rule: `title: High-Volume DoH Requests From Non-Browser Process` → `selection: uri_path="/dns-query" dest_domain IN (known_doh_providers) | stats count by src_ip, process_name | where count > 200 AND process_name NOT IN (approved_browsers)` → `condition: selection`.
- **Pro Tip**: Explicitly block or force-redirect known public DoH provider endpoints at the enterprise firewall/proxy (forcing all DNS resolution through the organization's monitored resolver) rather than trying to distinguish "good" from "bad" DoH traffic after the fact - this closes the DNS-security-bypass vector entirely while still allowing encrypted DNS through an internally-controlled, inspectable resolver.

Hypothesis **confirmed**-a DevOps server ran a custom Python script issuing over 2,100 oversized DoH requests encoding tunneled data to a public resolver, completely bypassing standard DNS security monitoring!
