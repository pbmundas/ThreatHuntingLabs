---
layout: default
title: Hunting Exercise - 103
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing IDS Self-Signed Certificate JA3S Fingerprint C2 Dataset

This hunt uses a simulated IDS/IPS TLS-inspection dataset (`ids_ja3s_selfsigned_2022-11-14T081500.json`) capturing **T1573.002: Asymmetric Cryptography (TLS)**, where a C2 server presents a self-signed certificate with a JA3S (server-side TLS fingerprint) that matches a known C2-framework default, allowing detection even when the SNI/domain rotates.

#### Step 1: Hypothesis Formation
**Hypothesis**: An internal host completes a TLS handshake with an external server presenting a self-signed certificate whose JA3S hash matches a known malicious-framework fingerprint (e.g., default Metasploit, Mythic, or Sliver TLS stacks), regardless of the domain/SNI presented, indicating C2 infrastructure rather than a legitimate self-signed internal or test service. Indicators:
- Server certificate is self-signed (issuer == subject) and not chained to a trusted root CA.
- JA3S fingerprint of the server's TLS response matches a threat-intel-published C2-framework default fingerprint.
- Certificate validity period, key size, or subject fields match a known auto-generated default template (e.g., generic CN like "localhost" issued for a public IP).
- Session is not to an internally-known self-signed test/dev endpoint already in the exceptions list.

**Null Hypothesis**: The connection targets an internal or partner test/staging environment that legitimately uses a self-signed certificate as documented policy. Invalidate by checking the destination IP against the internal self-signed-certificate exceptions list.

**Rationale**: JA3S fingerprinting is resilient to the domain-fronting and SNI-rotation techniques attackers use to evade domain-reputation-based blocking, because it fingerprints the server's TLS stack/configuration itself rather than any single presented hostname, making it a durable detection signal against infrastructure reuse across campaigns.

#### Step 2: Data Sources and Scope
- **Sources**: IDS/IPS with JA3/JA3S TLS fingerprinting (Suricata/Zeek); certificate-transparency and threat-intel JA3S fingerprint feeds; internal self-signed-cert exceptions list.
- **Scope**: ~2022-11-14T08:15:00-08:22:00 UTC; Host: WKS-LEGAL-018 (10.55.7.62); Destination: 91.240.118.30:443.
- **SIEM Queries** (Splunk/ELK):
  - `index=ids protocol=tls | lookup ja3s_threat_intel ja3s_hash OUTPUT framework_name | where isnotnull(framework_name)`
  - Self-signed check: `index=ids protocol=tls issuer=subject | table _time src_ip dest_ip ja3s_hash cert_cn`
  - Exceptions check: `| lookup selfsigned_exceptions dest_ip OUTPUT is_approved | where is_approved=false`

#### Step 3: Key Findings
Parsed events (4 shown) confirm WKS-LEGAL-018 completed a TLS handshake with an external IP presenting a self-signed certificate whose JA3S hash matches a published Sliver C2 framework default fingerprint.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-14 08:18:44 | WKS-LEGAL-018 | IDS (TLS handshake log) | TLS 1.2 handshake to 91.240.118.30:443, `ja3s=e35df3e00ca4ef31d42b34bebaa2f86e` | **JA3S-Match IOC**: this exact JA3S hash is published in multiple open threat-intel feeds as the default server-side fingerprint for the Sliver C2 framework's TLS listener. |
| 2022-11-14 08:18:44 | WKS-LEGAL-018 | IDS (certificate detail) | Certificate: issuer == subject (`CN=localhost`), validity 2022-11-14 to 2023-11-14 (exactly 365 days), RSA 2048-bit | **Auto-Generated-Cert IOC**: a generic "localhost" CN issued for a public-facing IP, with a round-numbered validity period, matches the auto-generated default certificate template used by several open-source C2 frameworks. |
| 2022-11-14 08:18:45 - 08:21:59 | WKS-LEGAL-018 | IDS (aggregate) | 3 additional short handshakes to the same IP over 3 minutes, no application data logged (encrypted) | **Session-Pattern IOC**: repeated short handshake-only sessions without subsequent visible browsing activity are consistent with implant check-in behavior rather than normal web use. |
| - | - | (Exceptions-list check) | 91.240.118.30 is not present in the internal self-signed-certificate exceptions inventory | Confirms this is not an approved internal/partner test endpoint. |

**Validation**:
- **Timeline**: repeated short TLS handshakes to an external IP presenting a self-signed certificate matching a published C2-framework JA3S fingerprint, with no corresponding browsing activity - consistent with an active implant check-in.
- **False Positives**: destination is absent from the approved self-signed-certificate exceptions list.
- **Correlation**: JA3S threat-intel match, auto-generated certificate template, and repeated handshake-only session pattern jointly confirm C2 infrastructure.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-LEGAL-018, block 91.240.118.30 at the perimeter, hunt across the environment for any other host with a TLS session sharing the same JA3S hash (since SNI/domain may differ per host), and identify the initial-access process on WKS-LEGAL-018.
- **Detection**: Sigma-style rule: `title: TLS Session Matches Known C2 JA3S Fingerprint` → `selection: protocol=tls | lookup ja3s_threat_intel ja3s_hash OUTPUT framework_name | where isnotnull(framework_name)` → `condition: selection`.
- **Pro Tip**: Maintain and continuously update a JA3S watchlist sourced from open threat-intel feeds and your own confirmed-malicious captures - because JA3S fingerprints attacker server infrastructure rather than any single domain, it remains effective detection even as adversaries rotate SNI/domain fronting to evade reputation-based blocking.

Hypothesis **confirmed**-a legal-department workstation completed repeated handshake-only TLS sessions with an external IP whose self-signed certificate's JA3S fingerprint matches a published Sliver C2 framework default, confirming an active covert C2 channel!
