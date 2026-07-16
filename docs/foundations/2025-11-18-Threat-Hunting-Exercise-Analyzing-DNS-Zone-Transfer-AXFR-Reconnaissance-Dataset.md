---
layout: default
title: Hunting Exercise - 119
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing DNS Zone Transfer AXFR Reconnaissance Dataset

This hunt uses a simulated authoritative-DNS-server dataset (`dns_axfr_recon_2022-12-16T044500.json`) capturing **T1590.002: Gather Victim Network Information: DNS**, where an external actor requests a full zone transfer (AXFR) from an authoritative DNS server misconfigured to allow transfers from arbitrary sources, instantly revealing the organization's entire internal and external DNS namespace - hostnames, internal IP ranges, and infrastructure naming conventions - in a single query.

#### Step 1: Hypothesis Formation
**Hypothesis**: An authoritative DNS server receives a DNS query with `QTYPE=AXFR` (or `IXFR`) from a source IP that is not one of the organization's registered secondary/slave name servers, and the server responds with a successful (non-refused) transfer, indicating the zone is misconfigured to allow unrestricted transfers and has just disclosed its complete DNS record set to an unauthorized party. Indicators:
- DNS query log entry with `qtype=AXFR` or `qtype=IXFR` from a source IP outside the documented secondary-nameserver allow-list.
- Server response code is `NOERROR` with a full zone record count returned (not `REFUSED`, which would indicate the transfer was correctly denied).
- The requesting source IP has no prior DNS query history against this authoritative server (a first-and-only contact, consistent with a scan-and-grab reconnaissance tool rather than an operational secondary DNS relationship).
- The returned zone contains internal-only hostnames/records (e.g., `vpn-gw`, `db-prod`, RFC1918 PTR records) that reveal internal network topology beyond what is intentionally public.

**Null Hypothesis**: The request originates from a legitimate, newly-added secondary DNS provider or a DNS-health-monitoring service performing an authorized transfer as part of a documented DNS-infrastructure change. Invalidate by checking the source IP against the current NS-delegation records and any recent DNS-infrastructure change tickets.

**Rationale**: A successful AXFR to an unauthorized source is one of the highest-value, lowest-effort reconnaissance techniques available to an external attacker because a single query can return the organization's entire hostname inventory and internal addressing scheme at once, information that would otherwise require extensive individual subdomain brute-forcing to assemble.

#### Step 2: Data Sources and Scope
- **Sources**: Authoritative DNS server query logs (BIND `named` query log or equivalent); NS-delegation/secondary-server registration records; DNS-infrastructure change-ticket system.
- **Scope**: ~2022-12-16T04:45:00-04:45:12 UTC; Authoritative Server: `ns1.corp-example.com` (203.0.113.10); Source: 45.155.205.87 (external, no prior history).
- **SIEM Queries** (Splunk/ELK):
  - `index=dns_auth qtype=AXFR OR qtype=IXFR | table _time src_ip zone rcode records_returned`
  - Unauthorized-source check: `| lookup registered_secondary_ns src_ip OUTPUT is_authorized | where is_authorized=false`
  - Prior-history check: `index=dns_auth src_ip="45.155.205.87" earliest=-90d` (expect zero results before this event)

#### Step 3: Key Findings
Parsed events (4 shown) confirm `ns1.corp-example.com` completed a full, unauthenticated AXFR zone transfer to an unrecognized external IP, disclosing 214 DNS records including 12 internal-only hostnames.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-16 04:45:03 | ns1.corp-example.com | DNS Query Log | `qtype=AXFR`, `zone=corp-example.com`, `src_ip=45.155.205.87`, `rcode=NOERROR` | **Successful-Transfer IOC**: a `NOERROR` response to an AXFR request means the server actually performed the zone transfer rather than correctly rejecting it with `REFUSED`, confirming a transfer-restriction misconfiguration. |
| 2022-12-16 04:45:04 - 04:45:11 | ns1.corp-example.com | DNS Query Log (aggregate) | 214 resource records transferred, response size 38.4 KB, single TCP session | **Volume IOC**: this record count matches the organization's actual total known zone size, confirming a complete - not partial - namespace disclosure occurred in one transaction. |
| - | - | (Registered-secondary check) | `45.155.205.87` does not appear in the NS-delegation or secondary-DNS-provider registration records | **Unauthorized-Source IOC**: this IP has no legitimate operational relationship with the organization's DNS infrastructure. |
| - | - | (Zone-content review) | Transferred records include `vpn-gw.corp-example.com`, `db-prod-01.corp-example.com`, and 10 additional internal-facing hostnames with public-routable A records | **Disclosure-Impact IOC**: these internal-infrastructure hostnames were not intended for public discovery and now provide the requester with a targeted map of high-value internal systems for follow-on reconnaissance or attack. |

**Validation**:
- **Timeline**: a single unauthenticated AXFR request from a source with no prior query history successfully retrieved the organization's complete zone file in an 8-second transfer - a complete, low-effort reconnaissance event.
- **False Positives**: no NS-delegation record or change-management ticket authorizes this source as a secondary name server.
- **Correlation**: successful (non-refused) transfer response, unauthorized source-IP status, full-zone record count, and disclosure of sensitive internal hostnames jointly confirm unauthorized DNS zone transfer reconnaissance.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Immediately restrict zone transfers on `ns1.corp-example.com` to only the organization's registered secondary name-server IPs (`allow-transfer` in BIND or equivalent), review and rotate/rename any exposed internal hostnames that reveal sensitive function (e.g., renaming `db-prod-01` to a non-descriptive identifier), and treat all disclosed internal hosts as having elevated reconnaissance exposure going forward.
- **Detection**: Sigma-style rule: `title: DNS Zone Transfer to Unauthorized Source` → `selection: qtype IN ("AXFR","IXFR") rcode="NOERROR" AND src_ip NOT IN (registered_secondary_ns)` → `condition: selection`.
- **Pro Tip**: Explicitly configure `allow-transfer { <secondary-ns-ips>; };` (or the equivalent ACL on your DNS platform) on every authoritative zone rather than leaving the default (often "any") in place - this single configuration line eliminates AXFR-based reconnaissance entirely, and should be paired with a periodic external AXFR-attempt test against your own domains to verify the restriction remains correctly applied after any DNS platform change.

Hypothesis **confirmed**-an unauthorized external source successfully requested and received a complete, unrestricted AXFR zone transfer from a misconfigured authoritative DNS server, disclosing 214 records including sensitive internal infrastructure hostnames!
