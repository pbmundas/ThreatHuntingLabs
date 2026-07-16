---
layout: default
title: Hunting Exercise - 98
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Firewall Outbound SMTP Relay Spam Botnet Dataset

This hunt uses a simulated perimeter firewall dataset (`firewall_smtp_relay_2022-11-02T031500.json`) capturing **T1583.001 / T1071.003 (via compromised host abuse)**, where a compromised internal host is repurposed as an open relay, sending high-volume outbound SMTP traffic on port 25/587 to hundreds of distinct external mail servers - a hallmark of spam-botnet or BEC-infrastructure abuse.

#### Step 1: Hypothesis Formation
**Hypothesis**: A non-mail-server host (workstation or server not on the approved SMTP relay list) establishes an abnormally high number of distinct outbound SMTP connections in a short window, indicating it has been compromised and conscripted into a spam-sending botnet or is being used to relay BEC phishing emails. Indicators:
- Source host is not in the organization's authorized mail-relay/MTA inventory.
- High fan-out: dozens to hundreds of unique destination IPs on TCP/25 or TCP/587 within minutes.
- Connections occur outside normal business-application traffic patterns for that host (e.g., a finance workstation, not an Exchange server).
- SMTP payload/banner grabs show non-standard or spoofed HELO/EHLO strings.

**Null Hypothesis**: The host is a legitimate application server (e.g., a marketing automation or ticketing system) configured to send transactional email directly rather than through the corporate MTA. Invalidate by checking CMDB/application-inventory records and DNS PTR/SPF alignment for the source IP.

**Rationale**: Spam botnets and BEC actors frequently abuse compromised internal hosts as email relays because outbound port 25/587 is often left open for legitimate application mail, making it a low-friction path that blends with normal business traffic unless fan-out and host-role are cross-checked.

#### Step 2: Data Sources and Scope
- **Sources**: Perimeter firewall/NGFW connection logs; internal MTA/relay inventory (CMDB); DNS PTR and SPF records.
- **Scope**: ~2022-11-02T03:15:00-04:05:00 UTC; Host: WKS-FIN-114 (10.44.6.91); Destinations: 214 distinct external mail-server IPs.
- **SIEM Queries** (Splunk/ELK):
  - `index=firewall dest_port IN (25,587) | stats dc(dest_ip) as unique_dests, count by src_ip | where unique_dests > 50`
  - Relay-inventory check: `| lookup authorized_mta_hosts src_ip OUTPUT is_authorized | where is_authorized=false`
  - SMTP banner: `index=firewall dest_port=25 src_ip="10.44.6.91" | table _time dest_ip smtp_helo`

#### Step 3: Key Findings
Parsed events (5 shown) confirm WKS-FIN-114, a standard finance workstation, sent SMTP connections to 214 distinct external mail servers in under an hour, immediately following a phishing-delivered macro execution.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-02 03:12:40 | WKS-FIN-114 | (EDR process event) | `winword.exe` spawned `powershell.exe -enc <b64>`, which dropped `svchost32.exe` in `%APPDATA%` | **Delivery IOC**: process lineage shows a macro-triggered dropper immediately preceding the mass-mail activity, consistent with a spam-bot payload installation. |
| 2022-11-02 03:15:02 | WKS-FIN-114 | Firewall (allow, TCP/25) | First of 214 unique SMTP connections, HELO string `mail-out-921.local` (does not resolve) | **Fan-Out IOC**: this host has no history of direct SMTP traffic; the sudden onset of mass connections to unrelated external mail servers is a classic spam-botnet signature. |
| 2022-11-02 03:15:02 - 04:04:51 | WKS-FIN-114 | Firewall (aggregate) | 214 unique destination IPs, port 25/587, ~1,900 total connection attempts | **Volume IOC**: this volume vastly exceeds any legitimate transactional-mail use case for a finance workstation, and matches known spam-relay throughput patterns. |
| 2022-11-02 03:16:10 | WKS-FIN-114 | (EDR process event) | `svchost32.exe` reading `contacts.csv` and `outlook_addresses.txt` from user profile | **Targeting IOC**: local harvesting of address-book data immediately before mass-SMTP activity suggests the bot is using stolen contacts as a spam/BEC target list. |
| - | - | (CMDB/relay-inventory check) | WKS-FIN-114 is absent from the authorized-MTA host list; SPF record for the domain does not include this host's IP | Confirms the host has no legitimate business reason to originate direct SMTP traffic. |

**Validation**:
- **Timeline**: macro-delivered dropper, local contact-list harvesting, then mass fan-out SMTP relay activity - a complete spam-botnet conscription chain.
- **False Positives**: no CMDB entry or SPF authorization exists for this host as a mail sender.
- **Correlation**: malicious process lineage, contact-harvesting, and abnormal SMTP fan-out jointly confirm the host was compromised and used as an unauthorized spam relay.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-FIN-114, block outbound TCP/25 and TCP/587 from non-MTA subnets at the firewall, notify email-reputation/blocklist providers proactively, and rotate credentials for the affected user.
- **Detection**: Sigma-style rule: `title: Non-MTA Host SMTP Fan-Out` → `selection: dest_port IN (25,587) AND src_ip NOT IN authorized_mta_hosts | stats dc(dest_ip) as fanout by src_ip | where fanout > 20` → `condition: selection`.
- **Pro Tip**: Enforce an explicit outbound-SMTP allow-list at the firewall (only designated MTA/relay hosts permitted on 25/587) rather than relying on host-based egress filtering alone - this collapses an entire class of spam-botnet and BEC-relay abuse to a single, easily monitored choke point.

Hypothesis **confirmed**-a phishing-compromised finance workstation harvested local contact data and was conscripted into a spam-relay botnet, firing SMTP connections at 214 external mail servers within an hour!
