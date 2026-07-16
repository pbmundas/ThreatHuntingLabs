---
layout: default
title: Hunting Exercise - 105
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Proxy Malicious Browser Extension Data Exfiltration Dataset

This hunt uses a simulated web-proxy dataset (`proxy_ext_exfil_2022-11-18T134500.json`) capturing **T1176: Browser Extensions** used for **T1114/T1005: collected-data exfiltration**, where a malicious or compromised browser extension harvests form-field data, cookies, and clipboard content and periodically exfiltrates it to an attacker-controlled endpoint disguised as extension "analytics" traffic.

#### Step 1: Hypothesis Formation
**Hypothesis**: A browser process on a host makes periodic outbound POST requests to a domain not associated with the currently-browsed sites, carrying a `chrome-extension://` or extension-identifiable `Origin`/`Referer` header, with payloads containing serialized form-data or cookie-like structures, indicating a malicious extension is harvesting and exfiltrating browsing data. Indicators:
- Outbound POST requests originate with an `Origin` header of `chrome-extension://<id>` or `moz-extension://<id>` rather than a normal page origin.
- Destination domain does not match any site the user has actively browsed to in the same session (cross-site data being sent to a third party).
- Request payload, when decoded, contains structured key-value data resembling form fields, autofill data, or cookie strings.
- The extension ID is not present in the organization's approved/whitelisted browser-extension inventory.

**Null Hypothesis**: A legitimate, approved productivity or security extension (e.g., a password manager or ad-blocker) is sending anonymized telemetry to its own vendor-operated analytics endpoint as documented in its privacy policy. Invalidate by checking the extension ID against the enterprise-approved extension allow-list and the destination against the vendor's documented telemetry domains.

**Rationale**: Malicious browser extensions operate with broad page-content access by design and can exfiltrate sensitive data entirely within HTTPS traffic that looks like ordinary web/analytics requests, so distinguishing them requires correlating the extension-origin header and payload structure against an approved-extension inventory rather than relying on domain reputation alone.

#### Step 2: Data Sources and Scope
- **Sources**: Forward-proxy/TLS-inspection logs with `Origin`/`Referer` header visibility; browser extension-management telemetry (enterprise browser policy); approved-extension allow-list.
- **Scope**: ~2022-11-18T13:45:00-14:30:00 UTC; Host: WKS-HR-029 (10.23.5.81); Destination: `metrics-collect.io` (194.61.55.12).
- **SIEM Queries** (Splunk/ELK):
  - `index=proxy http_method=POST origin_header="chrome-extension://*" | stats count by src_ip dest_domain origin_header`
  - Cross-site check: `| eval mismatch=if(dest_domain!=active_tab_domain,1,0) | where mismatch=1`
  - Extension-inventory check: `| lookup approved_extensions extension_id OUTPUT is_approved | where is_approved=false`

#### Step 3: Key Findings
Parsed events (5 shown) confirm a browser extension on WKS-HR-029 exfiltrated autofill and cookie data to an unapproved third-party domain every 5 minutes over 45 minutes.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-18 13:45:22 | WKS-HR-029 | Proxy | POST `https://metrics-collect.io/collect`, `Origin: chrome-extension://plkjadeglmpckhhoihplkbbmilllbjkc` | **Extension-Origin IOC**: the request explicitly originates from a browser extension context, not a webpage the user navigated to, meaning the extension itself initiated cross-site data transmission. |
| 2022-11-18 13:45:22 | WKS-HR-029 | Proxy (payload) | Decoded body contains JSON: `{"url":"hr-portal.corp.local/employee/ssn-update","fields":{"ssn":"***","dob":"***"}}` | **Sensitive-Data IOC**: the exfiltrated payload contains structured form-field data - including an SSN field - captured from an internal HR page the extension has no legitimate business reason to read. |
| 2022-11-18 13:45:22 - 14:30:11 | WKS-HR-029 | Proxy (aggregate) | 9 identical-structure POST requests to `metrics-collect.io`, exactly every 5 minutes | **Cadence IOC**: a fixed 5-minute exfiltration interval matches an automated harvesting loop rather than any user-driven or page-load-triggered analytics event. |
| 2022-11-18 13:40:05 | WKS-HR-029 | (Browser policy telemetry) | Extension `plkjadeglmpckhhoihplkbbmilllbjkc` ("QuickForm AutoFill Helper") installed from a sideloaded CRX, not the Chrome Web Store | **Distribution IOC**: sideloaded/unpacked extension installation bypasses store review and vetting, a common distribution method for malicious extensions. |
| - | - | (Extension-inventory check) | Extension ID is absent from the enterprise-approved extension allow-list | Confirms this extension was never vetted or authorized for use. |

**Validation**:
- **Timeline**: a sideloaded, unapproved extension began exfiltrating captured HR-portal form data (including SSN fields) to an external "metrics" domain on a fixed 5-minute interval - a complete data-harvesting-and-exfiltration chain.
- **False Positives**: no approved-extension inventory entry or documented telemetry domain covers this extension or destination.
- **Correlation**: extension-origin header, sensitive structured payload content, fixed-interval cadence, and sideloaded installation method jointly confirm malicious extension-based exfiltration.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Remove the extension from WKS-HR-029 and any other host where it is installed, block `metrics-collect.io` at the proxy/firewall, notify affected employees whose data may have been captured (SSN/DOB exposure), and treat this as a data-breach notification event pending legal/compliance review.
- **Detection**: Sigma-style rule: `title: Unapproved Browser Extension Cross-Site POST` → `selection: origin_header="chrome-extension://*" http_method=POST | lookup approved_extensions extension_id OUTPUT is_approved | where is_approved=false` → `condition: selection`.
- **Pro Tip**: Enforce browser extension allow-listing via enterprise browser management policy (blocking installation of any extension not on a centrally-approved list) rather than relying on store-review trust alone - sideloaded and even store-published extensions can be compromised post-approval via supply-chain updates, so continuous extension-ID monitoring against the allow-list is essential.

Hypothesis **confirmed**-a sideloaded browser extension on an HR workstation was harvesting sensitive employee form data, including SSNs, and exfiltrating it every 5 minutes to an unapproved external "analytics" domain!
