---
layout: default
title: Hunting Exercise - 118
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Email HTML Smuggling Phishing Attachment Delivery Dataset

This hunt uses a simulated email-gateway and endpoint dataset (`email_html_smuggling_2022-12-14T101500.json`) capturing **T1027.006: Obfuscated Files or Information: HTML Smuggling**, where an attacker embeds a malicious payload (an encoded executable or archive) inside JavaScript within an HTML email attachment, which is assembled and written to disk client-side in the browser - entirely bypassing network-level and gateway-level file inspection since no malicious file ever crosses the wire in its final form.

#### Step 1: Hypothesis Formation
**Hypothesis**: An email delivers an `.html`/`.htm` attachment (or a link to one) that, when opened, contains obfuscated JavaScript using `Blob`/`msSaveOrOpenBlob`/base64-decoding constructs to reconstruct and auto-trigger download of an embedded payload, and this download is followed shortly by execution of a file with an extension not native to normal browser downloads (`.iso`, `.js`, `.hta`, `.exe`), indicating HTML smuggling was used to bypass attachment-scanning controls. Indicators:
- Email-gateway attachment scan shows only an `.html` file was delivered, with no accompanying scan verdict on any embedded executable content (since the payload is client-side-assembled and never transits as a discrete file).
- The HTML file's source contains base64-encoded blobs combined with `Blob()`/`URL.createObjectURL()` or IE-legacy `msSaveBlob` JavaScript patterns.
- Browser download-history/EDR file-creation telemetry shows a new file (often `.iso`, `.img`, `.js`, or `.zip`) appearing in the Downloads folder immediately after the HTML attachment was opened, with no corresponding network download event for that file (because it was assembled locally, not fetched).
- The downloaded/mounted file is opened or executed within minutes, commonly an ISO mount followed by execution of a contained `.lnk`/`.js`/`.dll` dropper.

**Null Hypothesis**: The HTML attachment is a legitimate business report or interactive dashboard export that uses client-side JavaScript for benign rendering purposes (e.g., an exported Power BI report). Invalidate by checking the sender's authentication (SPF/DKIM/DMARC alignment) and whether the HTML structure matches a known-good reporting-tool export template.

**Rationale**: HTML smuggling is specifically designed to defeat gateway and network-layer file inspection, since the malicious payload literally does not exist as a discrete file until JavaScript executing inside the recipient's own browser reconstructs it - meaning detection must shift to endpoint-side telemetry (file creation without a corresponding network download) and to static/behavioral inspection of the HTML/JavaScript content itself.

#### Step 2: Data Sources and Scope
- **Sources**: Email-gateway logs (attachment metadata and scan verdicts); endpoint browser-download and file-creation telemetry (EDR); network proxy logs (to confirm absence of a corresponding file download).
- **Scope**: ~2022-12-14T10:15:00-10:24:00 UTC; Recipient: `t.nguyen@corp.example.com`; Attachment: `Invoice_44921.html`.
- **SIEM Queries** (Splunk/ELK):
  - `index=email_gateway attachment_ext="html" | search subject="*invoice*" OR subject="*statement*"`
  - Smuggling-pattern static check: `| rex field=attachment_content "(Blob\(|msSaveOrOpenBlob|atob\()" | where match_count > 2`
  - File-creation-without-download correlation: `index=edr event=file_create ext IN ("iso","js","hta") host="WKS-FIN-023"` compared against `index=proxy` for a matching download event (expect none).

#### Step 3: Key Findings
Parsed events (5 shown) confirm `t.nguyen` opened an HTML "invoice" attachment whose embedded JavaScript assembled and auto-saved a disguised ISO file, which was then mounted and executed, all without any corresponding network-level file transfer.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-14 10:15:03 | Email Gateway | Attachment Scan | `Invoice_44921.html`, scan verdict: clean (no executable content detected), SPF/DKIM: fail (sender domain mismatch) | **Delivery IOC**: the gateway only sees an HTML file with no embedded executable to flag, and the failed SPF/DKIM alignment is a red flag independently indicating a spoofed sender that should have been quarantined. |
| 2022-12-14 10:18:41 | WKS-FIN-023 | (Browser telemetry) | `Invoice_44921.html` opened in Chrome; JavaScript execution includes `atob()` decode of a ~14MB base64 string and `new Blob([...], {type:'application/octet-stream'})` | **Smuggling-Pattern IOC**: this is the canonical HTML-smuggling JavaScript construct - client-side base64 decoding into a Blob object to reconstruct a file that never existed on the wire. |
| 2022-12-14 10:18:44 | WKS-FIN-023 | (EDR file-creation event) | New file `Invoice_Statement.iso` (13.9 MB) written to `Downloads`, with **no corresponding network download event** in proxy logs | **No-Network-Transfer IOC**: a 13.9MB file appearing on disk with zero matching bytes transferred over the network confirms it was assembled entirely client-side from the smuggled base64 payload, bypassing all network-layer file inspection. |
| 2022-12-14 10:19:10 | WKS-FIN-023 | (EDR process event) | `explorer.exe` auto-mounted `Invoice_Statement.iso` as drive `E:`, then user double-clicked `Invoice_Statement.lnk` inside it | **Container-Evasion IOC**: mounting the payload inside an ISO is an additional evasion layer, since Windows treats the ISO's contents as coming from a trusted local "CD drive" and Mark-of-the-Web (MOTW) propagation is frequently lost for files inside ISO containers. |
| 2022-12-14 10:19:12 | WKS-FIN-023 | (EDR process event) | `Invoice_Statement.lnk` executed `powershell.exe -windowstyle hidden -enc <b64>` | **Execution IOC**: the `.lnk` file's true payload is a hidden PowerShell downloader, confirming the ISO delivered a functional dropper rather than a legitimate document. |

**Validation**:
- **Timeline**: a spoofed-sender HTML attachment, client-side JavaScript payload reconstruction with zero corresponding network transfer, ISO-mounting evasion, and hidden PowerShell execution form a complete HTML-smuggling delivery-and-execution chain.
- **False Positives**: the sender fails SPF/DKIM alignment and the HTML structure does not match any known legitimate reporting-tool export template.
- **Correlation**: gateway-blind attachment delivery, smuggling-pattern JavaScript, file-creation-without-network-transfer, ISO MOTW evasion, and hidden PowerShell execution jointly confirm malicious HTML smuggling.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Isolate WKS-FIN-023, block the sender domain and any observed C2 infrastructure from the decoded PowerShell payload, search all mailboxes for the same attachment hash/subject pattern, and quarantine/remove any unopened copies.
- **Detection**: Sigma-style rule: `title: File Creation With No Corresponding Network Download` → `selection: edr_event="file_create" ext IN ("iso","img","js","hta") AND NOT proxy_download_match_within(60s)` → `condition: selection`. Supplement with a static-analysis rule scanning inbound HTML attachments for `Blob()`/`atob()`/`msSaveOrOpenBlob` patterns combined with large embedded base64 strings.
- **Pro Tip**: Configure the email gateway to detonate/sandbox HTML attachments (rendering them in an instrumented headless browser) rather than relying on static file-type scanning alone - since the malicious content only manifests after JavaScript execution, behavioral detonation is the only gateway-level control capable of seeing the smuggled payload before it reaches the end user.

Hypothesis **confirmed**-a spoofed-sender phishing email delivered an HTML attachment whose embedded JavaScript smuggled a 13.9MB ISO payload past the email gateway entirely, which was then mounted and used to launch a hidden PowerShell downloader!
