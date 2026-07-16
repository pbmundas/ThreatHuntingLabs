---
layout: default
title: Hunting Exercise - 102
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing IDS Web Shell Upload File Extension Signature Dataset

This hunt uses a simulated IDS/IPS and web-application-firewall dataset (`ids_webshell_upload_2022-11-12T163000.json`) capturing **T1505.003: Server Software Component: Web Shell**, where an attacker exploits an unrestricted file-upload vulnerability to place an executable web shell (disguised via double extension or content-type spoofing) on a public-facing web server.

#### Step 1: Hypothesis Formation
**Hypothesis**: A file-upload request to a public-facing web application uploads a file with a server-executable extension (`.php`, `.aspx`, `.jsp`) or a disguised double extension (`.jpg.php`), followed shortly by a direct HTTP GET/POST request to that same uploaded filename, indicating successful web shell placement and immediate first use. Indicators:
- IDS/WAF signature match on executable file extensions within a multipart file-upload request to an endpoint not designed for code upload (e.g., an image/avatar uploader).
- The uploaded filename is subsequently requested directly via HTTP, often within seconds to minutes of the upload.
- The follow-up request includes suspicious query parameters (e.g., `?cmd=`, `?c=`) consistent with web shell command execution.
- Server response to the follow-up request has an anomalous size/status compared to normal application responses.

**Null Hypothesis**: A developer or authorized administrator is legitimately deploying a server-side script component through an approved change-management/CI-CD process. Invalidate by checking the source IP against the deployment pipeline's known egress ranges and cross-referencing an approved change ticket.

**Rationale**: Because many web applications only validate file extensions or MIME type superficially (or not at all) on upload endpoints, correlating the upload event with an immediate direct-access request to the same path is the most reliable way to distinguish a web shell drop from a false-positive extension match on benign content.

#### Step 2: Data Sources and Scope
- **Sources**: WAF/IDS logs with file-upload inspection; web-server access logs; change-management ticket system.
- **Scope**: ~2022-11-12T16:30:00-16:38:00 UTC; Target: `www.corp-portal.example.com` (public-facing avatar-upload endpoint); Source: 91.223.45.19 (external).
- **SIEM Queries** (Splunk/ELK):
  - `index=waf uri="/avatar/upload" method=POST | regex file_name="\.(php|phtml|aspx|jsp)(\.[a-z]{3,4})?$"`
  - Follow-up access: `index=web_access uri_path="*shell_x91.php*" | table _time src_ip status bytes`
  - Change-ticket check: `| lookup change_tickets src_ip OUTPUT ticket_id | where isnull(ticket_id)`

#### Step 3: Key Findings
Parsed events (5 shown) confirm an external actor uploaded a disguised PHP web shell through an avatar-upload endpoint and executed a command via it within 90 seconds.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-11-12 16:30:11 | www.corp-portal | WAF (upload inspection) | POST `/avatar/upload`, filename `profile.jpg.php`, `Content-Type: image/jpeg` (spoofed) | **Double-Extension IOC**: the `.jpg.php` naming pattern is a well-known technique to bypass extension allow-lists that only check the string "jpg" is present, while the server still executes it as PHP. |
| 2022-11-12 16:30:12 | www.corp-portal | (Filesystem event) | New file created: `/var/www/uploads/avatars/profile.jpg.php`, 4.1 KB, permissions 644 | **Placement IOC**: the upload directory is web-accessible and the file was written with execute-eligible permissions for the web server user. |
| 2022-11-12 16:31:38 | www.corp-portal | Web Access Log | GET `/uploads/avatars/profile.jpg.php?c=whoami`, status 200, response 312 bytes | **Immediate-Use IOC**: a direct request to the just-uploaded file, carrying a `?c=` command parameter, occurred within 90 seconds - consistent with automated shell verification, not a normal image-rendering request. |
| 2022-11-12 16:31:38 | www.corp-portal | Web Access Log (response body sample) | Response body contains a single line matching a Linux command-output pattern (uid/gid string) rather than JPEG binary data | **Execution-Confirmation IOC**: an image URL returning plaintext command output confirms the file is executing as server-side code, not being served as an image. |
| - | - | (Change-ticket check) | No change-management ticket exists authorizing file changes to the avatar-upload path in this window | Confirms this was not an authorized deployment or maintenance activity. |

**Validation**:
- **Timeline**: a spoofed-MIME double-extension upload, immediate filesystem placement in a web-accessible directory, and a command-execution request within 90 seconds form a complete web-shell-deployment-and-use chain.
- **False Positives**: no corresponding change ticket or known deployment-pipeline source IP is associated with the request.
- **Correlation**: WAF upload signature, filesystem write, and immediate command-parameter follow-up request jointly confirm active web shell compromise.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Take the affected upload directory offline or set it non-executable immediately, quarantine `profile.jpg.php` for forensic analysis, review web-server access logs for all activity from 91.223.45.19, and audit the upload endpoint for the underlying validation flaw.
- **Detection**: Sigma-style rule: `title: Web Shell Upload and Immediate Execution` → `selection1: uri="/*/upload" filename REGEX "\.(php|jsp|aspx)(\..{2,4})?$"` AND `selection2: uri_path=<same filename> within 300s of selection1` → `condition: selection1 and selection2`.
- **Pro Tip**: Enforce upload validation via server-side content inspection (magic-byte/file-signature checking, not extension or `Content-Type` header trust) combined with storing uploads outside the web root or in a non-executable object store - this closes the double-extension and MIME-spoofing bypass class entirely, rather than relying on an ever-growing extension blocklist.

Hypothesis **confirmed**-an external actor exploited an avatar-upload endpoint to plant a disguised PHP web shell and confirmed remote command execution against it within 90 seconds of the upload!
