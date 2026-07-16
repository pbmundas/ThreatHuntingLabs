---
layout: default
title: Hunting Exercise - 116
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing AzureAD Conditional Access Bypass Legacy Authentication Dataset

This hunt uses a simulated Azure AD sign-in log dataset (`aad_legacy_auth_bypass_2022-12-10T081500.json`) capturing **T1078.004: Valid Accounts: Cloud Accounts**, where an attacker with stolen credentials authenticates via a legacy authentication protocol (IMAP, POP3, SMTP AUTH, or older Exchange ActiveSync) that does not support modern authentication, thereby bypassing Conditional Access policies requiring MFA that only apply to modern-auth sign-ins.

#### Step 1: Hypothesis Formation
**Hypothesis**: A successful sign-in event for a user account occurs via a legacy authentication protocol (`clientAppUsed` = "IMAP4", "POP3", "Authenticated SMTP", "Exchange ActiveSync") from a source location/IP inconsistent with the user's normal geography, and no MFA challenge is present in the sign-in log, indicating an attacker is deliberately using legacy protocols to bypass Conditional Access MFA enforcement. Indicators:
- Sign-in log `clientAppUsed` field indicates a legacy/basic-authentication protocol rather than modern authentication (OAuth2/browser).
- `authenticationRequirement` field shows "singleFactorAuthentication" despite the user being covered by an MFA-requiring Conditional Access policy for modern-auth sign-ins.
- Source IP/geolocation is atypical for the user (different country, ASN, or a known VPN/proxy exit node) compared to their 30-day baseline.
- The sign-in is immediately followed by mailbox rule creation, mail search, or bulk mail access consistent with post-compromise mailbox abuse.

**Null Hypothesis**: The user is legitimately using an older mail client or a service account intentionally configured for legacy protocol access (e.g., a scanner/printer relay using SMTP AUTH) as a documented exception. Invalidate by checking the account against the legacy-auth exception inventory and confirming the source IP is a known, registered device/service location.

**Rationale**: Conditional Access policies that require MFA are commonly scoped to modern authentication flows; legacy protocols authenticate via a single username/password exchange with no interactive MFA prompt, so an account compromised via credential stuffing or phishing can be accessed with total MFA bypass as long as legacy authentication remains enabled for that user or tenant.

#### Step 2: Data Sources and Scope
- **Sources**: Azure AD Sign-in Logs (Interactive and Non-Interactive); Conditional Access policy report-only/enforcement logs; Exchange Online mailbox-audit logs; user geolocation/IP baseline.
- **Scope**: ~2022-12-10T08:15:00-08:40:00 UTC; Account: `r.patel@corp.example.com`; Source IP: 103.216.220.14 (unrecognized ASN, geolocated outside baseline country).
- **SIEM Queries** (Splunk/ELK, KQL for Sentinel):
  - `SigninLogs | where ClientAppUsed in ("IMAP4","POP3","Authenticated SMTP","Exchange ActiveSync") and ResultType == 0`
  - MFA-bypass confirmation: `| where AuthenticationRequirement == "singleFactorAuthentication" and UserPrincipalName in (mfa_required_users)`
  - Post-compromise mailbox check: `OfficeActivity | where Operation in ("New-InboxRule","Set-Mailbox") and UserId == "r.patel@corp.example.com" | where TimeGenerated > sign_in_time`

#### Step 3: Key Findings
Parsed events (5 shown) confirm `r.patel` authenticated via legacy IMAP4 from an unrecognized foreign IP with no MFA challenge, followed by creation of a hidden mailbox forwarding rule within 15 minutes.

| Timestamp (UTC) | Host | Event | Detail | IOC/Why Suspicious? |
|-----------------|------|-------|--------|----------------------|
| 2022-12-10 08:15:22 | AzureAD | Sign-in Log | `ClientAppUsed=IMAP4`, `ResultType=0` (success), `AuthenticationRequirement=singleFactorAuthentication`, source `103.216.220.14` | **MFA-Bypass IOC**: this account is covered by a Conditional Access policy requiring MFA, yet the legacy IMAP4 protocol allowed a single-factor successful authentication, confirming the CA policy gap for legacy auth. |
| 2022-12-10 08:15:22 | AzureAD | Sign-in Log (geolocation) | Source geolocated to a country the user has never signed in from in the prior 90 days; ASN flagged as a known VPN-exit provider | **Location-Anomaly IOC**: this represents a significant deviation from the user's established sign-in baseline, consistent with an attacker using stolen credentials from a remote location. |
| 2022-12-10 08:16:05 | AzureAD | Sign-in Log | Second and third IMAP4 sign-ins from the same source IP within 45 seconds, consistent with automated mailbox-sync tooling (not a human reading email interactively) | **Automation IOC**: rapid, repeated protocol-level authentication is typical of scripted mailbox access/exfiltration tools rather than a person checking email via a client. |
| 2022-12-10 08:29:51 | Exchange Online | Audit Log (`New-InboxRule`) | Rule `"..."` created forwarding all mail matching finance-related keywords to an external address, then marking as read and moving to RSS Subscriptions folder | **Post-Compromise IOC**: a hidden, keyword-targeted forwarding rule immediately following a legacy-auth sign-in is a well-established BEC/mailbox-takeover pattern (see also Report 2025-08-23 for full O365 rule-abuse detail). |
| - | - | (Legacy-auth exception check) | `r.patel` has no entry in the documented legacy-authentication exception list | Confirms this account has no legitimate business need for IMAP/POP/legacy protocol access. |

**Validation**:
- **Timeline**: an out-of-baseline-geography, single-factor legacy IMAP4 sign-in, followed by automated rapid re-authentication and a hidden keyword-targeted forwarding rule - a complete credential-compromise-and-mailbox-abuse chain enabled entirely by legacy auth's MFA bypass.
- **False Positives**: no exception-list entry authorizes legacy protocol use for this account.
- **Correlation**: MFA-bypassing sign-in method, geographic/ASN anomaly, automated re-authentication cadence, and immediate malicious mailbox-rule creation jointly confirm account takeover via legacy authentication.

#### Step 4: Recommendations & Next Steps
- **Immediate Response**: Disable legacy authentication for `r.patel@corp.example.com` immediately, revoke all active sessions/refresh tokens, force a password reset with mandatory MFA re-registration, remove the malicious inbox rule, and notify finance stakeholders of potential BEC exposure.
- **Detection**: Sigma/KQL-style rule: `title: Successful Legacy-Auth Sign-in for MFA-Required Account` → `selection: ClientAppUsed IN (legacy_protocols) AND ResultType=0 AND AuthenticationRequirement="singleFactorAuthentication" AND UserPrincipalName IN (mfa_enforced_users)` → `condition: selection`.
- **Pro Tip**: Disable legacy authentication protocols tenant-wide (via Conditional Access "Block Legacy Authentication" policy or Azure AD Security Defaults) rather than relying on per-account exceptions - legacy auth is the single most common Conditional Access/MFA bypass vector in cloud-identity compromises, and Microsoft has deprecated Basic Auth for Exchange Online specifically because of this exposure.

Hypothesis **confirmed**-an attacker used stolen credentials to authenticate via legacy IMAP4 from an unrecognized foreign location, completely bypassing the account's Conditional Access MFA requirement, then established a hidden mailbox forwarding rule targeting finance-related emails!
