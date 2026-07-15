# Low-Hanging Fruits in Threat Hunting: Where to Start (and What Attackers Are Already Looking For)

If you've ever sat down to build a threat hunting program from scratch, you know the paralysis that comes with it. MITRE ATT&CK has 14 tactics and hundreds of techniques. Your environment has thousands of assets. Your SIEM has more log sources than your team has hours in the week. Where do you even begin?

Here's the secret every experienced hunter eventually learns: **you don't start with the exotic stuff.** You start where attackers start — the low-hanging fruit. The exposed RDP box nobody remembers standing up. The SMB share with anonymous access. The S3 bucket someone made public "just for testing" in 2021 and never locked back down. The domain admin whose Kerberos ticket has never been rotated.

Attackers are economically rational. They will always try the cheap, reliable win before they burn a zero-day. If you build your hunting program around the same economics, you catch the overwhelming majority of real-world intrusions — and you build the muscle memory and tooling that makes the harder hunts possible later.

This post is a practical field guide to identifying low-hanging fruit in your own environment and turning each one into an actual hunt — not just a checklist item, but a repeatable process with a hypothesis, a data source, a query, and a "what does abnormal actually look like" answer. It's written to be useful whether you're running your first hunt this week or you're a Tier 3 hunter looking for a refresher on the fundamentals before you build out your next dashboard pack.

---

## What Actually Makes Something "Low-Hanging Fruit"

Not everything common is low-hanging fruit, and not everything obscure is safe to ignore. The real definition combines four things:

1. **Prevalence** — the service or misconfiguration exists in nearly every environment (RDP, SMB, weak AD permissions, forgotten cloud storage).
2. **Exposure** — it's reachable without much effort, whether that's internet-facing, unauthenticated, or just poorly segmented internally.
3. **Known exploitation path** — there's a well-documented, often automated way to abuse it (a CVE, a default credential, a scanning tool, a public Metasploit module).
4. **Weak or absent monitoring** — nobody's watching it closely, so an attacker can dwell there for days or months.

When all four line up, you get the pattern behind almost every headline breach of the last three decades: WannaCry and NotPetya riding EternalBlue through unpatched SMB. Equifax falling to an unpatched Apache Struts endpoint. Mirai turning millions of IoT devices into a botnet using nothing more than default Telnet credentials. The Colonial Pipeline ransomware entering through a single leaked VPN password with no MFA. None of these needed a zero-day. They needed an attacker who looked for the door that was already unlocked.

That's the mindset threat hunters need to adopt: **hunt where the door is unlocked, not where the wall is thickest.**

---

## The Attacker's Economics (and Why This Matters to You)

Every attacker — from a script kiddie running masscan against a /8 to a nation-state operator doing initial access broker work — is making a cost-benefit calculation. Low-hanging fruit wins because:

- **Automation scales it.** Shodan and Censys index exposed services continuously. A scanner doesn't need to "target" your organization; it just needs your IP range to show up in a sweep of port 3389 or 445.
- **Credential reuse is everywhere.** Password spray and credential stuffing tools don't care what your environment looks like — they just need one exposed authentication endpoint and a leaked credential list.
- **Patch lag is nearly universal.** Even mature organizations run 30–90 day patch cycles for non-critical systems, which is more than enough window for a public exploit to land and get weaponized.
- **Misconfiguration doesn't require a vulnerability at all.** A publicly readable S3 bucket, an LDAP server accepting anonymous binds, or a default "public"/"private" SNMP community string isn't a bug — it's a decision someone made and forgot about.

If you flip this around, it becomes your hunting prioritization model. **Hunt first where automation, credential reuse, patch lag, and misconfiguration intersect with your actual exposed attack surface.** That intersection is almost always smaller than people expect — and far more tractable than "hunt for APT29" as a starting brief.

---

## A Threat Hunter's Workflow for Low-Hanging Fruit

Before diving into the categories, here's the repeatable process worth applying to every item below:

1. **Inventory** — Do you actually know this asset/service exists and where? (Attack surface management tools, CMDB, or even a good old `nmap` sweep of your own ranges help here.)
2. **Exposure check** — Is it reachable from the internet, from a flat internal network, from a guest VLAN? Exposure changes the hunting priority dramatically.
3. **Hypothesis** — State the specific abuse pattern you're hunting for, in one sentence. ("An attacker is brute-forcing our exposed RDP with a common credential list.")
4. **Data source mapping** — Which logs actually let you test that hypothesis? (Windows Security Event Logs, firewall/NetFlow, Duo/MFA logs, cloud audit trails, etc.)
5. **Baseline vs. anomaly** — What does normal look like for this asset, and what specific deviation would confirm the hypothesis?
6. **Hunt and validate** — Run the query, triage hits, confirm true/false positive.
7. **Close the loop** — If it's a true positive, escalate. Either way, feed what you learned back into detection engineering so it becomes a standing alert instead of a one-off hunt.

Keep that loop in your head as you read the categories below — every one of them is meant to be run through exactly this process.

---

## Category 1: Exposed Remote Access Services

This is the single most productive place to start a low-hanging-fruit hunting program, because it's where the highest volume of real-world intrusions actually begin.

**The usual suspects:**

- **RDP (port 3389, T1021.001)** — still the number one initial access vector for ransomware crews. Weak or reused passwords, no MFA, and internet exposure make it a near-guaranteed win for anyone running a scan. BlueKeep (2019) and countless WannaCry-adjacent campaigns rode this door in.
- **SSH (port 22, T1021.004)** — brute-forced constantly by botnets (Mirai's SSH-scanning descendants never stopped). Weak keys, password auth left enabled, and root login permitted are the classic misconfigurations.
- **Telnet (port 23, T1021.001)** — should be extinct, isn't. Still found on network gear and IoT devices with default credentials, and it's the backbone of the entire Mirai botnet story.
- **VPN gateways (Cisco ASA/AnyConnect, Pulse Secure, Fortinet FortiGate, Palo Alto GlobalProtect, Citrix ADC)** — a steady stream of high-severity CVEs (Pulse Secure 2021, Fortinet SSL-VPN RCE 2022) plus the simple fact that VPN is often the *one* control standing between the internet and your internal network. Colonial Pipeline's 2021 ransomware entry point was a VPN account with a reused password and no MFA — nothing exotic at all.
- **WinRM (port 5985/5986, T1021.006)** — frequently overlooked because it's "just for admins," which is exactly why an attacker who compromises one admin credential can move laterally through it undetected.

**Hunting hypothesis:** *"An external or internal actor is attempting authentication against an exposed remote-access service using automated or credential-stuffing techniques, or has already succeeded and is behaving anomalously."*

**Data sources:** Firewall/perimeter logs (allowed/denied connections to 3389/22/23/443-VPN), Windows Security Event Log (4624/4625 for RDP and WinRM), VPN concentrator authentication logs, MFA provider logs (Duo, Okta, etc. — see our companion Duo dashboard series for a deep dive here).

**What to actually hunt for:**

- High-volume failed logon attempts (Event ID 4625) against a single account or against many accounts from a single source — the spray vs. brute-force distinction matters (see our Duo password-spray dashboard writeup for the exact table pattern).
- Successful RDP/SSH logons from IP ranges or countries with no legitimate business reason to connect.
- WinRM/PowerShell remoting sessions initiated from a workstation that has never previously used them (a hallmark of lateral movement, not routine admin work).
- VPN logins without a corresponding MFA push/approval event — a strong indicator of either MFA misconfiguration or a bypassed control.

**Example hunting query logic (Windows Security Event Log, pseudocode you can adapt to your SIEM's query language):**

```
EventID = 4625
| stats count by TargetUserName, IpAddress, bin(time, 5m)
| where count > 5
```

```
EventID = 4624 AND LogonType = 10   // RemoteInteractive (RDP)
| where SourceNetworkAddress NOT IN (known_corporate_ranges)
```

**Expected/normal:** RDP and SSH access limited to a small, known set of jump hosts or admin workstations, all internal, all corresponding to a change ticket or known maintenance window.

**Abnormal:** Any successful authentication to these services directly from the public internet without going through a bastion/jump host, or any spike in failure volume that doesn't correlate with a known password-policy rollout.

**Quick win:** If you find any of these services directly exposed to the internet without MFA, that's not really a hunt anymore — that's an immediate hardening action. Fix it, *then* go back and hunt your logs for the window it was exposed to see if anyone already found it.

---

## Category 2: File Sharing and Legacy Protocols

**The usual suspects:** SMB (port 445, T1210), FTP (port 21, T1105), NFS, and anything still running Telnet-era plaintext authentication.

SMB deserves special attention because it's the protocol behind two of the most destructive malware outbreaks in history — WannaCry and NotPetya, both riding the EternalBlue exploit through unpatched SMBv1. Even years later, SMBv1 shows up in environments that "definitely don't use it anymore" but never actually disabled it.

FTP is the internet's oldest low-hanging fruit — plaintext credentials, anonymous access frequently left enabled by accident, and file listings that hand an attacker a roadmap of what's worth stealing.

**Hunting hypothesis:** *"SMBv1 is still enabled somewhere in the environment, or anonymous/guest access to file shares is exposing sensitive data."*

**What to hunt for:**

- Any negotiated SMBv1 connection in your network traffic logs or via `Get-SmbConnection`/protocol-negotiation audit logs — SMBv1 usage today is itself the finding, not just a precursor to one.
- Anonymous or guest-account access to file shares (Event ID 4624 with LogonType 3 and AccountName = ANONYMOUS LOGON).
- Unusual lateral SMB traffic between workstations that normally never talk to each other directly — a strong lateral-movement/worm-propagation signal (this is exactly how NotPetya moved).
- FTP sessions authenticating with the literal username "anonymous," and any subsequent large outbound file transfer following such a session.

**Expected:** SMB traffic confined to client-to-file-server patterns; no workstation-to-workstation SMB traffic outside of specific IT tooling.

**Abnormal:** Workstation-to-workstation SMB (classic lateral movement precursor), any SMBv1 negotiation at all in a modern environment, anonymous FTP sessions followed by directory listings of sensitive shares.

---

## Category 3: Databases Directly Exposed to the Network

**The usual suspects:** MySQL (3306), MSSQL (1433), PostgreSQL (5432), MongoDB, Redis, Elasticsearch — all frequently found with default or weak credentials, and in the NoSQL world, sometimes with *no* authentication configured at all out of the box.

MongoDB's history is almost a genre unto itself: 2017 saw tens of thousands of exposed, unauthenticated MongoDB instances mass-ransomed by opportunistic actors who didn't even need to exploit anything — the databases were simply open to the internet with no password. Redis has a similar story, where its default configuration historically had no authentication and could be abused for remote code execution via its scripting/config commands.

**Hunting hypothesis:** *"A database service is reachable from outside its expected network segment, and/or is being accessed by an account or source that doesn't match normal application behavior."*

**What to hunt for:**

- Database connections originating from outside the application-tier subnet that's supposed to be the only thing talking to it.
- Authentication attempts using default account names (`sa`, `root`, `admin`) against MSSQL/MySQL.
- Unauthenticated connections succeeding at all against MongoDB/Redis/Elasticsearch (if this happens, you don't have a hunting finding, you have an incident).
- Large or unusual `SELECT`/export-style queries against sensitive tables outside of normal application query patterns — this is where DB audit logging, not just network logs, becomes essential.

**Quick win:** Run an internal Shodan-style scan (using something like `nmap` or your existing vulnerability scanner) against your own IP ranges for these ports. If they come back reachable from outside their expected segment, that's your first hunt target before you even open a log query.

---

## Category 4: Cloud Storage and IAM Misconfigurations

**The usual suspects:** AWS S3 buckets, Azure Blob Storage, Google Cloud Storage — all with a long, embarrassing history of "public by accident." Uber's 2017 breach and Capital One's 2019 breach both trace back to cloud storage/IAM misconfiguration rather than a sophisticated exploit chain.

This category is unique because it's rarely about a vulnerability at all — it's almost always a *decision*, made once, forgotten forever. Someone made a bucket public "temporarily" to share a file with a vendor. Someone attached an overly permissive IAM role to a Lambda function during a demo. Nobody ever went back and locked it down.

**Hunting hypothesis:** *"Cloud storage or IAM permissions have drifted from their intended, least-privilege state, and something outside the expected principal set is now able to read/write."*

**What to hunt for:**

- CloudTrail/Azure Activity Log/GCP Audit Log events showing bucket ACL or policy changes that grant `AllUsers`/`AllAuthenticatedUsers`/public-read.
- Access to storage objects from IP ranges or principals that fall outside your known corporate/service-account population.
- IAM role or policy changes that broaden permissions (`iam:AttachRolePolicy`, `PutBucketPolicy`) outside of a documented change window — this is the cloud equivalent of the Configuration Drift hunting we covered in the Duo dashboard series, and the same "who changed what, was it ticketed" workflow applies directly.
- New access keys created for service accounts that haven't rotated keys in the recorded history of the account — often a sign either of legitimate automation setup or of persistence being planted.

**Expected:** Storage buckets accessed exclusively by known application roles/service accounts, from known VPC/region ranges.

**Abnormal:** Any public-read/public-write grant on a bucket that should never have one; access from an unfamiliar geographic region or an unrecognized AWS/Azure account ID (cross-account access is a classic supply-chain/third-party-compromise indicator).

---

## Category 5: Web Applications and Outdated Frameworks

**The usual suspects:** Apache/IIS/Nginx (T1190) running outdated CMS or framework versions, Apache Struts (Equifax, 2017), Log4j/Log4Shell (2021, arguably the single largest "low-hanging fruit" event in internet history because of how trivially exploitable and how universally deployed the vulnerable library was), Microsoft Exchange ProxyLogon (2021), Spring4Shell (2022).

What makes this category so persistently fruitful for attackers is the **patch lag problem** combined with **dependency sprawl** — most organizations don't actually know every place a vulnerable library like Log4j is embedded, because it's three dependencies deep in a vendor product they didn't build themselves.

**Hunting hypothesis:** *"A public-facing web application or one of its dependencies has a known, actively exploited vulnerability, and exploitation attempts or successful compromise indicators are present in web/application logs."*

**What to hunt for:**

- Web server access logs showing exploit-signature request patterns (e.g., `${jndi:ldap://` strings for Log4Shell, unusual `.jsp`/`.aspx` file drops for webshell activity following a framework RCE).
- Outbound connections from a web/application server to unfamiliar external IPs immediately following a suspicious inbound request — this "inbound exploit, outbound callback" pattern is one of the highest-confidence signals available in web-tier hunting.
- New files written to web-accessible directories outside of your normal deployment pipeline (a classic webshell-drop indicator).
- Process trees where a web server process (`w3wp.exe`, `httpd`, `java`) spawns a command shell (`cmd.exe`, `powershell.exe`, `/bin/sh`) — legitimate web applications almost never do this, so it's an extremely high-signal EDR/Sysmon hunting query.

**Example Sysmon-based hunting logic:**

```
EventID = 1 (ProcessCreate)
ParentImage ends with ("w3wp.exe", "httpd", "tomcat*", "java.exe")
Image ends with ("cmd.exe", "powershell.exe", "sh", "bash")
```

This single pattern has caught more post-exploitation activity across more unrelated CVEs (Struts, Log4Shell, ProxyLogon, Spring4Shell) than almost any CVE-specific signature, because it hunts the *behavior* every web-RCE exploit eventually needs, not the specific payload.

---

## Category 6: Active Directory and Identity Weak Points

If web-facing services are where attackers get *in*, Active Directory is where they get *everywhere*. This is arguably the richest low-hanging-fruit category for internal threat hunting, because AD's own design includes several features that are trivially abusable once an attacker has any foothold at all.

**The usual suspects:**

- **Kerberoasting (T1558.003)** — any authenticated domain user can request a service ticket for any account with a Service Principal Name (SPN) set, then crack it offline. If your service accounts have weak passwords (and they usually do, because "the password hasn't changed since 2014" is a shockingly common finding), this is a near-instant path to a privileged account.
- **AS-REP Roasting (T1558.004)** — accounts with Kerberos pre-authentication disabled can have their hashes requested and cracked offline without any authentication at all.
- **LDAP anonymous binds (T1087.002)** — still found in the wild, handing out full directory structure, usernames, and sometimes group membership to anyone who asks.
- **Golden/Silver Ticket abuse (T1558)** — post-compromise persistence that's "easy" specifically because most environments never rotate the krbtgt account password and don't monitor for anomalous ticket lifetimes.
- **Zerologon (2020) and PrintNightmare (2021)** — both turned "any domain-joined machine" into "domain admin" with minimal effort, and both remain relevant because patch adoption for AD-adjacent vulnerabilities lags behind almost every other category.

**Hunting hypothesis:** *"An account is requesting an abnormal volume or pattern of Kerberos service tickets consistent with Kerberoasting, or authenticating in a pattern consistent with Golden/Silver Ticket abuse."*

**Data sources:** Domain Controller Security Event Logs (4769 for TGS requests, 4768 for TGT requests, 4624/4625), LDAP query logs if available.

**What to hunt for:**

- Event ID 4769 (Kerberos service ticket request) with encryption type RC4 (0x17) — modern Windows environments should be using AES, so RC4 requests are frequently a Kerberoasting tool's fingerprint (tools like Rubeus/Impacket often default to or explicitly request RC4 because it's what's crackable offline).
- A single account requesting service tickets for an unusually high number of distinct SPNs in a short window — normal application behavior requests tickets for the services it actually uses, not a broad sweep.
- Event ID 4768 requests with pre-authentication disabled (AS-REP roasting indicator) for accounts that shouldn't have that flag set.
- TGT lifetimes or logon session patterns inconsistent with the domain's configured Kerberos ticket lifetime — a classic Golden Ticket tell, since forged tickets often don't match the environment's actual policy.

**Example hunting logic:**

```
EventID = 4769
TicketEncryptionType = 0x17
| stats dc(ServiceName) as distinct_spns by SubjectUserName, bin(time, 15m)
| where distinct_spns > 5
```

**Expected:** Service ticket requests concentrated around known application/service accounts, consistent daily volume, AES encryption for modern domain functional levels.

**Abnormal:** Burst requests for many SPNs from a single non-service user account, RC4 tickets in an AES-capable domain, AS-REP requests for accounts that were never meant to allow it.

**Related low-hanging fruit worth a dedicated pass:** LSA/SAM credential dumping (T1003.001/.002) via Mimikatz-style tooling, Group Policy Object abuse for lateral deployment of malicious scripts, and default/weak local administrator passwords reused across the fleet (LAPS deployment status is worth checking as part of this hunt, not just logs).

---

## Category 7: Living-off-the-Land and Persistence Basics

Not every low-hanging fruit is a *service* — some of it is the built-in Windows tooling that every environment already has, and that most SOCs still don't monitor closely enough.

**The usual suspects:** PowerShell (T1059.001) with default execution policy misconfigurations, WMI (T1047) for remote execution and persistence, scheduled tasks (T1053.005), Windows services (T1543.003), Run/RunOnce registry keys (T1547.001), and logon scripts (T1037.001).

None of these require an exploit. They're documented, supported, legitimate Windows features — which is exactly why they're so effective for attackers and so easy for defenders to overlook. NotPetya used WMI and PsExec for lateral movement rather than a novel technique. Olympic Destroyer used scheduled tasks for persistence. Zerologon-adjacent intrusions frequently finish with a scheduled task or service creation to survive reboot.

**Hunting hypothesis:** *"A persistence mechanism (scheduled task, service, registry Run key, WMI event subscription) has been created outside of normal software deployment/patch management processes."*

**What to hunt for:**

- Event ID 4698 (scheduled task created) where the task's action launches PowerShell, `cmd.exe`, `rundll32.exe`, or a binary from a user-writable directory like `%TEMP%` or `%APPDATA%`.
- Event ID 7045 (new service installed) outside of a known software deployment window, especially services with randomly generated or suspicious-sounding names.
- New or modified Run/RunOnce registry values pointing to non-standard executable locations.
- WMI event subscriptions (`__EventFilter`, `__EventConsumer`) — a technique with very little legitimate day-to-day usage in most environments, making any occurrence worth a look.
- PowerShell script block logging (Event ID 4104) containing obfuscation indicators — excessive string concatenation, `-EncodedCommand`, `IEX`/`Invoke-Expression` chains.

**Expected:** Scheduled tasks and services created only through your software deployment tooling (SCCM, Intune, Ansible, etc.), with predictable naming conventions and signed binaries.

**Abnormal:** Tasks/services referencing scripting interpreters directly, unsigned binaries in temp directories, or any WMI persistence artifact at all in an environment that doesn't use WMI subscriptions for legitimate purposes.

---

## Category 8: Email, Collaboration, and OAuth Abuse

**The usual suspects:** Office 365/Exchange (T1114.003, T1566.001), Microsoft Word/Excel macros (T1203), OAuth token leakage (T1528), Teams/Slack external link abuse.

This category is low-hanging fruit not because the technology is old, but because it's where humans are the exploited surface rather than a piece of software. Emotet, one of the most prolific malware families of the last decade, spread almost entirely through malicious Office macros in phishing attachments — no novel exploit required, just a document and a "Enable Content" click.

**Hunting hypothesis:** *"A user has interacted with a malicious macro-enabled document or granted OAuth consent to an illegitimate application, and post-compromise activity is observable in mail/identity logs."*

**What to hunt for:**

- Office documents spawning child processes (`WINWORD.EXE`/`EXCEL.EXE` → `powershell.exe`/`cmd.exe`/`mshta.exe`) — one of the highest-confidence, lowest-noise detections available for macro-based initial access.
- New OAuth application consent grants with broad scopes (mail read/send, files read/write) shortly after a phishing-adjacent event, or granted by an account with no history of installing third-party apps.
- Inbox rule creation (forwarding, auto-delete) immediately following a successful but otherwise anomalous login — a classic business email compromise (BEC) persistence tactic worth its own dedicated hunt.
- External sharing link creation in SharePoint/OneDrive for sensitive document libraries, from accounts that don't normally share externally.

**Expected:** Office documents used for document editing, no child-process spawning; OAuth consents limited to IT-approved application catalog.

**Abnormal:** Any Office-app-to-shell process chain; OAuth grants to unfamiliar app names/publishers; inbox forwarding rules created outside of a documented mailbox-delegation change.

---

## Category 9: IoT, OT, and Default Credentials

**The usual suspects:** Network printers (T1539, PrintNightmare 2021), IP cameras and DVRs (the backbone of the original Mirai botnet), SNMP with default "public"/"private" community strings, SCADA/ICS protocols like Modbus and DNP3 with no built-in authentication at all.

The common thread here is **default credentials that were never changed**, on devices that were never really designed with internet exposure in mind. Mirai's 2016 rampage is the canonical example: it didn't exploit a vulnerability, it just tried a list of about 60 default username/password combinations against exposed Telnet services and compromised millions of devices.

**Hunting hypothesis:** *"IoT/OT/network devices are reachable with default or weak credentials, or are exhibiting traffic patterns inconsistent with their function (e.g., a printer making outbound internet connections)."*

**What to hunt for:**

- Outbound connections from device classes that should never initiate outbound internet traffic (printers, cameras, PLCs, HMIs) — this single behavioral rule catches an enormous share of IoT botnet activity regardless of the specific malware family.
- SNMP queries succeeding with default community strings during an authorized internal scan.
- Authentication logs (where available) on network gear showing default account usage (`admin`/`admin`, `cisco`/`cisco`).
- Any Modbus/DNP3 traffic originating from outside the expected OT network segment — in a properly segmented environment, this should be a zero-tolerance finding, not a statistical anomaly.

**Quick win:** An asset inventory + default-credential sweep of your own IoT/OT fleet (done carefully, in coordination with OT engineering for safety-critical systems) will usually surface more real risk in an afternoon than weeks of log hunting on these device classes, precisely because the vulnerability *is* the missing password change.

---

## Worked Example: A Complete Low-Hanging-Fruit Hunt, Start to Finish

To make the workflow from earlier concrete, here's a full walkthrough on one of the highest-value hunts in this entire list: **Kerberoasting against service accounts.**

**1. Inventory** — Pull every account in AD with a Service Principal Name set (`Get-ADUser -Filter {ServicePrincipalName -ne "$null"}` or an LDAP query for `servicePrincipalName=*`). You'll almost always find more than you expect, including several nobody can immediately explain.

**2. Exposure check** — Every one of these accounts is "exposed" in the sense that matters here: any authenticated domain user, including a standard employee account, can request a ticket for them. This is why Kerberoasting doesn't need a foothold escalation — a single phished user account is enough to start.

**3. Hypothesis** — "An attacker with a standard domain user credential is requesting Kerberos service tickets for multiple SPN accounts in a short window, aiming to crack weak service account passwords offline."

**4. Data source** — Domain Controller Security Event Logs, Event ID 4769.

**5. Baseline** — Spend a week observing normal 4769 volume per account. Legitimate service ticket requests cluster tightly around the actual application/service using that SPN, at a steady, low, predictable rate tied to that application's normal operation.

**6. Hunt** — Run the query from Category 6 above, looking for RC4-encrypted ticket requests and for single accounts requesting many distinct SPNs quickly. Pull the results into a table sorted by `distinct_spns` descending.

**7. Validate** — For any hit, check: Is this a known vulnerability scanner or pentest tool account (should be documented and excluded)? Does the requesting account's normal job function explain touching multiple services? If not, this becomes a Tier 2/3 escalation — check that account's other recent activity (logon locations, process execution if EDR is available) for corroborating compromise indicators.

**8. Close the loop** — Whether it's a true or false positive, two things should happen regardless: rotate the passwords on any weak service accounts you found (this is the actual fix, not just the detection), and turn the validated query into a standing correlation rule so this becomes continuous monitoring instead of a one-time hunt.

This same eight-step shape applies to every category above — swap in the relevant event IDs, thresholds, and baseline behavior, and you have a repeatable hunt template your whole team can use consistently.

---

## A Quick-Start Checklist for Beginners

If you're new to threat hunting and this is your first real program, don't try to build all nine categories at once. Here's a realistic four-week starting sequence:

- **Week 1:** Attack surface inventory. What's actually internet-facing? Run an external scan of your own IP ranges. You cannot hunt what you don't know exists.
- **Week 2:** Remote access and file-sharing hunts (Categories 1–2). Highest real-world impact, most straightforward log sources (firewall + Windows Security Event Log).
- **Week 3:** Cloud storage/IAM review (Category 4) and a Kerberoasting/AS-REP roasting pass (Category 6). Both are largely one-time "clean up what you find" exercises that pay for themselves immediately.
- **Week 4:** Living-off-the-land basics (Category 7) — get comfortable with Sysmon/EDR process-tree hunting, since this skill transfers to nearly every future hunt you'll ever run, regardless of the specific threat.

From there, layer in web application hunting (Category 5), email/OAuth (Category 8), and IoT/OT (Category 9) as your data source coverage matures.

## Where Professionals Should Push Further

If you've already got the basics covered, the next level isn't a new category — it's **depth and automation** within the categories above:

- Move from one-off hunts to **standing correlation rules** for every validated finding (this is exactly the dashboard-and-detection-engineering approach we walked through in our Cisco Duo Threat Hunting Dashboard series — the same "hunt it manually first, then operationalize it" philosophy applies here).
- Build **per-asset and per-user baselines** rather than relying on static global thresholds — a threshold that works for your finance team's Kerberos ticket volume will be wrong for your DevOps team's service accounts.
- Chain low-hanging-fruit findings together. A single Kerberoasting hit is interesting; a Kerberoasting hit from an account that also just had a new MFA device enrolled and logged in from a new country is an active incident.
- Establish a **recurring cadence** for the "one-time cleanup" items (public cloud storage sweeps, default credential audits, SPN account password rotation) — low-hanging fruit regrows. New S3 buckets get created, new service accounts get spun up, and last quarter's clean audit doesn't cover this quarter's sprawl.

---

## Why This Approach Works

The uncomfortable truth about threat hunting is that most real-world intrusions — the ones that actually make the news — don't involve some brilliant novel technique. They involve EternalBlue on unpatched SMB (WannaCry, NotPetya), an unpatched web framework (Equifax), a reused VPN password with no MFA (Colonial Pipeline), default IoT credentials (Mirai), or a misconfigured cloud bucket (Uber, Capital One). The common denominator across three decades of breach history isn't sophistication — it's **an unlocked door that nobody was watching.**

Building your threat hunting program around low-hanging fruit isn't a lesser form of hunting. It's the highest-leverage place to spend your first hours, because it's where attacker economics and your actual exposure overlap the most. Master this list, turn every finding into a standing detection, and you'll have built both the technical foundation and the team habits that make the harder, more advanced hunts possible down the road.

---

*This post is part of the ThreatHuntLabs.com knowledge base. If you found this useful, check out our companion deep-dive on building a full Cisco Duo Threat Hunting Dashboard pack for Kibana, which takes several of the identity-focused hunts above (impossible travel, Kerberos abuse patterns, MFA fatigue) and turns them into production dashboards with full detection logic.*
