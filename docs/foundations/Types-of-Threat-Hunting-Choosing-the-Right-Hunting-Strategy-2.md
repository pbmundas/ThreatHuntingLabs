## TTP-Driven Threat Hunting

Unlike IOC Hunting, which searches for known artifacts such as IP addresses or file hashes, **TTP-Driven Threat Hunting** focuses on **how attackers operate**.

TTP stands for **Tactics, Techniques, and Procedures**, a concept popularized by the MITRE ATT&CK framework.

Instead of asking:

> "Has this malicious IP address communicated with our network?"

Hunters ask:

> **"Are attackers exhibiting behaviors that resemble known adversary techniques?"**

This distinction is important.

An attacker can easily change an IP address, file hash, or malware filename.

Changing behavior is much harder.

For example, regardless of which malware family is used, attackers often need to:

- Discover the environment.
- Escalate privileges.
- Establish persistence.
- Move laterally.
- Access credentials.
- Exfiltrate data.

Those behaviors leave traces across different data sources.

Imagine an attacker attempting **Credential Dumping (MITRE ATT&CK T1003)**.

The malware itself may never have been seen before.

Its hash won't appear in any Threat Intelligence feed.

Yet the behavior remains similar.

Hunters may search for:

- LSASS memory access.
- Suspicious process creation.
- Unusual privilege escalation.
- Unsigned binaries accessing protected processes.
- Security tools being disabled.

Rather than detecting a specific malware family, TTP Hunting attempts to identify attacker behavior itself.

**Advantages**

- Effective against previously unseen malware.
- Works well against advanced persistent threats (APTs).
- Closely aligns with adversary behavior documented in MITRE ATT&CK.

**Limitations**

- Requires strong understanding of attacker techniques.
- Can generate false positives if normal administrative activity resembles attacker behavior.

---

## Behavior-Driven Threat Hunting

One of the most powerful forms of Threat Hunting begins with neither Threat Intelligence nor IOCs.

It begins with **behavior**.

Instead of asking,

> "Do we recognize this malware?"

Hunters ask,

> **"Does this activity make sense?"**

Imagine an employee who normally logs into two systems each day.

Today they authenticate to seventy-five servers.

No alerts fire.

The credentials are valid.

Authentication succeeds.

Everything appears legitimate.

Yet the behavior is highly unusual.

This is where Behavior-Driven Hunting begins.

Hunters focus on identifying activities that significantly deviate from established baselines.

Examples include:

- PowerShell executing thousands of times on a server.
- Microsoft Word spawning PowerShell.
- A workstation communicating with a domain for the first time.
- Service accounts authenticating interactively.
- Administrative tools executing outside business hours.
- Unexpected parent-child process relationships.
- Large-scale file access within a short period.
- Rare processes appearing on critical systems.

Notice something interesting.

None of these observations require known malware.

None require Threat Intelligence.

None require Indicators of Compromise.

They simply represent behavior that deserves investigation.

Behavior-Driven Hunting is particularly effective because sophisticated attackers increasingly rely on legitimate tools already present within operating systems.

Rather than dropping malware, they abuse PowerShell, Windows Management Instrumentation (WMI), PsExec, Remote Desktop Protocol (RDP), and many other trusted utilities.

Looking for behavior instead of malware significantly increases the chances of discovering previously unseen attacks.

**Advantages**

- Excellent for identifying unknown threats.
- Detects Living-off-the-Land attacks.
- Less dependent on external intelligence.

**Limitations**

- Requires mature baselines.
- May produce false positives in dynamic environments.

---

## Entity-Centric Threat Hunting

Sometimes the investigation doesn't begin with attacker behavior.

Instead, it begins with a specific entity.

An entity could be:

- A user.
- A privileged account.
- A workstation.
- A domain controller.
- An application.
- A Kubernetes cluster.
- An Azure subscription.
- An AWS account.
- A Microsoft 365 tenant.
- A service account.
- An IP address.
- A hostname.

Instead of searching the entire environment, hunters ask:

> **"Is this specific entity behaving normally?"**

Imagine the Chief Financial Officer is preparing for a merger.

Executives become attractive targets during mergers because compromising a single mailbox can expose confidential financial information.

Rather than hunting across every employee account, the security team focuses exclusively on executive identities.

Questions may include:

- Has this account authenticated from new locations?
- Has MFA recently been disabled?
- Have new OAuth applications been granted consent?
- Has mailbox forwarding been configured?
- Has the account recently accessed sensitive SharePoint sites?

By narrowing the scope to one entity, investigators can perform a much deeper analysis.

Entity-Centric Hunting is particularly useful during insider threat investigations, executive protection, privileged account monitoring, and cloud identity security.

**Advantages**

- Focused investigations.
- Easier correlation across multiple data sources.
- Highly effective for protecting high-value assets.

**Limitations**

- Limited scope.
- May overlook broader attacker activity elsewhere.

---

## Situational Threat Hunting

Not every Threat Hunt begins because of suspicious activity.

Sometimes the business itself creates the reason.

This is known as **Situational Threat Hunting**.

Certain events naturally increase organizational risk.

Examples include:

- A major acquisition or merger.
- Migration to Microsoft 365.
- Cloud transformation projects.
- Deployment of critical infrastructure.
- Public disclosure of sensitive information.
- Executive travel.
- Red Team exercises.
- Regulatory audits.
- Major software deployments.

Consider a newly disclosed critical vulnerability affecting Microsoft SharePoint.

Even before exploitation attempts are observed, hunters proactively investigate:

- Have vulnerable servers communicated with suspicious IP addresses?
- Are exploit attempts visible in IIS logs?
- Have suspicious web shells been created?
- Are unexpected PowerShell executions occurring after HTTP requests?

The hunt isn't triggered by alerts.

It's triggered by changing business conditions.

Situational Hunting helps organizations prepare before attackers exploit periods of increased risk.

**Advantages**

- Proactive risk reduction.
- Closely aligned with business priorities.
- Supports major organizational changes.

**Limitations**

- Requires strong communication between business and security teams.
- Often depends on accurate asset inventories.

---

## Vulnerability-Driven Threat Hunting

Every week, security vendors publish newly discovered vulnerabilities.

Most organizations immediately focus on patching.

Experienced Threat Hunters ask a different question.

> **"Were attackers already exploiting this vulnerability before we knew it existed?"**

This mindset forms the foundation of Vulnerability-Driven Hunting.

Suppose a critical remote code execution vulnerability receives a CVSS score of 10.0.

Even if patches are immediately applied, attackers may have already gained access days or weeks earlier.

Hunters therefore investigate historical activity.

Typical questions include:

- Were exploit attempts observed before the patch was applied?
- Which systems were exposed?
- Did suspicious child processes execute afterward?
- Were new administrator accounts created?
- Did outbound network connections increase following exploitation?

Rather than treating vulnerabilities purely as patch management issues, hunters investigate whether exploitation has already occurred.

**Advantages**

- Identifies historical compromises.
- Complements vulnerability management.
- Reduces attacker dwell time.

**Limitations**

- Requires high-quality historical telemetry.
- Older logs may no longer be available if retention periods are short.

[Continue to explore more types here](Types-of-Threat-Hunting-Choosing-the-Right-Hunting-Strategy-3.md)
