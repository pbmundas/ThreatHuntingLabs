
# Types of Threat Hunting: Choosing the Right Hunting Strategy

In the previous article, we explored the **Threat Hunting Lifecycle** and followed an investigation from developing a hypothesis to improving future detections.

One important realization emerged from that discussion.

Every successful Threat Hunt follows a structured investigative process.

But there is one question we haven't answered yet.

> **Where does a Threat Hunt actually begin?**

Does every hunt start with Threat Intelligence?

Should hunters always investigate suspicious users?

Can they simply search for anomalies across millions of events?

Or should they begin by validating whether existing detections have blind spots?

The answer is surprisingly simple.

**There is no single starting point.**

Unlike Incident Response, where investigations usually begin after a security alert is generated, Threat Hunting can begin from many different directions.

A newly disclosed vulnerability.

A suspicious authentication pattern.

An executive's account behaving unusually.

A ransomware campaign targeting your industry.

A newly published MITRE ATT&CK technique.

Even an analyst's curiosity.

Each of these situations can trigger a Threat Hunt.

What changes isn't the investigation itself.

What changes is **the reason for starting it.**

Understanding these different starting points is one of the most valuable skills a Threat Hunter can develop because selecting the right hunting strategy often determines how quickly hidden threats are discovered.

In this article, we'll explore the major Threat Hunting methodologies used by mature security teams, understand when each one should be used, and learn the advantages and limitations of each approach.

---

## Every Threat Hunt Starts with a Different Question

Imagine five different organizations.

Each has invested in modern security technologies.

Each has experienced security incidents in the past.

Each employs experienced SOC analysts.

Yet on the same Monday morning, every Threat Hunting team begins a completely different investigation.

**Organization A**

Their Threat Intelligence provider reports that a ransomware group has recently begun exploiting VPN appliances using a newly published technique.

The hunters immediately ask:

> **"Are we vulnerable to this campaign?"**

---

**Organization B**

A Detection Engineer notices an unusual increase in PowerShell executions across several domain controllers.

The question becomes:

> **"Is this administrative activity, or is someone attempting to execute malicious scripts?"**

---

**Organization C**

The CEO's Microsoft 365 account successfully authenticates from India.

Fifteen minutes later, another successful authentication occurs from Germany.

The hunt begins with a simple question.

> **"Has this account been compromised?"**

---

**Organization D**

A critical vulnerability affecting Microsoft SharePoint is publicly disclosed.

Before attackers begin exploiting it, hunters ask:

> **"Have attackers already attempted to exploit this vulnerability inside our environment?"**

---

**Organization E**

The security team wants to understand whether privileged service accounts are behaving normally.

There are no alerts.

No incidents.

No external intelligence.

Only curiosity.

The investigation begins with:

> **"What does normal privileged account behavior actually look like?"**

---

All five organizations are performing Threat Hunting.

All five are trying to identify threats that automated security controls may have missed.

Yet none of them begin from the same place.

That is why Threat Hunting isn't a single methodology.

It's a collection of investigative approaches that share the same objective but start from different triggers.

---

## Understanding the Different Types of Threat Hunting

Over the years, security vendors, researchers, and experienced hunting teams have introduced different ways to classify Threat Hunting.

Some classify hunts based on **the source of the hypothesis.**

Others classify them based on **the type of data being investigated.**

Some focus on **attacker behavior**, while others begin with **known Indicators of Compromise (IOCs)** or **Threat Intelligence**.

Although terminology varies across organizations, most Threat Hunting approaches can be grouped into two broad categories.

- **Structured Threat Hunting**
- **Unstructured Threat Hunting**

From these two categories emerge several specialized hunting methodologies that mature Threat Hunting teams regularly use.

These include:

- Intelligence-Driven Hunting
- IOC-Driven Hunting
- TTP-Driven Hunting
- Behavior-Driven Hunting
- Entity-Centric Hunting
- Situational Hunting
- Vulnerability-Driven Hunting
- Detection Gap Hunting
- Campaign Hunting

Before exploring each methodology individually, it's important to understand the difference between structured and unstructured hunting because almost every investigation belongs to one of these two families.

---

## Structured Threat Hunting

Structured Threat Hunting begins with a clearly defined hypothesis.

Instead of randomly exploring security data, hunters already know what they're looking for.

The objective is to either validate or disprove a specific assumption using available evidence.

Think of structured hunting as conducting a scientific experiment.

Every experiment begins with a question.

Every Threat Hunt should do the same.

For example:

- Could attackers be abusing Microsoft OAuth applications?
- Are domain controllers showing evidence of Kerberoasting?
- Has any endpoint executed known Living-off-the-Land Binaries (LOLBins)?
- Are attackers attempting Pass-the-Hash attacks against privileged accounts?

Each question defines the scope of the investigation.

The hunter identifies the required data sources, develops appropriate queries, validates observations, and determines whether the hypothesis is true.

Structured hunts are typically more focused, easier to measure, and highly repeatable.

Because they follow a defined objective, they are commonly used by mature Threat Hunting teams.

However, even within structured hunting, there are several different methodologies depending on what inspired the original hypothesis.

Let's explore the most common ones.

---

## Intelligence-Driven Threat Hunting

One of the most common structured hunting methodologies begins with Threat Intelligence.

Threat Intelligence continuously provides organizations with information about emerging malware, ransomware groups, attacker infrastructure, vulnerabilities, phishing campaigns, and evolving adversary techniques.

Instead of waiting for attackers to generate alerts, hunters proactively ask:

> **"Could these same techniques already be present inside our environment?"**

Imagine Microsoft publishes an advisory describing a ransomware campaign that abuses scheduled tasks for persistence.

Your organization hasn't generated any related alerts.

Does that guarantee you're safe?

Not necessarily.

An experienced Threat Hunter begins investigating before evidence of compromise becomes obvious.

Typical data sources for Intelligence-Driven Hunting include:

- Threat Intelligence reports
- Government advisories
- Vendor security bulletins
- ISAC intelligence sharing communities
- MITRE ATT&CK updates
- Malware research publications

The investigation then focuses on identifying whether observed attacker behaviors, infrastructure, or techniques already exist inside the organization's environment.

**Advantages**

- Proactively investigates emerging threats.
- Helps organizations prepare before attacks become widespread.
- Aligns hunting activities with current adversary behavior.

**Limitations**

- Highly dependent on the quality of Threat Intelligence.
- May overlook completely new attacker techniques that have not yet been documented.

---

## IOC-Driven Threat Hunting

Sometimes the objective isn't to understand attacker behavior.

Instead, hunters already possess known Indicators of Compromise (IOCs).

These may include:

- Malicious IP addresses
- Domains
- URLs
- File hashes
- Registry keys
- Email addresses
- Process names

The goal becomes straightforward.

> **"Do any of these indicators exist inside our environment?"**

Suppose Threat Intelligence identifies a phishing campaign distributing malware from several known domains.

Rather than waiting for alerts, hunters search DNS logs, proxy logs, firewall logs, and endpoint telemetry to determine whether any systems have already communicated with those domains.

IOC Hunting is usually one of the fastest hunting methodologies because the search criteria are already known.

However, this simplicity also creates its biggest weakness.

Attackers can easily change IP addresses.

Domains can be replaced within minutes.

Malware hashes change with every recompilation.

As a result, IOC Hunting is excellent for identifying known compromises but far less effective against sophisticated attackers using previously unseen infrastructure.

Experienced Threat Hunters rarely rely on IOC Hunting alone.

Instead, they combine it with behavioral analysis to identify attacker activity that cannot be detected using static indicators. [Continue to explore more types here](Types-of-Threat-Hunting-Choosing-the-Right-Hunting-Strategy-2.md)

