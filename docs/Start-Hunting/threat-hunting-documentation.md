# Threat Hunting Documentation: Hunt Logs, Reports, and Findings

Here's an uncomfortable truth about threat hunting: if you found something amazing but nobody else can understand what you found, it basically didn't happen. Documentation is where hunts actually become useful to the rest of the organization. Without it, all that time spent digging through logs just disappears into someone's memory and memories fade, people change roles, and knowledge walks out the door.

So let's talk about how to document hunts properly, in a way people will actually read and use.

## Why Documentation Gets Skipped (and Why That's a Problem)

Let's be honest writing things up is nobody's favorite part of hunting. The fun part is digging through data, spotting something weird, and chasing it down. Writing a report afterward feels like homework.

But here's the thing: a hunt without documentation can't be repeated, can't be handed off, can't be used as evidence, and can't help the next person who runs into something similar. If you don't write it down, you basically have to rediscover it every time.

Good documentation turns a one-time discovery into permanent organizational knowledge.

## The Hunt Log: Your Working Notes

Before you get to any polished report, there's the hunt log your raw, in-the-moment notes while you're actually hunting. Think of it like a lab notebook, not a final product.

A solid hunt log usually captures:

- **The hypothesis** what you were looking for and why (e.g., "checking for lateral movement using PsExec after the recent phishing campaign")
- **Date and time range covered** so anyone reading it later knows exactly what window was examined
- **Queries and commands run** the actual searches you used, so someone else can rerun them
- **What you found at each step** even the dead ends. Especially the dead ends, honestly, because they tell the next hunter what NOT to waste time on
- **Screenshots or data snippets** visual proof, not just your word for it
- **Your reasoning** why you pivoted from one lead to another

The hunt log doesn't need to be pretty. It needs to be complete and time-stamped. Think "detailed diary," not "final report."

## From Hunt Log to Actual Report

Once the hunt log exists, it needs to be turned into something other people can actually use. And here's a key idea: **different audiences need different reports from the same hunt.**

A CISO doesn't want your raw SPL queries. A SOC analyst doesn't want three paragraphs about business risk. So good hunting programs usually produce more than one version of the same findings.

### Executive Summary
This is short usually half a page to one page. No jargon, no query syntax, no acronym soup. It answers three questions:
1. What did we look for and why?
2. What did we find?
3. What's the business impact, and what needs to happen next?

Executives care about risk, cost, and decisions they need to make not technical mechanics.

### Technical Report
This is the detailed version for other analysts, SOC teams, or incident responders. It includes the actual queries, the IOCs, the timeline of activity, affected systems, and enough detail that someone could reproduce the hunt or take direct action from it (like writing a new detection rule).

Same hunt, same findings just written for a completely different reader.

## TLP: How to Mark Who Can See What

You'll often hear "TLP" thrown around in threat intel and hunting circles. TLP stands for **Traffic Light Protocol**, and it's basically a simple color-coded system for how far information is allowed to travel.

- **TLP:RED** for the eyes in the room only. Don't share this beyond the people it was directly given to.
- **TLP:AMBER** can be shared within your organization, and sometimes with partners who need it, but not publicly.
- **TLP:GREEN** can be shared within your community or industry, just not posted publicly on the internet.
- **TLP:CLEAR** (previously called TLP:WHITE) no real restrictions, safe for public release.

Every hunt report should carry a TLP label right at the top. It sounds like a small thing, but it prevents sensitive findings like details of an active compromise from accidentally ending up somewhere they shouldn't.

## Documenting IOCs Properly

IOCs (Indicators of Compromise) are often the most valuable output of a hunt the actual IPs, hashes, domains, or file names tied to malicious activity. But a list of IOCs with no context is nearly useless.

Good IOC documentation includes:

- **The indicator itself** (hash, IP, domain, etc.)
- **What type it is** (file hash, network indicator, registry key, etc.)
- **Where it was seen** (which system, which log source)
- **When it was seen** (timestamp)
- **Confidence level** are you certain this is malicious, or is it a "worth watching" indicator?
- **Context** what campaign or activity is this tied to?

Without that context, an IOC list is just... a list. With context, it becomes something a SOC can actually act on like building a detection rule or blocking traffic with confidence.

## Practical Exercise: Document the Day 8 Hunt, Three Ways

Let's make this real. Say you just wrapped up a hunt on Day 8 of your program, and here's roughly what happened:

*You hypothesized that an attacker might be using scheduled tasks for persistence, based on a threat intel report about a new campaign. You searched Windows Event Logs across 40 endpoints for suspicious `schtasks.exe` activity. You found 3 endpoints with a scheduled task disguised as a legitimate Windows update process, pointing to a suspicious PowerShell script that beacons out every 6 hours to an external IP.*

Now let's document that same hunt three different ways.

### 1. The Hunt Log (raw working notes)
```
Date: Day 8, 09:14–13:40
Hypothesis: Adversary using scheduled tasks for persistence (ref: TI report #2026-114)
Scope: 40 endpoints, Windows Event Log ID 4698 (task creation)

09:14 - Query: EventID=4698 across endpoint fleet, last 30 days
09:40 - 6 unusual task names found, cross-referenced against baseline
10:15 - 3 tasks named "WindowsUpdateHealthCheck" - not a real MS task name
10:22 - Task action points to powershell.exe -enc <base64>
10:35 - Decoded payload - beacons to 185.x.x.x every 6 hours
11:00 - Checked network logs, confirmed outbound traffic matches pattern
11:45 - Affected hosts: WKS-114, WKS-220, WKS-341
12:30 - No lateral movement observed from these hosts (checked auth logs)
13:40 - Hunt concluded, escalating to IR
```

### 2. Executive Summary
> **TLP:AMBER**
> **Subject: Persistence Mechanism Found on 3 Endpoints**
>
> During a proactive hunt this week, our team identified malicious software disguised as a Windows system process on three employee computers. This software was designed to maintain hidden access and was periodically contacting an external server, though no evidence of further spread was found.
>
> The affected machines have been isolated and are being cleaned up by our response team. We recommend approving a quick fleet-wide scan to confirm no other machines are affected. No customer data or critical systems were involved.

### 3. Technical Report
> **TLP:AMBER**
> **Hunt Report: Scheduled Task Persistence Day 8**
>
> **Hypothesis:** Based on TI report #2026-114, hunted for adversarial use of Windows scheduled tasks for persistence.
>
> **Scope:** 40 endpoints, Event ID 4698, 30-day lookback.
>
> **Findings:** 3 endpoints (WKS-114, WKS-220, WKS-341) had a scheduled task named `WindowsUpdateHealthCheck` not a legitimate Microsoft task. Task action executes a base64-encoded PowerShell payload that beacons to `185.x.x.x` every 6 hours.
>
> **IOCs:**
> | Indicator | Type | Confidence | First Seen |
> |---|---|---|---|
> | 185.x.x.x | C2 IP | High | Day 8, 10:35 |
> | WindowsUpdateHealthCheck | Scheduled task name | High | Day 8, 10:15 |
> | (hash of decoded payload) | File hash | High | Day 8, 10:35 |
>
> **Lateral movement:** None observed in authentication logs.
>
> **Recommended actions:** Block C2 IP at perimeter firewall. Deploy detection rule for task name pattern. Run fleet-wide scan for the same IOC set. Escalate to IR for endpoint remediation.

Notice how it's the exact same hunt, but each version serves a completely different reader. The exec summary takes 30 seconds to read and tells leadership what they need to know. The technical report gives another analyst everything they'd need to act on it immediately.

## The Bottom Line

Documentation isn't the boring afterthought of threat hunting it's what makes hunting actually valuable to an organization. A brilliant find that lives only in your head helps nobody. The same find written up clearly, with the right IOCs, the right TLP marking, and the right version for the right audience? That's what turns a good hunter into a good hunting *program*.

Write it down. Future-you (and everyone else on the team) will thank you and here is the link to [Threat Hunting Report template](../Downloads/threat-hunting-related-document-references.md).
