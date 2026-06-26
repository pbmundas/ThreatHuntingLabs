## Detection Gap Hunting

One of the most valuable yet least discussed Threat Hunting methodologies is **Detection Gap Hunting**.

Unlike most hunting approaches that search for evidence of attackers, Detection Gap Hunting begins by questioning the organization's own security controls.

Instead of asking,

> **"Has an attacker compromised our environment?"**

Hunters ask,

> **"If an attacker used this technique today, would our security controls detect it?"**

This subtle shift in thinking makes Detection Gap Hunting one of the most effective methods for continuously improving a Security Operations Center (SOC).

Imagine your organization recently implemented Microsoft Sentinel and Microsoft Defender XDR.

Hundreds of analytics rules are active.

Thousands of alerts are generated every day.

Everything appears healthy.

But are there techniques that attackers could execute without generating a single alert?

Perhaps PowerShell encoded commands execute successfully.

Perhaps attackers abuse Remote Desktop Protocol (RDP) after business hours.

Maybe Windows Management Instrumentation (WMI) is used for lateral movement.

Or perhaps attackers create scheduled tasks without triggering any analytics.

These questions form the basis of Detection Gap Hunting.

Hunters deliberately simulate or investigate attacker techniques to determine whether existing detections are capable of identifying them.

If no alerts are generated, a detection gap has been discovered.

That discovery becomes an opportunity to improve the organization's visibility before attackers exploit the weakness.

**Advantages**

- Continuously improves security monitoring.
- Strengthens Detection Engineering.
- Reduces attacker dwell time.
- Identifies blind spots before attackers exploit them.

**Limitations**

- Requires mature detection engineering capabilities.
- Often involves collaboration between multiple security teams.

---

## Campaign-Driven Threat Hunting

Sometimes the objective isn't to investigate a single technique.

Instead, the goal is to determine whether a specific threat actor or campaign has targeted the organization.

This approach is known as **Campaign-Driven Threat Hunting**.

Rather than focusing on isolated Indicators of Compromise or individual behaviors, hunters investigate the complete attack lifecycle associated with a known adversary.

For example, suppose intelligence reports reveal that a ransomware group targeting the manufacturing sector typically follows this sequence:

1. Initial access through VPN credentials.
2. PowerShell reconnaissance.
3. Credential dumping.
4. Lateral movement using PsExec.
5. Data exfiltration.
6. Ransomware deployment.

Instead of searching for one indicator, hunters investigate whether **any part of the campaign** has already occurred.

Questions may include:

- Have VPN accounts authenticated from unusual locations?
- Has PowerShell recently executed encoded commands?
- Have administrative shares been accessed unexpectedly?
- Has PsExec appeared on systems where it normally doesn't execute?
- Have unusually large outbound transfers occurred?

Campaign Hunting focuses on identifying the broader operation rather than individual events.

This approach is particularly effective against Advanced Persistent Threats (APTs), ransomware groups, and financially motivated cybercriminal organizations that repeatedly follow similar attack patterns.

**Advantages**

- Provides a complete view of attacker activity.
- Excellent for tracking sophisticated adversaries.
- Aligns well with Threat Intelligence.

**Limitations**

- Requires high-quality intelligence.
- Can become time-consuming due to the volume of data involved.

---

## Comparing the Different Threat Hunting Methodologies

At first glance, many of these hunting approaches appear similar.

However, the difference lies in **what triggers the investigation**.

The objective remains the same.

The starting point changes.

| Hunting Method | Investigation Starts With | Best Used For |
|----------------|---------------------------|---------------|
| **Intelligence-Driven** | Threat Intelligence Reports | Emerging campaigns and known adversaries |
| **IOC-Driven** | Known Indicators of Compromise | Identifying known malware or infrastructure |
| **TTP-Driven** | MITRE ATT&CK Techniques | Detecting attacker behavior regardless of malware |
| **Behavior-Driven** | Unusual Activity | Discovering unknown attacks and Living-off-the-Land techniques |
| **Entity-Centric** | Specific User, Host, or Asset | Insider threats, executive protection, privileged accounts |
| **Situational** | Business Events | Mergers, cloud migrations, audits, Red Team exercises |
| **Vulnerability-Driven** | Newly Disclosed Vulnerabilities | Determining whether exploitation has already occurred |
| **Detection Gap** | Existing Security Controls | Improving detections and identifying blind spots |
| **Campaign-Driven** | Threat Actor Campaigns | Tracking advanced adversaries across the attack lifecycle |

Notice that every methodology ultimately leads to the same destination.

The hunter develops a hypothesis.

Collects evidence.

Analyzes observations.

Validates findings.

Improves the organization's security posture.

Only the trigger differs.

---

## Choosing the Right Hunting Strategy

One of the biggest misconceptions among newcomers is believing there is a "best" Threat Hunting methodology.

In reality, experienced Threat Hunters don't choose the methodology first.

They choose the methodology that best answers the question they're trying to investigate.

If Threat Intelligence reports a new ransomware campaign, Intelligence-Driven Hunting makes sense.

If unusual PowerShell activity appears across multiple systems, Behavior-Driven Hunting is more appropriate.

If a critical vulnerability has just been disclosed, Vulnerability-Driven Hunting becomes the logical choice.

If executives are travelling internationally during a merger, Entity-Centric Hunting may provide the greatest value.

The investigation always begins with the problem.

The methodology simply provides the most effective path toward answering it.

Mature Threat Hunting teams rarely rely on a single methodology.

Instead, they combine multiple approaches depending on the situation.

A hunt may begin with Threat Intelligence, transition into Behavior Analysis, and eventually uncover Detection Gaps that improve future monitoring.

Threat Hunting is flexible because attackers are flexible.

---

## Key Takeaways

Throughout this article, we explored the major Threat Hunting methodologies used by mature security teams.

We learned that:

- There is no universal starting point for a Threat Hunt.
- Different situations require different hunting methodologies.
- Structured Hunting begins with a clearly defined hypothesis.
- Intelligence, IOCs, TTPs, vulnerabilities, behaviors, entities, campaigns, and detection gaps can all initiate a Threat Hunt.
- Mature Threat Hunters often combine multiple methodologies during a single investigation.
- The methodology may change, but the investigative mindset remains the same.

The true objective of Threat Hunting isn't simply executing queries or reviewing logs.

It's selecting the right investigative approach to uncover threats that traditional security controls failed to detect.

---

## Looking Ahead

By now, we've answered several important questions.

- **Why** does Threat Hunting exist?
- **What** is Threat Hunting?
- **How** does a Threat Hunt progress?
- **Where** can a Threat Hunt begin?

The next logical question is perhaps the most practical one.

> **How do Threat Hunters actually analyze millions of security events without manually reviewing every log?**

The answer lies in a collection of analytical techniques that allow hunters to quickly identify suspicious patterns, anomalies, and attacker behavior hidden within enormous volumes of telemetry.

In the next article, we'll explore the **Threat Hunting Data Analysis Techniques** that experienced hunters use every day, including:

- Baselining
- Grouping
- Clustering
- Frequency Analysis
- Stack Counting (Repetition Counting)
- Rarity Scoring
- Outlier Detection
- Time Delta Analysis
- Entropy & String Analysis
- Parent-Child Process Analysis
- First-Time-Seen Analysis
- Peer Comparison
- Path & Location Anomalies
- Impossible Travel Detection
- Volume & Size Anomalies
- Sequence & Chain Analysis

These techniques form the analytical toolkit of every successful Threat Hunter and are what transform massive datasets into actionable intelligence.

