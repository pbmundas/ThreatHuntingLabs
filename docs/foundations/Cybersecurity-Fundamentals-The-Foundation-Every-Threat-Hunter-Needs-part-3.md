# Security Controls, Telemetry and Logs: Where Threat Hunting Begins

[*Threat Hunting Foundations – Part 1*](Cybersecurity-Fundamentals-The-Foundation-Every-Threat-Hunter-Needs-part-1.md)       
[*Thinking Like a Threat Hunter - Part 2*](Cybersecurity-Fundamentals-The-Foundation-Every-Threat-Hunter-Needs-part-2.md)

In the previous parts of this article, we explored cyber threats, common attack techniques, threat actors, investigation methodology, and the cybersecurity frameworks that help defenders understand attacker behavior.

Now we'll answer one of the most important questions every aspiring Threat Hunter should ask:

> **Where does the evidence come from?**

Every action performed by an attacker leaves traces behind.

A successful login generates an authentication event.

A malicious PowerShell command creates a process.

A downloaded payload generates network traffic.

A compromised endpoint communicates with external infrastructure.

An attacker establishing persistence modifies the operating system.

None of these actions happen silently.

Modern operating systems, network devices, cloud platforms, and security products continuously generate telemetry describing what is happening within the environment.

Threat Hunters don't investigate assumptions.

They investigate **evidence**.

Understanding where this evidence comes from is one of the most important skills you'll develop as a defender.

---

## Understanding Security Controls

Security controls are safeguards implemented to reduce cyber risk and protect organizational assets.

No organization can completely prevent cyber attacks.

Instead, organizations deploy multiple layers of security controls that work together to:

- Prevent attacks
- Detect malicious activity
- Respond to incidents
- Recover affected systems

Every security control contributes to improving an organization's security posture.

More importantly for Threat Hunters, many of these controls generate valuable evidence during an investigation.

---

## Preventive Controls

Preventive controls attempt to stop attacks before they succeed.

Their primary objective is reducing the attack surface and preventing unauthorized actions.

Common preventive controls include:

- Multi-Factor Authentication (MFA)
- Firewalls
- Endpoint Protection
- Secure Configuration Baselines
- Patch Management
- Application Control
- Email Security Gateways
- Network Segmentation

For example, if an attacker attempts to access an account using stolen credentials, Multi-Factor Authentication may block the login entirely.

Although preventive controls reduce successful attacks, they cannot stop every threat.

Attackers continuously adapt their techniques.

This is why detective controls become equally important.

---

## Detective Controls

Detective controls identify suspicious or malicious activity after it occurs.

These controls generate the telemetry that Threat Hunters investigate every day.

Examples include:

- Security Information and Event Management (SIEM)
- Endpoint Detection and Response (EDR)
- Windows Event Logs
- Sysmon
- Intrusion Detection Systems (IDS)
- DNS Monitoring
- Authentication Logs
- Cloud Audit Logs

Unlike preventive controls, detective controls don't stop attacks.

Instead, they answer important investigative questions.

- What happened?
- Who performed the activity?
- Which systems were affected?
- When did it happen?
- How did it happen?

Threat Hunting depends heavily on detective controls because they provide the evidence required to reconstruct attacker activity.

---

## Corrective Controls

Corrective controls restore systems after an incident has occurred.

Examples include:

- Restoring backups
- Rebuilding compromised systems
- Incident Response procedures
- Disaster Recovery plans
- Security patches

Threat Hunters frequently recommend improvements to corrective controls after completing investigations.

Every investigation should strengthen the organization's ability to recover from future attacks.

---

## Administrative Controls

Administrative controls define how people should protect organizational resources.

Examples include:

- Security Policies
- Acceptable Use Policies
- Risk Assessments
- Security Awareness Training
- Access Control Procedures
- Incident Response Plans

Many successful attacks occur because processes fail rather than technology.

Strong administrative controls reduce these risks.

---

## Technical Controls

Technical controls use technology to protect systems and generate security visibility.

Examples include:

- Firewalls
- Antivirus
- EDR
- SIEM
- Web Application Firewalls
- Identity Providers
- Encryption
- Network Access Control

Threat Hunters interact with technical controls more frequently than any other control category because they continuously produce operational telemetry.

---

## Physical Controls

Physical controls protect the infrastructure supporting digital systems.

Examples include:

- Badge-controlled access
- CCTV systems
- Locked server rooms
- Security guards
- Biometric authentication
- Environmental monitoring

Although physical security isn't usually part of day-to-day Threat Hunting, unauthorized physical access often leads to digital compromise.

---

## Why Security Controls Matter to Threat Hunters

Security controls don't exist only to stop attacks.

They also generate valuable evidence.

Imagine an attacker successfully compromises an employee's workstation.

Throughout the attack, different security controls begin recording activity.

Authentication systems record successful logins.

Windows records process execution.

Firewalls observe network communication.

DNS servers record domain lookups.

EDR solutions monitor endpoint behavior.

Every control contributes another piece of evidence.

Threat Hunting isn't about relying on one data source.

It's about combining evidence from multiple sources to understand what really happened.

---

## Understanding Security Telemetry

One of the most important concepts every Threat Hunter must understand is **telemetry**.

Telemetry is the operational data generated by systems as they perform normal activities.

Every login.

Every process.

Every network connection.

Every DNS query.

Every PowerShell execution.

Every registry modification.

Every file creation.

Generates telemetry.

Threat Hunters don't create this information.

They analyze it.

The more telemetry available, the greater the visibility into attacker behavior.

---

## What Are Logs?

Logs are chronological records of events generated by operating systems, applications, security tools, cloud platforms, and network devices.

Each log answers different investigative questions.

No single log tells the complete story.

Instead, Threat Hunters correlate multiple log sources to reconstruct attacker activity.

Let's examine the most common evidence sources used during investigations.

---

## Windows Event Logs

Windows Event Logs provide one of the richest sources of endpoint evidence.

They record operating system activity including:

- User logons
- Failed authentication attempts
- Service creation
- Account changes
- System startup and shutdown
- Application events
- Security events
- Policy changes

For many investigations, Windows Event Logs provide the first indication that something unusual has occurred.

---

## Sysmon

Sysmon extends native Windows logging by providing significantly more detailed endpoint telemetry.

Examples include:

- Process Creation
- Parent-Child Process Relationships
- Network Connections
- Registry Modifications
- Driver Loading
- File Creation
- Process Injection
- Named Pipe Activity

Because of this enhanced visibility, Sysmon has become one of the most valuable data sources for Threat Hunters.

---

## Authentication Logs

Identity plays a role in almost every cyber attack.

Authentication logs record activities such as:

- Successful logins
- Failed login attempts
- Account lockouts
- Password changes
- Privilege usage
- Multi-Factor Authentication events

These logs help investigators determine whether attacker activity involved credential theft, privilege escalation, or unauthorized account usage.

---

## Firewall Logs

Firewalls monitor traffic entering and leaving organizational networks.

Firewall logs typically include:

- Source IP Address
- Destination IP Address
- Ports
- Protocols
- Allowed Connections
- Blocked Connections

Threat Hunters analyze firewall telemetry to identify:

- Command and Control communication
- External attacker infrastructure
- Lateral movement
- Network scanning
- Unexpected outbound traffic

---

## DNS Logs

Every domain lookup generates DNS activity.

Threat Hunters investigate DNS logs because attackers frequently rely on DNS during intrusions.

Examples include:

- Newly observed domains
- Rare domains
- High-frequency DNS requests
- DNS tunneling
- Suspicious Top-Level Domains

DNS telemetry often reveals attacker infrastructure that would otherwise remain hidden.

---

## Proxy Logs

Proxy servers record web activity performed by users and systems.

These logs commonly reveal:

- Websites visited
- Downloaded files
- Upload activity
- Browser communications
- Internet usage

Proxy logs frequently help investigators determine how malware entered the environment or whether sensitive information left the organization.

---

## Endpoint Detection and Response (EDR)

Modern EDR solutions combine multiple telemetry sources into a single investigative platform.

They commonly record:

- Process Execution
- Script Activity
- Memory Behavior
- Network Connections
- Registry Changes
- Persistence Mechanisms
- User Activity

Threat Hunters often pivot between EDR telemetry and traditional logs to validate observations and understand attacker behavior.

---

## Cloud Logs

Modern organizations increasingly rely on cloud platforms.

Cloud services generate valuable audit telemetry including:

- Administrative Actions
- Resource Creation
- API Activity
- Identity Events
- Permission Changes
- Authentication Events

Examples include:

- Microsoft 365 Audit Logs
- Azure Activity Logs
- AWS CloudTrail
- Google Cloud Audit Logs

Threat Hunters must understand both traditional endpoint telemetry and cloud-generated evidence.

---

## Correlation: Turning Data into Evidence

No individual log explains an entire attack.

Instead, investigators combine evidence from multiple sources.

Consider the following sequence.

An employee receives a phishing email.

↓

Authentication logs record a successful login.

↓

Windows Event Logs record PowerShell execution.

↓

Sysmon captures the encoded command.

↓

DNS logs reveal communication with an unfamiliar domain.

↓

Firewall logs record outbound connections.

↓

EDR identifies credential dumping.

Each event appears relatively ordinary by itself.

Together, they reveal the complete attack.

This process of connecting multiple evidence sources is called **correlation**.

Correlation is one of the most valuable skills every Threat Hunter develops.

---

## From Telemetry to Threat Hunting

Everything we've learned throughout this article connects together.

Cyber Threat

↓

Attack

↓

Security Controls

↓

Telemetry

↓

Logs

↓

Evidence

↓

Investigation

↓

Detection

↓

Threat Hunting

Threat Hunting is not the process of searching random logs.

It is the disciplined process of transforming raw telemetry into meaningful evidence that explains attacker behavior.

---

## Final Thoughts

Cybersecurity fundamentals are much more than introductory concepts.

They form the knowledge that supports every Threat Hunting investigation.

Understanding cyber threats explains what attackers are trying to achieve.

Understanding investigations teaches you how to ask the right questions.

Understanding frameworks provides structure.

Understanding security controls explains how organizations defend themselves.

Understanding telemetry reveals where evidence exists.

Understanding logs teaches you where to begin searching.

Without these fundamentals, security events become noise.

With them, every event becomes a potential clue.

Great Threat Hunters are not defined by how many tools they know.

They are defined by how effectively they understand systems, analyze evidence, and connect seemingly unrelated events into a complete picture of attacker activity.

Master the fundamentals first.

Everything else becomes significantly easier.

---

## Key Takeaways

- Security controls reduce cyber risk and generate valuable investigative evidence.
- Preventive controls stop attacks, detective controls identify attacks, and corrective controls restore systems.
- Telemetry is the operational data continuously generated by systems.
- Logs are one of the most important evidence sources during Threat Hunting.
- Windows Event Logs, Sysmon, Firewall Logs, DNS Logs, Authentication Logs, Proxy Logs, EDR telemetry, and Cloud Logs each contribute unique investigative insights.
- Correlation transforms raw telemetry into actionable evidence.
- Every successful Threat Hunting investigation begins with understanding where the evidence comes from.

---

## What's Next?

Now that you've built a strong cybersecurity foundation, the next logical step is understanding the discipline itself.

In the next article, we'll explore:

## **What Is Threat Hunting? Understanding the Mindset Before the Methodology**

We'll examine how Threat Hunting differs from SOC monitoring, Incident Response, Detection Engineering, Threat Intelligence, and Vulnerability Management, while introducing the hypothesis-driven mindset that professional Threat Hunters use to uncover hidden adversaries before automated alerts identify them.
