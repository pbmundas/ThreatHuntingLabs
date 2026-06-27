
# Threat Hunting Methodologies: Choosing the Right Hunting Approach

In the previous article, we learned how experienced Threat Hunters develop meaningful hypotheses.

A hypothesis answers an important question.

> **"What do I want to investigate?"**

However, another equally important question remains.

> **"How should I investigate it?"**

Imagine two Threat Hunters receive exactly the same hypothesis.

> Attackers may be abusing PowerShell within our environment.

Both hunters begin with the same objective.

Yet their investigations look completely different.

One starts searching for known Indicators of Compromise.

The other maps the behaviour to MITRE ATT&CK.

A third analyst begins analysing process relationships.

Another compares today's activity against historical baselines.

Who's correct?

Interestingly...

All of them are.

Because Threat Hunting doesn't have a single methodology.

Different investigations require different approaches.

Experienced Threat Hunters don't choose a methodology because it's popular.

They choose the methodology that best answers the investigative question in front of them.

This article explores the most widely used Threat Hunting methodologies, when to use them, their strengths, their limitations, and how mature Threat Hunting teams combine them to uncover adversaries who intentionally avoid detection.

---

## There Is No Universal Hunting Method

One of the biggest misconceptions about Threat Hunting is believing there's a standard checklist that works for every investigation.

There isn't.

Consider the following situations.

An intelligence report identifies new infrastructure used by a ransomware group.

A critical zero-day vulnerability is publicly disclosed.

A user suddenly begins downloading ten times more data than usual.

An endpoint starts communicating with an IP address that has never been observed before.

Each situation requires a different investigative approach.

Trying to solve every problem using the same methodology is like trying to repair every fault in a car using only a screwdriver.

Sometimes it works.

Most of the time, it doesn't.

This is why mature Threat Hunting teams maintain multiple methodologies and select the one that best aligns with the available intelligence, telemetry, business risk, and investigative objective.

---

## Selecting the Right Methodology

Before beginning a Threat Hunt, experienced hunters ask themselves several questions.

- What triggered this investigation?
- Do we have Indicators of Compromise?
- Are we investigating attacker behaviour?
- Is there historical data available?
- Are we validating Threat Intelligence?
- Are we searching for unknown attackers?
- Which telemetry is available?
- How mature are our detections?

The answers determine which methodology is most appropriate.

There is no universally "best" methodology.

There is only the methodology that best fits the current investigation.

---

## The Major Threat Hunting Methodologies

Throughout this article we'll explore the following methodologies.

| Methodology | Primary Focus |
|-------------|---------------|
| Intelligence-Driven Hunting | Threat Intelligence |
| IOC-Based Hunting | Known Indicators of Compromise |
| TTP-Based Hunting | Adversary Behaviour |
| Behavioral Hunting | Abnormal Behaviour |
| Baseline-Driven Hunting | Deviation from Normal Activity |
| Analytics-Driven Hunting | Statistical Analysis |
| Risk-Based Hunting | Business Risk |
| ATT&CK-Driven Hunting | MITRE ATT&CK Techniques |
| Campaign-Based Hunting | Specific Threat Actors |
| Hybrid Hunting | Multiple Methodologies Combined |

Each has its own purpose.

Each solves a different investigative problem.

Understanding when to use each methodology is one of the defining characteristics of an experienced Threat Hunter.

---

## Before We Begin...

It's important to understand one final concept.

These methodologies are **not competitors**.

You don't choose one and ignore the others.

Instead, think of them as different lenses through which you examine the same environment.

Imagine standing in front of a large building.

One person views it from the front.

Another from above.

Another from inside.

Each perspective reveals something different.

Threat Hunting methodologies work exactly the same way.

The better your ability to change perspectives, the more likely you are to discover adversaries attempting to remain hidden.

