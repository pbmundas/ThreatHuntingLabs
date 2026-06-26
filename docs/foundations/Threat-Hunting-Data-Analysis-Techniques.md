# Threat Hunting Data Analysis Techniques: How Threat Hunters Find Attackers Hidden in Millions of Events

It's **9:15 on a Monday morning**.

Your Security Information and Event Management (SIEM) platform has already ingested more than **34 million security events**.

Authentication logs.

DNS queries.

Firewall connections.

PowerShell executions.

Email activity.

Endpoint telemetry.

Cloud audit logs.

Process creation events.

And it's not even lunchtime.

Then your manager walks over and asks a seemingly simple question.

> **"Can you tell me whether an attacker is currently hiding somewhere inside our environment?"**

No alerts have been triggered.

No ransomware has appeared.

No users have reported suspicious activity.

There are simply **millions of events** flowing into your SIEM every hour.

Where do you even begin?

Surely you can't review every single event manually.

Even if you could inspect one log every second without taking a break, reviewing just **one day's worth of telemetry** would take years.

Clearly, experienced Threat Hunters don't investigate events one by one.

Instead, they look for **patterns**.

That single realization changes the way you think about Threat Hunting.

Threat Hunting isn't about reading logs.

It's about reducing millions of events into a handful of observations that deserve investigation.

That's exactly where **data analysis techniques** come in.

Rather than trying to identify attackers directly, these techniques help answer questions like:

- What looks different today?
- What has never happened before?
- Which device behaves differently from every other device?
- Which user suddenly performed an unusual action?
- Which process rarely executes?
- Which sequence of events doesn't make sense?

Each technique gives the hunter another perspective on the same data.

Individually they are useful.

Combined together, they become incredibly powerful.

By the end of this article you'll understand not only **what these techniques are**, but more importantly **how experienced Threat Hunters use them to uncover hidden attackers.**

---

## Before We Begin: Think Like a Threat Hunter

One of the biggest misconceptions about Threat Hunting is believing success comes from knowing hundreds of KQL queries.

Or mastering Splunk SPL.

Or writing advanced Sigma rules.

Those skills certainly help.

But they aren't what separates an experienced Threat Hunter from everyone else.

Imagine two analysts sitting next to each other.

Both have access to the same SIEM.

Both can query exactly the same logs.

Both have identical permissions.

Yet one consistently uncovers threats while the other finds nothing.

Why?

Because they ask different questions.

The first analyst asks:

> **"Which query should I run?"**

The Threat Hunter asks:

> **"If an attacker wanted to stay hidden, what patterns would they accidentally leave behind?"**

That difference in mindset changes everything.

Threat Hunters aren't searching for individual events.

They're searching for **deviations**.

Every analytical technique discussed in this article exists for one reason.

To answer a single question.

 tip "Threat Hunter's Mindset"

    Instead of asking:

    **"What is malicious?"**

    Experienced Threat Hunters ask:

    **"What doesn't belong?"**

    That subtle shift in thinking is what transforms reactive investigations into proactive Threat Hunting.

Let's start with the most fundamental technique used during almost every Threat Hunt.

---

## 1. Baselining

Imagine you're responsible for protecting **10,000 Windows endpoints**.

Every morning, employees log in.

Microsoft Teams starts automatically.

Outlook opens.

Edge launches.

OneDrive synchronizes files.

Background services initialise.

Nothing appears unusual.

The same pattern repeats tomorrow.

And the day after.

Eventually, you begin to understand what **normal** looks like.

This is known as a **baseline**.

A baseline is simply a reference point representing expected behaviour within an environment.

Without understanding what "normal" looks like, identifying abnormal behaviour becomes almost impossible.

Think about airport security.

Security officers don't inspect every traveller because they expect everyone to be dangerous.

They understand what normal passenger behaviour looks like.

Anyone behaving significantly differently naturally attracts more attention.

Threat Hunters work the same way.

---

**A Real Investigation**

 example "Example: Detecting a Deviation from the Baseline"

    For several months, a user's workstation has behaved predictably.

    Every morning it launches Microsoft Teams, Outlook, Microsoft Edge, and OneDrive.

    Today, however, something different appears.

    `powershell.exe -EncodedCommand SQBFAFgA...`

    The command executes silently.

    It downloads additional content.

    It creates child processes.

    This user has **never** executed an encoded PowerShell command before.

    The workstation has **never** communicated with the external domain referenced by the script.

    No alert has fired.

    No malware has been detected.

    But today's activity no longer resembles the established baseline.

    **That's exactly what Threat Hunters investigate.**

Notice something important.

Nothing here proves malicious activity.

Baselining doesn't tell us an attack has occurred.

It simply tells us something has changed.

That change deserves attention.

---

**What Can Be Baselined?**

Almost every security dataset can have a baseline.

Some of the most common examples include:

| Data Source | Typical Baseline |
|-------------|------------------|
| Authentication Logs | Normal login hours and locations |
| Process Creation | Commonly executed applications |
| DNS Logs | Frequently accessed domains |
| Firewall Logs | Expected outbound destinations |
| Service Accounts | Normal authentication behaviour |
| Endpoint Telemetry | Parent-child process relationships |
| File Access Logs | Frequently accessed files |
| Email Activity | Average emails sent each day |
| Cloud Audit Logs | Administrative changes |

Once a baseline has been established, every new event can be compared against it.

Instead of asking,

> "Is this malware?"

Threat Hunters ask:

> **"Does today's behaviour resemble yesterday's behaviour?"**

If the answer is no, the investigation has just begun.

---

**Why Baselining Matters**

Baselining is often the first analytical technique used during Threat Hunting because attackers rarely arrive with flashing warning signs.

Instead, they quietly introduce small deviations into an otherwise normal environment.

A workstation that normally contacts ten external domains suddenly contacts an eleventh.

A service account that authenticates only from servers suddenly logs in from a user workstation.

A user who typically signs in between 9 AM and 6 PM suddenly authenticates at 2 AM.

Individually, none of these observations prove malicious activity.

Collectively, they begin telling a story.

Baselining gives Threat Hunters the context needed to recognise when that story changes.

Without it, every event looks equally important.

With it, unusual behaviour naturally rises to the surface.

---

Now that we understand how to identify changes from normal behaviour, the next challenge is equally important.

What happens when your dataset contains **millions of events**, making it impossible to investigate them individually?

Before identifying anomalies, we first need to organise the data.

## 2. Grouping

Imagine your SIEM contains **12 million process creation events** collected over the past 24 hours.

Reviewing each event individually would be impossible.

Even if every event were legitimate, simply scrolling through the logs would consume hours before you discovered anything useful.

Threat Hunters solve this problem by asking a different question.

Instead of investigating individual events, they begin organising similar events together.

This technique is known as **Grouping**.

Grouping transforms millions of unrelated records into meaningful categories, making large datasets significantly easier to understand.

Think of it like sorting a box of mixed LEGO bricks.

Rather than examining every single brick individually, you first separate them by colour, size, or shape.

Once organised, patterns become much easier to recognise.

Threat Hunting follows exactly the same principle.

---

**A Real Investigation**

 example "Example: Grouping Similar Process Executions"

    Imagine your SIEM has recorded thousands of process executions from endpoints across the organisation.

    Instead of reviewing every single event individually, you group identical process names together.

| Process | Number of Executions |
|---------|---------------------:|
| chrome.exe | 486,214 |
| msedge.exe | 352,811 |
| teams.exe | 287,194 |
| outlook.exe | 241,503 |
| explorer.exe | 176,322 |
| powershell.exe | 3,982 |
| certutil.exe | 6 |
| mshta.exe | 2 |

Within seconds, the investigation changes.

You're no longer looking at hundreds of thousands of events.

You're looking at only eight groups.

The data has become manageable.

More importantly, unusual activity has already started becoming visible.

---

**What Can Be Grouped?**

Almost every security dataset benefits from grouping.

Threat Hunters frequently group events by:

| Data Source | Common Grouping |
|-------------|-----------------|
| Authentication Logs | Username |
| Endpoint Logs | Process Name |
| DNS Logs | Queried Domain |
| Firewall Logs | Destination IP |
| Email Logs | Sender Address |
| Cloud Audit Logs | Operation Name |
| Registry Events | Registry Path |
| File Activity | File Extension |
| Alerts | Alert Type |

Grouping doesn't identify attacks.

It simply removes unnecessary complexity, allowing hunters to focus on meaningful observations instead of drowning in raw data.

---

**Why Grouping Matters**

One failed login tells you very little.

Ten thousand failed logins also tell you very little.

But grouping those events by **country**, **username**, or **source IP address** immediately reveals patterns.

Consider the following grouped authentication failures.

| Country | Failed Logins |
|---------|--------------:|
| India | 12 |
| United Kingdom | 18 |
| United States | 15 |
| Russia | 8,421 |

Nothing about an individual failed login is suspicious.

However, once grouped together, one country immediately stands out.

Grouping doesn't find attackers.

It simply points investigators toward the places worth investigating.

---

## 3. Clustering

At first glance, Grouping and Clustering seem almost identical.

Both organise data.

Both simplify investigations.

But there's an important difference.

**Grouping uses characteristics that already exist.**

**Clustering discovers relationships that weren't obvious before.**

Imagine you manage thousands of endpoints.

Most employee laptops naturally behave very similarly.

Office applications.

Browsers.

Video conferencing software.

PDF readers.

Engineering workstations, however, look different.

They frequently execute Visual Studio, Docker, Git, and development tools.

Database servers form another group.

Domain Controllers form another.

Without anyone explicitly defining these categories, systems naturally begin forming clusters based on their behaviour.

That's exactly what Clustering attempts to identify.

---

**A Real Investigation**

 example "Example: Identifying an Unusual Workstation"

Imagine your organisation has analysed process execution data from every endpoint.

Most systems naturally fall into familiar groups.

| Cluster | Typical Applications |
|---------|----------------------|
| Office Users | Outlook, Teams, Edge, Excel |
| Developers | Visual Studio, Docker, Git |
| Database Servers | SQL Server, Backup Services |
| Domain Controllers | LSASS, Netlogon, DFSR |

Then one workstation appears that doesn't belong to any cluster.

Instead, it frequently executes:

- `certutil.exe`
- `mshta.exe`
- `powershell.exe`
- `rundll32.exe`
- `regsvr32.exe`

Each application is completely legitimate.

But together, they don't resemble any other workstation in the organisation.

That workstation immediately becomes interesting.

---

**Why Clustering Matters**

Attackers rarely behave exactly like normal users.

Even when they attempt to blend into legitimate activity, subtle behavioural differences often remain.

Clustering helps Threat Hunters identify those systems that simply don't fit.

Instead of asking,

> **"Is this workstation malicious?"**

Hunters ask,

> **"Why is this workstation behaving differently from every other workstation?"**

Sometimes the answer is perfectly legitimate.

Sometimes it's the first indication that an attacker has established persistence.

---

## 4. Frequency Analysis

One of the simplest Threat Hunting techniques is also one of the most effective.

Instead of asking what happened, hunters ask:

> **"How often does this normally happen?"**

Frequency Analysis focuses on measuring how often specific activities occur over time.

The technique itself is simple.

Unexpected increases—or unexpected decreases—often indicate that something has changed.

---

**A Real Investigation**

 example "Example: Normal PowerShell Activity"

For the past week, PowerShell executions have remained fairly consistent.

| Day | PowerShell Executions |
|-----|----------------------:|
| Monday | 38 |
| Tuesday | 41 |
| Wednesday | 36 |
| Thursday | 44 |
| Friday | 39 |

Nothing appears unusual.

This becomes the baseline.

The following Monday, however, the numbers change dramatically.

 warning "Example: Something Has Changed"

| Day | PowerShell Executions |
|-----|----------------------:|
| Monday | **5,732** |

One number doesn't prove malicious activity.

But compared to the established baseline, something has clearly changed.

That change deserves investigation.

---

**Common Uses of Frequency Analysis**

Threat Hunters commonly measure the frequency of:

- Authentication attempts
- Failed logins
- DNS requests
- PowerShell executions
- Process launches
- Administrative actions
- File downloads
- Registry modifications
- Email activity
- Firewall connections

The goal isn't to identify malware.

The goal is to identify **unexpected changes in behaviour**.

---

## 5. Stack Counting (Repetition Counting)

If Frequency Analysis tells us **how often something happens over time**, Stack Counting tells us **how often different things appear within the same dataset**.

Think of it as ranking events from the most common to the least common.

Most attackers try to blend into everyday activity.

Ironically, the tools they use often become the rarest events in the environment.

That's exactly what Stack Counting helps reveal.

---

**A Real Investigation**

 example "Example: Finding the Needle in the Haystack"

Imagine you count every executable launched yesterday.

| Process | Executions |
|---------|-----------:|
| chrome.exe | 452,118 |
| msedge.exe | 338,404 |
| teams.exe | 301,442 |
| outlook.exe | 284,006 |
| explorer.exe | 176,311 |
| powershell.exe | 3,241 |
| certutil.exe | 7 |
| mshta.exe | 2 |
| rundll32.exe | 1 |

Most analysts instinctively focus on the largest numbers.

Threat Hunters often do the opposite.

Why did **rundll32.exe** execute only once?

Why did **mshta.exe** execute twice?

Why did **certutil.exe** suddenly appear seven times?

Those rare events may be completely legitimate.

Or they may represent an attacker attempting to remain hidden.

Either way, they're worth investigating.

---

**Why Stack Counting Matters**

Stack Counting is one of the fastest ways to reduce millions of events into a shortlist requiring human attention.

Instead of searching directly for malicious activity, it asks a much simpler question.

> **"What is so uncommon that it deserves another look?"**

Very often, that's where the investigation begins.

---

At this point, we've explored five of the most widely used analytical techniques in Threat Hunting.

Each one helps reduce overwhelming volumes of telemetry into meaningful observations.

However, experienced attackers are also aware of these techniques.

Many deliberately avoid generating rare events or obvious spikes in activity.

Instead, they attempt to blend into normal operations so convincingly that even frequency analysis and stack counting fail to detect them.

So how do experienced Threat Hunters identify attackers who intentionally try to look ordinary?

That's exactly what we'll explore next as we dive into **Rarity Scoring, Outlier Detection, Time Delta Analysis, Entropy Analysis, Parent-Child Process Analysis, and First-Time-Seen Analysis.**

## 6. Rarity Scoring

Imagine you're responsible for monitoring 15,000 endpoints.

Most applications executed throughout the day are completely expected.

Microsoft Teams.

Microsoft Edge.

Google Chrome.

Microsoft Outlook.

Adobe Acrobat.

Visual Studio.

Nothing stands out because thousands of employees use them every day.

Now imagine discovering a process that appears only once across the entire organization.

Should you panic?

Not necessarily.

But it certainly deserves attention.

This idea forms the basis of **Rarity Scoring**.

Unlike Stack Counting, which simply ranks events by occurrence, Rarity Scoring assigns a score based on how uncommon an event is compared to everything else in the environment.

The rarer the behaviour, the higher the investigation priority.

**Example: A Rare Application**

| Application | Devices Executed |
|-------------|----------------:|
| chrome.exe | 14,892 |
| msedge.exe | 14,611 |
| teams.exe | 14,488 |
| outlook.exe | 14,021 |
| powershell.exe | 1,623 |
| mimikatz.exe | 1 |

Every application above is legitimate except one.

Would you ignore **mimikatz.exe** simply because it executed once?

Probably not.

Being rare doesn't automatically make something malicious.

But rarity often points investigators toward behaviour that deserves closer examination.

**Where Rarity Scoring Helps**

Threat Hunters commonly apply rarity scoring to:

- Executable names
- Parent-child relationships
- Registry keys
- Network destinations
- DNS queries
- Browser user agents
- Service installations
- Scheduled tasks

Instead of asking:

> "Is this malicious?"

Threat Hunters ask:

> **"How unusual is this compared to everything else?"**

---

## 7. Outlier Detection

Suppose you collect authentication activity for every employee in your organization.

Most users log in between:

- 8:00 AM
- 9:00 AM

Most generate:

- 200–400 authentication events per day.

Everything appears remarkably consistent.

Then one user suddenly generates:

**18,000 authentication events.**

That user becomes an **outlier**.

Outlier Detection identifies observations that are significantly different from the majority of the dataset.

Unlike baselining, which compares today's behaviour with historical behaviour, outlier detection compares one entity against everyone else.

**Example: Authentication Volume**

| User | Authentication Events |
|------|----------------------:|
| User A | 284 |
| User B | 301 |
| User C | 263 |
| User D | 295 |
| User E | **18,417** |

One user clearly behaves differently.

The reason may be perfectly legitimate.

Perhaps they're a service account.

Perhaps they're an administrator.

Or perhaps an attacker is attempting password spraying or lateral movement.

Either way, this observation deserves investigation.

**Common Outliers**

Threat Hunters often search for:

- Large authentication spikes
- Excessive network traffic
- Abnormal process creation
- High-volume DNS requests
- Excessive failed logins
- Large data transfers

Outliers don't always represent attacks.

But attackers frequently become outliers sooner or later.

---

## 8. Time Delta Analysis

Security events don't just occur.

They occur **over time**.

Sometimes the time between two events is more important than the events themselves.

This is known as **Time Delta Analysis**.

Rather than asking what happened, Threat Hunters ask:

> **"How quickly did it happen?"**

**Example: Impossible Speed**

Imagine the following sequence.

| Time | Activity |
|------|----------|
| 09:02:14 | User opens Microsoft Word |
| 09:02:18 | PowerShell launches |
| 09:02:19 | Encoded command executed |
| 09:02:20 | External payload downloaded |
| 09:02:22 | Scheduled task created |

Everything occurred within **eight seconds**.

Humans rarely work this quickly.

Automation does.

Malware does.

Attack frameworks do.

The extremely small time difference immediately suggests automated execution.

**Time Delta Analysis Can Reveal**

- Malware execution
- Automated scripts
- Brute-force attacks
- Password spraying
- Beaconing activity
- Scheduled persistence

Sometimes the timing tells a more compelling story than the events themselves.

---

## 9. Entropy & String Analysis

Attackers frequently disguise their payloads.

One common technique involves generating random-looking file names, registry keys, domains, or PowerShell commands.

Humans naturally create names that are readable.

Attackers—and malware—often don't.

Entropy Analysis measures how random a string appears.

The more random it looks, the more suspicious it may become.

**Example**

Which filename looks more suspicious?

| Filename |
|----------|
| PayrollReport.pdf |
| Invoice-April.xlsx |
| xJ83kdPqLm92Af.exe |

The third filename immediately attracts attention.

Not because it's malware.

But because it doesn't resemble something humans normally create.

Threat Hunters commonly analyse:

- File names
- Registry keys
- Scheduled task names
- Service names
- Domains
- URLs
- PowerShell commands
- Base64 strings

Entropy doesn't identify attacks.

It identifies **artificial randomness**, which often accompanies malicious activity.

---

## 10. Parent-Child Process Analysis

One of the most powerful analytical techniques involves understanding which processes launch other processes.

Windows follows fairly predictable parent-child relationships.

For example:

| Parent | Child |
|---------|-------|
| explorer.exe | chrome.exe |
| explorer.exe | outlook.exe |
| services.exe | svchost.exe |

These relationships occur thousands of times every day.

Now consider something different.

| Parent | Child |
|---------|-------|
| WINWORD.EXE | powershell.exe |
| EXCEL.EXE | cmd.exe |
| Acrobat.exe | mshta.exe |

Nothing here is technically illegal.

Every executable is signed by Microsoft or Adobe.

But the relationships themselves are unusual.

Attackers frequently abuse trusted applications to launch malicious payloads.

Rather than hunting for malware, Threat Hunters hunt for **unexpected process relationships**.

**Parent-Child Analysis Commonly Detects**

- Office macro abuse
- LOLBins (Living-off-the-Land Binaries)
- Script execution
- Malware launch chains
- Initial payload execution
- Persistence mechanisms

The individual process may appear harmless.

The parent-child relationship often tells the real story.

---

## 11. First-Time-Seen Analysis

Threat Hunters love asking one simple question.

> **"Has this ever happened before?"**

If the answer is no, the event becomes immediately interesting.

This technique is known as **First-Time-Seen Analysis**.

Rather than focusing on rarity, it focuses on novelty.

**Example**

A workstation suddenly contacts:

```
update-secure-microsoft365-cloudsync.net
```

Threat Intelligence reports nothing.

No antivirus alerts appear.

No users complain.

But one observation stands out.

This domain has **never** been contacted by any device in the organization before.

That's enough to justify investigation.

First-Time-Seen Analysis commonly applies to:

- Domains
- IP addresses
- Processes
- Scheduled tasks
- Services
- Registry keys
- Executables
- User agents
- Cloud applications

Many advanced attacks begin with something the environment has simply never seen before.

Recognising those first appearances allows Threat Hunters to investigate early—often before traditional detection rules are created.

---

We've now explored techniques that identify **rare behaviour**, **statistical anomalies**, **timing anomalies**, **randomness**, **unexpected process relationships**, and **new observations**.

In the final part of this article, we'll explore techniques that compare entities with their peers, identify impossible behaviour, detect abnormal data movement, reconstruct attack chains, and learn how experienced Threat Hunters combine multiple analytical techniques during a single investigation.

## 12. Peer Comparison

Imagine you're responsible for monitoring activity across 2,000 employees.

Most users in the Human Resources department perform similar tasks every day.

They access the HR portal.

Open Microsoft Outlook.

Use Microsoft Teams.

Download payroll reports.

Occasionally upload documents to SharePoint.

Their daily behavior is remarkably consistent.

Now imagine one HR employee suddenly uploads **18 GB** of data to an unfamiliar cloud storage service.

Would that be considered normal?

Probably not.

Nothing about uploading files is inherently malicious.

However, compared to everyone else performing the same role, this user's behaviour is significantly different.

This is where **Peer Comparison** becomes valuable.

Rather than comparing a user against their own historical behaviour, Peer Comparison compares them against others performing similar roles.

**Example: Comparing Similar Users**

| Department | Average Daily Upload |
|------------|--------------------:|
| Human Resources | 35 MB |
| Finance | 52 MB |
| Marketing | 410 MB |
| Engineering | 2.8 GB |

Now consider one HR employee.

| User | Daily Upload |
|------|-------------:|
| HR-User-27 | **18 GB** |

Nothing proves malicious activity.

Perhaps they're preparing quarterly reports.

Perhaps they're migrating data.

Or perhaps they're exfiltrating sensitive information.

The key observation is simple.

Compared to their peers, their behaviour doesn't fit.

**Common Peer Comparisons**

Threat Hunters frequently compare:

- Users within the same department
- Devices with identical roles
- Domain Controllers
- Database Servers
- Cloud workloads
- Service Accounts
- Administrative accounts

Peer Comparison is especially valuable in large enterprises where historical behaviour alone isn't enough to identify suspicious activity.

---

## 13. Path and Location Anomaly

Attackers often try to hide malicious files in locations users rarely inspect.

Windows itself follows predictable conventions.

System files belong in system directories.

Applications install into program directories.

User documents remain within user profiles.

When software suddenly appears somewhere unexpected, it deserves attention.

**Example**

Which executable looks more suspicious?

| Executable | Location |
|------------|----------|
| notepad.exe | `C:\Windows\System32\` |
| chrome.exe | `C:\Program Files\Google\Chrome\` |
| AdobeUpdater.exe | `C:\Users\Public\Adobe\` |

The executable name itself appears legitimate.

The location doesn't.

Attackers frequently exploit trusted filenames while storing them in unexpected directories.

Threat Hunters commonly investigate:

- Executables inside temporary folders
- Files under `C:\Users\Public`
- Unexpected startup locations
- Unusual scheduled task paths
- DLLs loaded from user profiles
- Scripts stored in Downloads folders

The executable may be legitimate.

Its location may not be.

---

## 14. Impossible Travel (Velocity Analysis)

Authentication events become much more interesting when geography is considered.

Suppose an employee successfully authenticates from Bangalore at 9:00 AM.

Twenty minutes later, the same account authenticates from London.

Technically, both logins are successful.

Neither violates authentication policies.

Yet something doesn't make sense.

Humans can't travel halfway around the world in twenty minutes.

This analytical technique is known as **Impossible Travel** or **Velocity Analysis**.

**Example**

| Time | Location |
|------|----------|
| 09:00 | Bangalore, India |
| 09:18 | London, United Kingdom |

Unless the employee has discovered teleportation, one of these sessions is likely suspicious.

Possible explanations include:

- VPN usage
- Credential theft
- Session hijacking
- Cloud proxy services
- Identity compromise

Threat Hunters investigate before drawing conclusions.

The goal isn't to prove an attack.

The goal is to identify behaviour that defies normal human movement.

---

## 15. Volume and Size Anomaly

Sometimes the content of an event isn't unusual.

Its size is.

Imagine a workstation that normally uploads between **50 MB and 100 MB** every day.

One afternoon, it uploads **47 GB**.

The destination might be legitimate.

The protocol might be encrypted.

No malware is detected.

Yet the volume alone deserves investigation.

**Example**

| Day | Data Uploaded |
|-----|--------------:|
| Monday | 64 MB |
| Tuesday | 71 MB |
| Wednesday | 58 MB |
| Thursday | 69 MB |
| Friday | **47 GB** |

Threat Hunters frequently monitor:

- Large uploads
- Large downloads
- Archive creation
- Database exports
- Cloud storage uploads
- Backup transfers
- Email attachment sizes

Large volumes don't automatically indicate data theft.

However, they often represent the earliest visible sign of exfiltration.

---

## 16. Sequence (Chain) Analysis

Individual events rarely tell the full story.

The sequence in which they occur often reveals far more than the events themselves.

Attackers don't simply execute one command.

They perform a chain of actions.

Each step prepares for the next.

Threat Hunters reconstruct those chains to understand the attack.

**Example**

Consider the following sequence.

| Step | Activity |
|------|----------|
| 1 | Microsoft Word opens |
| 2 | PowerShell launches |
| 3 | Encoded command executes |
| 4 | Payload downloaded |
| 5 | Scheduled task created |
| 6 | LSASS accessed |
| 7 | External communication established |

Viewed individually, every event appears legitimate.

Microsoft Word opening isn't suspicious.

Neither is PowerShell.

Nor is a scheduled task.

However, when these activities occur in sequence, they form a recognizable attack chain.

Sequence Analysis helps Threat Hunters reconstruct an adversary's actions instead of evaluating isolated events.

---

## Combining Multiple Techniques

One of the biggest misconceptions about Threat Hunting is believing that a single analytical technique identifies attackers.

In reality, experienced Threat Hunters combine several techniques before reaching a conclusion.

Imagine the following investigation.

A workstation executes **rundll32.exe** for the first time.

Stack Counting identifies it as a rare process.

First-Time-Seen Analysis confirms it has never executed before.

Parent-Child Analysis shows it was launched by Microsoft Word.

Time Delta Analysis reveals the entire execution chain completed within five seconds.

Sequence Analysis shows PowerShell, a scheduled task, and outbound network communication immediately followed.

None of these observations independently prove malicious activity.

Together, they build a compelling investigative narrative.

Threat Hunting is rarely about finding a single suspicious event.

It's about connecting multiple observations until the overall picture becomes clear.

---

## Choosing the Right Technique

Not every investigation requires every analytical technique.

Different questions require different approaches.

| Question | Recommended Technique |
|----------|----------------------|
| What changed compared to yesterday? | Baselining |
| Which events occur most frequently? | Frequency Analysis |
| Which events are rare? | Stack Counting / Rarity Scoring |
| Which systems behave differently? | Clustering |
| Which users differ from similar users? | Peer Comparison |
| Which events occurred unusually quickly? | Time Delta Analysis |
| Which processes launched unexpectedly? | Parent-Child Analysis |
| Which files appear randomly generated? | Entropy Analysis |
| Which domains have never been contacted before? | First-Time-Seen Analysis |
| Which activities form an attack chain? | Sequence Analysis |

Experienced Threat Hunters don't memorise techniques.

They understand which technique best answers the investigative question in front of them.

---

## Key Takeaways

Throughout this article, we've explored sixteen analytical techniques that help Threat Hunters reduce millions of security events into a manageable set of meaningful observations.

Some techniques identify changes from normal behaviour.

Others highlight statistical anomalies.

Some focus on relationships.

Others reconstruct complete attack chains.

None of them guarantee the discovery of malicious activity.

Instead, they provide different perspectives on the same data.

The most effective Threat Hunters don't rely on just one technique.

They combine multiple observations, challenge their assumptions, and follow the evidence wherever it leads.

Ultimately, Threat Hunting isn't about writing clever queries or memorising detection rules.

It's about recognising patterns that don't belong.

And that's a skill developed through curiosity, experience, and continuous practice.

---

## What's Next?

By now, we've covered:

- Why Threat Hunting matters
- Where Threat Hunting fits within Security Operations
- The Threat Hunting Data Pipeline
- The Threat Hunting Lifecycle
- Different Types of Threat Hunting
- Data Analysis Techniques used by Threat Hunters

In the next article, we'll move from analysing data to **developing hunting hypotheses**—the starting point of every successful Threat Hunt. You'll learn where hypotheses come from, how to write effective ones, and how mature Threat Hunting teams transform intelligence, anomalies, and attacker behaviour into structured investigations.
