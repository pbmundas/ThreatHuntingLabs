# Threat Hunting Program Models: From Solo Hunter to Enterprise Team

If you've ever wondered how threat hunting actually works inside real companies, here's the thing — it doesn't look the same everywhere. A five-person startup and a global bank both "do" threat hunting, but what that means on the ground is completely different. One might have a single analyst spending a few hours a week poking around logs. The other might have a 24/7 team spread across three continents.

So let's walk through how threat hunting programs actually grow, from one curious person to a full-blown enterprise operation.

## Stage 1: The Solo Hunter

Every hunting program starts somewhere, and honestly, it usually starts with one person.

This is the security analyst who got tired of just reacting to alerts and started asking, "wait, what if something's already inside and we just haven't noticed?" So they start digging — maybe an hour here, an afternoon there, whenever things are quiet.

There's no formal process. No dedicated budget. It's mostly curiosity and a gut feeling that alerts alone aren't catching everything. The tools are whatever's already available — SIEM queries, some open-source scripts, maybe a spreadsheet to track findings.

It's scrappy, but it works surprisingly well for small organizations. The downside? It depends entirely on one person's time and skill. If they're busy, hunting doesn't happen. If they leave, the whole thing disappears with them.

## Stage 2: Embedded Hunting

As things grow a bit, hunting doesn't get its own team yet — instead, it gets embedded into existing roles. A few analysts on the SOC (Security Operations Center) team get told, "spend 20% of your time hunting instead of just triaging alerts."

This is actually a pretty common and practical middle step. The people already know the environment, they already understand the logs and the tools, so there's no learning curve. The tricky part is that hunting always competes with the "urgent" stuff — a real incident always wins over proactive hunting. So hunting quality can be inconsistent depending on how busy the SOC is that week.

## Stage 3: Hunt Rotations

Once an organization takes hunting a bit more seriously, they often set up **rotations**. Instead of hunting being an afterthought, specific analysts get scheduled time — say, one week a month — where their *only* job is hunting. No tickets, no alert queues, just hunting.

This does two good things. First, it protects hunting time from getting swallowed by daily firefighting. Second, it spreads hunting knowledge across the whole team instead of it living in one person's head. Everyone gets a turn, everyone builds the skill.

The challenge here is consistency — different people hunt differently, so you need decent documentation and playbooks so quality doesn't swing wildly from one rotation to the next.

## Stage 4: Tiger Teams

Now we get into bigger territory. A **tiger team** is a short-term, focused group pulled together for a specific hunting mission — say, "we think there's a supply chain compromise, let's dig deep for two weeks."

Tiger teams aren't permanent. They're assembled, they hunt hard on a specific hypothesis or threat, and then they disband and everyone goes back to their regular roles. Think of it like a strike team, not a standing army.

This model is great for handling specific, high-stakes situations — like a new vulnerability just dropped, or a threat intel report suggests you might be targeted. It's flexible and can move fast. The catch is that it's reactive by nature; it's not built for the slow, ongoing hunting that catches things nobody was specifically looking for.

## Stage 5: Dedicated Hunt Team

This is where hunting becomes a real program, not a side activity. A **dedicated team** means people whose full-time job is hunting — nothing else. No alert queues, no rotations pulling them away.

This is a big investment, so it usually only makes sense once an organization has enough size, enough data, and enough leadership buy-in to justify it. But the payoff is real: consistent methodology, deep expertise, and hunters who can build long-term knowledge of the environment instead of relearning it every rotation.

The tradeoff is cost and headcount — not every organization can justify a full-time hunting team, especially smaller ones.

## Stage 6: MDR Hunt Services (Outsourced Hunting)

Not every company wants to — or can — build an internal team. That's where **MDR (Managed Detection and Response)** providers come in. These are external companies that hunt on your behalf, using their own analysts and tools, often across many customers at once.

This is a solid option for organizations that don't have the size or budget for an internal program but still want proactive hunting happening. The provider brings experience from hunting across tons of different environments, which can actually be an advantage — they've seen patterns you haven't.

The downside is that outside hunters don't know your environment as intimately as your own team would. There's also a dependency on trusting a third party with sensitive access and data.

## Stage 7: Enterprise-Wide Hunting Operations

At the very top end, you get large, multi-team hunting operations — the kind you'd see at massive global companies. This usually means:

- Multiple dedicated teams across regions or business units, following the sun so hunting never really stops
- Their own threat intelligence feeding directly into hunting hypotheses
- Custom tooling built specifically for their environment
- Clear program ownership, metrics, and reporting up to leadership
- Tight integration with incident response, detection engineering, and red teams

This is the full maturity model — hunting isn't a nice-to-have anymore, it's baked into how the security organization runs.

## Who Actually Owns the Program?

This part trips a lot of organizations up. Threat hunting can live in a few different places:

- **Under the SOC** — makes sense since hunters need to work closely with detection and response
- **Under Threat Intelligence** — good if hunting is driven heavily by intel and hypotheses
- **As its own standalone function** — reporting directly to a CISO, common in mature programs

There's no single right answer. What actually matters is that someone clearly owns it, so it doesn't quietly become "everyone's job" — which usually means it becomes nobody's job.

## The Bottom Line

Threat hunting doesn't need to start big. In fact, most great hunting programs started with one curious analyst asking uncomfortable questions about their own environment. What matters is recognizing which stage you're at, and having a real plan for how you grow from there — instead of staying stuck in "one person hunting when they get time" forever.

Whether you're a five-person startup or a Fortune 500, the same basic idea holds: hunting is what happens when you stop waiting for alerts and start actively looking for what they might be missing.
