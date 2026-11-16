# Aries Experimental Second-Opinion Guide

> v0.5.0 status: optional and disabled in the default workflow. This protocol is retained for research only. It is not required for evidence assessment, cannot block a report, and should not be used during ordinary one-click investigations.

## The simple explanation

Aries now uses three AI roles during the reasoning stage of an investigation:

1. **Aries lead** owns the case, talks to you, runs the forensic workflow, and is the only role allowed to change official leads or findings.
2. **Investigator reviewer** independently checks whether Aries missed a pivot, relationship, or useful lead.
3. **Skeptical validator** tries to disprove or downgrade Aries' conclusions before they reach the report.

The two reviewers are not additional evidence. They are two independent opinions about the same evidence. A finding is still supported only by real artifacts such as event logs, registry data, Prefetch, memory, MFT/USN, browser history, or other parsed forensic sources.

## Where it happens

The normal sequence is:

`parsing → triage → recursive pivots → targeted timeline → orchestration review → evidence assessment → report`

The expensive forensic tools finish before orchestration begins. Each reviewer receives one self-contained inline packet capped at roughly 8,000 estimated tokens through a native-schema delegate envelope. Reviewers make no tool calls, do not browse case files, and never run another copy of Volatility, Dissect, EvtxECmd, or the Zimmerman tools.

## What happens automatically

When `orchestration_review` runs for the first time, Aries:

1. records a fingerprint of the current reasoning state;
2. creates an internal snapshot and a bounded `review-packet.json` under `output\orchestration\`;
3. creates one investigator task and one validator task;
4. creates a JSON output schema for each task;
5. returns exit code `4`, meaning **waiting for reviews**.

The Aries lead delegates the investigator first. After its response is accepted and given a provenance receipt, Aries delegates the validator as a separate fresh child. Sequential execution reduces provider rate-limit pressure while preserving separate contexts. The validator never receives the investigator response.

The lead saves each returned object to a temporary inbox file and registers it with `orchestration.py --submit-review`, providing the actual delegation ID, child ID, and provider/model. Directly writing the final response paths is rejected. Aries then verifies:

- correct snapshot, task, and role IDs;
- valid JSON structure;
- permitted decision values;
- referenced lead and finding IDs really exist;
- evidence references are case-relative and point to real files;
- each candidate entity occurs in its cited evidence;
- neither response refers to a foreign Aries case path;
- each response has a matching delegated-child provenance receipt;
- the investigator and validator came from distinct child executions;
- neither response attempts to become authoritative case state.

If either response fails validation, the phase stays `waiting` and prints the exact errors. It does not discard the valid response or pretend the review succeeded.

If a child receives a provider error, Aries records the failure instead of fabricating a response. Transient rate limits may be retried after backoff. Billing, exhausted-credit, quota, and authentication failures are non-retryable and immediately mark orchestration `degraded`; three transient failures do the same. Evidence assessment and final reporting remain blocked until a fresh review round succeeds.

## What the merger does

The deterministic merger creates:

`output\orchestration\review-summary.json`

It records:

- reviewer assessments of existing leads;
- accept/downgrade/reject decisions for findings;
- candidate leads;
- contradictions;
- evidence gaps;
- report blockers;
- agreements and disagreements.

It does **not** automatically add leads, close leads, retract findings, or rewrite the report. The lead agent must check the cited evidence and make the authoritative decision.

## Why the lead agent remains in control

Allowing several agents to write the same case files would create race conditions and an unclear audit trail. Aries therefore follows a single-writer rule:

| Role | Read parsed case data | Run heavy parsers | Change leads/findings | Report to user |
|---|---:|---:|---:|---:|
| Aries lead | Yes | Yes, once | Yes | Yes |
| Investigator reviewer | Bounded/read-only | No | No | No |
| Skeptical validator | Bounded/read-only | No | No | No |

## Review-item decisions

Merged items receive IDs:

- `OF-*` — finding review
- `OL-*` — lead review
- `OC-*` — candidate lead
- `OX-*` — contradiction
- `OG-*` — evidence gap
- `OB-*` — report blocker

After examining the evidence, the lead can record:

- `resolved` — the case state was corrected or the concern was otherwise addressed;
- `dismissed` — the suggestion was rejected with an evidence-based reason;
- `deferred` — the issue remains open and may keep the report in draft status.

Example:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\orchestration.py `
  --case victim `
  --resolve OC-EXAMPLE `
  --decision dismissed `
  --reason "The address belongs to the isolated lab network and has no incident bridge."
```

## Stale-review protection

If authoritative leads, findings, triage summaries, pivots, or the targeted timeline change after the reviewers received their snapshot, the old review becomes stale. Evidence assessment will reject it, and Aries will create a new review round rather than relying on an opinion about outdated case state.

Older review rounds remain preserved for auditability.

## What you should see during a test

You give Aries one normal investigation request. Near the end, it should delegate the investigator, register its response, then delegate the validator and register that response. After merging them, Aries should explain any material disagreement and either investigate it, correct the case, or explicitly dismiss it with evidence.

A good result is not “both agents agree.” A good result is:

- a missed important lead is found without your second prompt;
- an unsupported claim is downgraded before the report;
- historical activity stays separate unless a bridge exists;
- fabricated evidence references are rejected;
- the final report explains unresolved limitations;
- the investigation does not repeat heavy parser work.
- the review summary shows real child/model provenance for both roles;
- a rate-limited child never turns into a lead-authored “independent” review;
- unrelated case/task content is rejected rather than entering the report.

## What v0.3.3 deliberately does not include

Historical note: the web interface, browser uploader, case-scoped forensic data lake, case assistant, and one-click report access now exist in v0.4.9. The orchestration protocol described here remains optional research material and is not part of that default web workflow.
