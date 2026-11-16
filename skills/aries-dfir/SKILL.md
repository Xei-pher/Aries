---
name: aries-dfir
description: Artifact-adaptive, recursive, resumable Windows DFIR evidence-set investigation with Volatility, Dissect, and EZ Tools
version: 0.3.4
platforms: [windows]
metadata:
  hermes:
    tags: [dfir, forensics, incident-response, volatility, dissect, eztools, sysmon, eventlogs]
    category: security
    requires_toolsets: [terminal, file]
---
# Aries DFIR v0.3.4

## Principle

**A suspicious artifact is the beginning of an investigation, not the end of one.**

Register the supplied evidence immediately. Disk and memory are optional. Artifact folders and individual hives, EVTX, Prefetch, Amcache, SRUM, MFT/USN, LNK/Jump Lists, browser artifacts, archives, and text-based forensic outputs are valid evidence sets.

When event telemetry exists, follow it early. Otherwise route the available artifacts to their parsers. Never wait for a huge whole-disk timeline before examining higher-signal evidence.

For archives, use the deterministic safe static route. Never execute recovered content and never trust filename extensions as the only type signal. ZIP/TAR is extracted internally; RAR/7z requires 7-Zip. Review `output/artifacts/.../static-analysis.json` and the line-preserving `content/*.txt` copies. Record encrypted, unsupported, or rejected archive contents as explicit coverage gaps.

## Start / resume

Start from evidence:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/investigate.py --evidence "E:\Evidence\Case01" --mode quick --all --concise`

Separate evidence:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/investigate.py --evidence "E:\Evidence\disk.E01" --evidence "E:\Evidence\memory.raw" --mode quick --all --concise`

Artifact folder:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/investigate.py --evidence "E:\Evidence\Baggage" --mode quick --all --concise`

Resume all remaining deterministic phases in one bounded call:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/investigate.py --case CASE --mode quick --all --concise`

In the Hermes terminal always use native `C:/Aries/...` paths. Never translate them to `/c/Aries/...`.

Check status:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/case.py status --case CASE`

## Default phase order

1. preflight
2. evidence_integrity
3. artifact_discovery
4. eventlog_baseline
5. event_triage
6. artifact_baseline
7. artifact_triage
8. memory_baseline
9. disk_baseline
10. pivot
11. targeted_timeline
12. evidence_assessment
13. ioc_scan
14. report

Whole-disk `disk_timeline` is optional:

`investigate.py --case CASE --phase disk_timeline`

Do not generate it automatically unless broad chronology is necessary.

## Event logs

Artifact discovery inventories all EVTX files and assigns tiers.

Automatic baseline parses Tier 1 and Tier 2 channels with EvtxECmd. Tier 1 includes Sysmon, Defender, PowerShell, Security, System, Application. Tier 2 includes high-value channels such as TaskScheduler, WMI Activity, RDP/Terminal Services, WinRM, BITS, Firewall, SMB, DNS Client, AppLocker, CodeIntegrity, and Group Policy when present.

After event parsing, `event_triage.py` creates **leads**, not findings.

## Leads and pivoting

List leads:

`case.py lead-list --case CASE`

Seed a manual lead when the analyst identifies one:

`case.py lead --case CASE --type process --value "CrackedSoftware.exe" --priority high --score 80 --source "analyst" --reason "Needs cross-source investigation"`

Run bounded recursive pivot engine:

`C:/Aries/.venv/Scripts/python.exe C:/Aries/scripts/pivot.py --case CASE`

For process/file/hash leads, pivot across:
- Sysmon process/network/DNS/file/registry events
- Defender detections/actions
- Security process/audit events
- PowerShell
- Prefetch
- Amcache
- ShimCache
- UserAssist
- Volatility process/cmdline/network/malfind output

For IP/domain/URL leads, pivot across:
- Sysmon network/DNS
- Firewall/DNS Client
- browser/download artifacts
- SRUM
- memory netstat/netscan
- related processes and downloads

Do not stop after one match. Ask what created it, executed it, connected to it, and what happened immediately before/after. Follow child leads automatically for up to three hops by default.

Prioritize high-priority leads that materially affect the requested report and disposition them as confirmed, benign, contextual, false positive, or unresolved with a specific reason and structured evidence or recorded-context basis. Other open leads remain disclosed limitations and do not prevent report delivery. Never bulk-close leads merely to change a status. Every confirmed finding needs at least two independent artifact families and exact existing evidence references. Confirmed malicious status additionally needs direct malicious classification/binary or memory behavior plus corroboration, or three genuinely independent artifact families. Recorded benign/training/admin context must be explicitly resolved with evidence before confirmation. Distant activity needs both an incident-cluster label and exact bridge evidence.

The confirmed-malicious threshold is not a suppression rule. Record directly observed downloads, executions, network connections, detections, crashes, transfers, and persistence events as factual findings when authoritative evidence supports them. A private/RFC1918 address is not benign merely because it is private. Closing all leads does not complete an incident investigation: synthesize each material cluster into findings or record an evidence-cited no-incident conclusion. Compatibility Assistant/AppCompat registry writes are not timestomping proof, and Sysmon Event ID 15 is FileCreateStreamHash rather than FileCreateTime.

## Targeted timeline

`targeted_timeline.py` builds a chronology from active lead correlations. Prefer this over a giant whole-disk timeline during normal triage.

## Single-model workflow

The normal investigation uses one primary model. Do not delegate, spawn reviewer children, or run `orchestration_review` during the default workflow. After the targeted timeline, the primary model must adjudicate material leads from exact evidence and then run the deterministic evidence assessment.

`orchestration_review` remains an experimental optional phase for later second-opinion work. It is not part of the default phase order, never counts as forensic evidence, and never blocks evidence assessment or final reporting.

## Case context / corrections

When the analyst clarifies legitimate training, acquisition, known-good, or admin activity, record it immediately:

`case.py context-add --case CASE --type training --value "course_files" --details "Known legitimate course material" --source "analyst clarification" --confidence high`

If Aries already recorded an incorrect finding, retract it:

`case.py finding-retract --case CASE --id F-0001 --reason "Analyst established this was training activity"`

Then reset/rerun affected phases as appropriate:

`case.py reset-phase --case CASE --phase event_triage`
`case.py reset-phase --case CASE --phase pivot`
`case.py reset-phase --case CASE --phase targeted_timeline`
`case.py reset-phase --case CASE --phase report`

## Analyst brief and case assistant

When the web console supplies an analyst brief, use it to prioritize scope and explicitly answer requested questions and deliverables. The console converts questions, imperative requests, and report/timeline requirements into `analyst-questions.json`. Before evidence assessment, record each answer with `case.py answer --case CASE --id Q-001 --status answered --answer "..." --confidence high --evidence-ref output/path.txt`. Repeat the evidence option when appropriate. If the answer claims one artifact caused, installed, dropped, staged, or belongs to the same attack chain as another, add the exact proof with `--bridge-evidence-ref`; timing alone is not proof. Prefer parsed row-level output over a whole EVTX citation. If the case cannot answer a requirement, record `--status unresolved --limitation "..."`; never leave requested requirements pending or put answers only in the final chat response. Save durable known-good/training/admin/acquisition statements as case context. The brief never weakens evidence or safety requirements.

Record each supported answer and each material lead disposition immediately after validation. Never postpone all `case.py answer` or `lead-close` operations until the end of the session. Prefer existing parsed output and targeted queries, and stay within the configured model-iteration budget.

The web case assistant uses `case_datalake.py` to retrieve bounded excerpts from the active case's parsed evidence. It is read-only. It must use only the supplied case packet, cite exact supplied `path:Lx-Ly` references, distinguish observation from inference, and disclose missing evidence. Never access another case, raw source evidence, extracted binaries, or the network to answer a case question.

## Findings

Record only after evidence review:

`case.py finding --case CASE --kind observation|hypothesis|inference|confirmed ...`

- observation = artifact directly shows it
- hypothesis = worth testing
- inference = evidence supports interpretation
- confirmed = sufficiently corroborated

Confirmed malicious, attribution, and capability claims require exact evidence references and at least two independent artifact families. Attribution requires stronger linkage than a remote account/IP/session alone. Capability claims require observed behavior or binary/memory analysis. ATT&CK mappings require observed behavior.

Use separate incident clusters for temporally distant activity. Merge clusters only when a shared entity, process lineage, account/session, infrastructure, persistence mechanism, or other explicit bridge connects them.

Run `evidence_assessment.py --case CASE` before finalizing. Treat its issues as a completeness and overclaim checklist. `case.py report` always writes either a complete report or a clearly labeled partial report with unresolved requirements, evidence candidates, and limitations. Do not write `report.md` manually. When a provider fails, preserve checkpoints and let the deterministic report stage finish.

Legitimate remote access is not automatically malware. Upload direction must be verified. Listening sockets are not outbound C2. Security-course tooling is not current incident activity without linkage.

## Partial phases

Exit code 3 means a phase produced useful data but one or more selected parsers/plugins failed. Aries marks it `partial`, continues, and documents the coverage gap.

## IOC scan

Automatic IOC scan excludes giant whole-disk timeline files and oversized outputs. It focuses on high-value parsed evidence, pivots, and the targeted timeline.

## Safety / project guard

- Never execute recovered files.
- Never modify source evidence.
- Export only into the case workspace.
- During investigation, do not create/modify Aries project-level scripts, skills, or framework files. Product development is separate from case work.
- Do not run Hermes verification, pytest, framework health checks, installers, or source-control commands during a case investigation. Stop cleanly when no case-scoped work remains.
