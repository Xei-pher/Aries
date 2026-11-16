# Aries v0.5.0 — Windows Developer Preview

Aries is a local-first Windows forensic investigation console. It accepts disk images, memory captures, EVTX, registry hives, Prefetch, archives, scripts, text exports, and other loose artifacts; runs deterministic forensic processing; uses one configured model for bounded evidence-led synthesis; and produces a case workspace, cited answers, timeline, findings, and Markdown report.

**Release status:** developer preview. Use Aries to accelerate and document analysis, not as a substitute for analyst validation. The Windows web service binds to localhost and has no authentication or TLS. Do not expose port 8787 to a network.

## v0.5 highlights

- Unresolved high-priority leads block Ready status only when durable case state ties them to an analyst question or active finding. Historical residual uncertainty remains disclosed without making every report permanently partial.
- Analyst answers that claim causality or one attack chain must cite separate bridge evidence. Whole raw EVTX citations generate a precision warning in favor of parsed row-level evidence.
- Repeated findings are merged, and titles are normalized when a proposed confirmed claim is downgraded.
- The material lead queue is capped at 12 and the targeted timeline at 2,000 rows/200 rows per lead by default.
- The single-model pass is capped at 18 iterations, 15 minutes, 36 observable API calls, 4 million observable tokens, or an estimated US$5—whichever observable limit is reached first.
- Windows installation, privacy, security, contribution, platform-support, and GitHub publication guidance are included.

## Windows installation

Prerequisites: Windows 10/11 x64, PowerShell 5.1+, Python 3.10–3.12, Git (for publishing), and a working Hermes CLI. Install 7-Zip for RAR/7z evidence. Eric Zimmerman tools under `C:\Tools` are optional but strongly recommended for broad Windows-artifact coverage.

1. Download and extract the release ZIP to a temporary folder.
2. Open PowerShell in that folder.
3. Run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Install-Aries.ps1
```

4. Configure the single Aries model when prompted or run `hermes -p aries setup`.
5. Run `C:\Aries\Test-Aries.ps1` and resolve any failed required capability.
6. Launch `C:\Aries\Start-Aries-Web.ps1`, then use `http://127.0.0.1:8787`.

Existing users should stop every live investigation and run `Update-Aries.ps1` from the extracted v0.5 folder instead. The updater preserves `C:\Aries\cases`, `.venv`, and local configuration.

## Start the web console

After installing or updating Aries:

```powershell
C:\Aries\Start-Aries-Web.ps1
```

The console opens at `http://127.0.0.1:8787` and provides:

- case creation and large artifact upload;
- evidence registration and hashing through the existing Aries engine;
- one-click autonomous investigation through the `aries` Hermes profile;
- phase status, lead, finding, timeline, and report views;
- evidence-grounded case questions through the Aries assistant;
- Markdown report and compact case-review bundle downloads.

The server binds to localhost by default. Do not expose it to another network until authentication, TLS, role-based access, and deployment hardening are added.

## Architecture boundary

The web interface is a control plane. Volatility, Dissect, Zimmerman tools, source evidence, model credentials, and case outputs remain under `C:\Aries` on the Windows forensic workstation. The hosted interface preview contains demonstration data only and cannot receive evidence.

v0.4.1 adds real large-file upload telemetry (bytes, percentage, speed, ETA, final SHA256 stage, cancellation) and shows the resolved Hermes primary model in the sidebar.

v0.4.2 uses Hermes' stable top-level `-z` scripted interface for web investigations and case-assistant questions. This avoids the version-specific `chat --oneshot --query-file` flags. It also fixes the New Case dialog so its close and cancel controls never trigger form validation.

v0.4.3 adds confirmed destructive case deletion, a collapsible live activity/terminal drawer, per-case web audit records, Hermes usage/cost capture, and a redacted AI session export after each completed run. It also tightens false-positive controls: every confirmed finding needs exact existing evidence references and two independent families; malicious confirmation without a direct classification/behavior signal requires three independent families; known context and distant historical activity cannot be bypassed with vague narrative linkage.

v0.4.4 makes investigation startup observable. Run Investigation opens the activity drawer immediately, fast Hermes CLI/profile/auth failures are surfaced on the case page, and later unexpected exits preserve the actual log tail instead of becoming a generic interrupted state. Download diagnostics creates a small support ZIP containing version/model metadata, case state, audit records, and execution logs while excluding source evidence and bulk parsed artifacts.

v0.4.5 adds an analyst-controlled Stop action that terminates the coordinator and its child process tree, marks in-progress phases interrupted/resumable, and immediately unlocks case deletion. The activity drawer now refreshes every second from an append-only command audit. Coordinator, preflight, Volatility, Dissect, EvtxECmd, and loose-artifact commands appear when launched and record their completion, return code, and duration. Common command-line secret values are redacted.

v0.4.6 repairs the independent-review handoff exposed by the CaseTest diagnostic run. Reviewer packets are capped at roughly 8,000 estimated tokens instead of 30,000 and are embedded in one role-specific delegate envelope with a native dynamic JSON Schema. A child receives everything inline and must make zero tool calls. Invalid, timed-out, iteration-exhausted, or schema-invalid child work is recorded as a failure and cannot be repaired or impersonated by the parent. Placeholder provenance such as `none` is rejected. The web model display also resolves the actual configured model instead of accidentally showing the provider base URL.

v0.4.7 closes two follow-on gaps. Both reviewers must now cover exactly the same bounded lead and finding IDs; incomplete, duplicate, or out-of-scope review sets are rejected before merge, preventing large numbers of artificial `single_reviewer` blockers. The updater refuses to modify Aries during a live investigation and safely stops a verified stale Aries web listener before copying files. The launcher refuses to start when port 8787 is already serving another version, so an old in-memory server can no longer silently survive an update.

v0.4.8 removes delegated review from the critical path. The normal workflow uses one primary model and proceeds from targeted timeline directly to deterministic evidence assessment, IOC review, and reporting. Existing review artifacts remain available for audit, but missing, stale, failed, or disagreeing reviewers cannot block the report. The strict evidence controls remain: exact references, corroboration thresholds, context handling, temporal linkage, overclaim checks, and unresolved high-priority lead gates.

v0.4.9 gives every registered case a persistent case assistant backed by a local searchable forensic data lake. Parsed outputs, timelines, leads, findings, IOCs, case context, investigation briefs, and reports are indexed per case; raw evidence and other cases are excluded. Questions automatically refresh the index, retrieve bounded evidence excerpts, and require exact file-and-line citations. Assistant history remains with the case. Run Investigation now opens an optional analyst brief for scope, known facts, exclusions, context, and required questions; the brief is saved, audited, passed to the investigation, and available to the assistant.

v0.4.10 hardens the case assistant after a Windows index-build failure. The data lake now uses SQLite FTS5 when available, automatically falls back to an ordinary SQLite text index when FTS5 is unavailable, rebuilds a damaged/stale database once, and finally uses a bounded direct-text search rather than returning an unexplained HTTP 500. Concurrent first questions share a per-case build lock, and retrieval failures are written to the case audit. The default disk baseline now parses ShellBags, RecentDocs, Jump Lists, and LNK files so local-versus-network document access is not inferred from Prefetch alone. The evidence gate blocks local/network-location conclusions that lack a path-bearing access artifact.

v0.4.11 repairs the BSides case workflow. Upload containers no longer inflate evidence-source counts; old affected cases migrate automatically. Every explicit analyst question or requested deliverable is tracked in structured case state, requires an evidence-cited answer or an explicit limitation, and is rendered into the final report. Report readiness now requires the current evidence assessment, an actual report file, and a completed report phase; the web service can reconcile a ready assessment and finish the report when a model session reaches its tool limit. Ask Aries now sends a compact Windows-safe prompt, and material-lead counts/report tables exclude medium/low noise.

v0.4.12 makes the final evidence assessment a quality classification instead of a report-generation lock. Aries always produces a report after assessment: fully satisfied cases are Ready, while incomplete cases are Review required and list unanswered requests, unresolved leads, and other limitations. The pipeline can therefore reach 100% even when a free model ends without a final response or is temporarily unavailable. Reports remain resumable. Recursively derived single-source entities no longer hard-block reporting, and new pivot children start at medium priority until independently corroborated.

v0.4.13 separates deterministic evidence processing from model analysis. One-click investigation now completes resumable parsing first, then starts one bounded model pass over the ready case outputs whose explicit job is to save analyst-question answers and adjudicate material leads. Assessment and report generation always rerun afterward, even if the provider is unavailable. The dashboard labels the percentage as Processing and shows unresolved analyst-request counts so 100% processing is never presented as 100% analytical completion. Case-assistant index builds also use unique staging files so an interrupted Windows `.building` lock does not repeatedly force degraded retrieval.

v0.4.14 closes the broad-brief synthesis gap exposed by the Victim case. Prose requests now become durable investigative and report/timeline requirements, and an incident case cannot become Ready merely because every lead was closed. Observed download, execution, network, detection, and transfer behaviors remain reportable without forcing a confirmed-malicious label. The validator rejects Compatibility Assistant registry writes as timestomping proof and catches Sysmon Event ID 15 misinterpretation. Defender Event 5007 configuration changes no longer seed detection leads, duplicate lead updates are suppressed, and an already-ready case requires a changed brief before another model run.

v0.4.15 makes reporting the guaranteed output instead of the reward for clearing every gate. Model/provider failure now produces a clearly labeled partial report containing deterministic answers, case evidence candidates, parser coverage, leads, and limitations. Evidence hashes are answered without a model. Unrelated open leads are advisory rather than report blockers. The model pass is explicitly report-first, and a partial case exposes **Retry AI synthesis**, which reuses all completed forensic processing instead of rerunning parsers. Processing completion, report availability, and AI synthesis completion are tracked separately.

v0.4.16 makes archive and script evidence genuinely first-class. ZIP/TAR archives are safely extracted internally; RAR/7z uses an available 7-Zip backend. Paths, links, member counts, individual sizes, and total expanded size are bounded before analysis. Extracted content is never executed. Extensionless files are classified from their bytes, so a PowerShell script named `sample` is still recognized, copied into indexed case output with stable line citations, and routed to static triage. Artifact-only cases skip empty EVTX phases, and AI synthesis has a 20-minute hard deadline so a provider/tool loop cannot leave a case running forever.

v0.4.17 fixes Windows RAR members whose preserved archive metadata makes `Path.stat()` fail even though the file is readable. Static analysis now derives member size and SHA256 directly from bounded bytes and uses 7-Zip's validated member inventory instead of stat-walking the extraction directory. A failed artifact baseline is now a hard processing failure, its exact reason appears in diagnostics and evidence assessment, and **Retry artifact processing** reruns the parser plus only its dependent phases instead of wasting another model-only attempt.

---

# Aries v0.3.4 — Single-Model DFIR Engine

Aries is a focused Windows DFIR agent built as an isolated Hermes profile. It analyzes complete evidence sets with Dissect, Volatility 3, and locally installed Eric Zimmerman tools under `C:\Tools`.

For a one-model configuration, see `MODEL-SETUP-OPENAI.md` or `MODEL-SETUP-CLAUDE.md`.

The experimental orchestration implementation is retained only for optional second-opinion testing and is not part of the default workflow.

Disk images and memory captures are optional. Aries accepts artifact/triage folders and individual EVTX, registry hives, ShellBags, Prefetch, Amcache, SRUM, MFT/USN, LNK/Jump Lists, WebCache, browser databases, archives, and text-based forensic outputs.

## What changed in v0.3.4

The required two-reviewer checkpoint was removed. Aries now uses one primary model, while deterministic evidence assessment remains the final report gate. This removes provider-dependent waiting, provenance handoff failures, reviewer disagreement churn, and doubled model cost without weakening artifact-based standards.

## v0.3.3 cost controls retained

### Bounded context and cost controls

The parent now runs deterministic phases through `investigate.py --all --concise`: full command output is written to `output\logs`, while only a bounded operational summary enters model context. Event/artifact/pivot triage keeps at most 24 active high/critical leads in the material queue; overflow is retained as a medium-priority backlog with an audit record.

High-priority lead queues and model-visible phase output remain bounded. Full command output is written to case logs. Deterministic evidence assessment controls whether the report is labeled Ready or Review required; unresolved work remains visible and resumable.

---

## v0.3.0 evidence-set foundation retained

### 1. Evidence sets replace the E01/memory-only intake model

`investigate.py --evidence` now registers files and directories as first-class evidence. Artifact discovery inventories loose sources recursively, hashes directories per file, and routes only applicable phases. A ShellBag challenge folder no longer falls outside the case workflow.

### 2. Loose-artifact parser routing

New `run_artifact_baseline.py` routes supported loose artifacts to RECmd/SBECmd, PECmd, AmcacheParser, SrumECmd, MFTECmd, LECmd, JLECmd, RBCmd, or WxTCmd. Browser/WebCache, archive, text, and unknown artifacts remain inventoried and searchable without being executed.

### 3. Recursive pivots

`pivot.py` follows newly derived entities for up to three bounded hops by default, records independent artifact families, and tracks unresolved/single-source leads. It no longer stops at the first layer of matches.

### 4. Evidence discipline and report gate

New `evidence_assessment.py` checks open high-priority leads, exact evidence references, independent corroboration, attribution/capability overclaims, ATT&CK mappings without behavior, and unsupported temporal linkage. Reports with blocking issues are explicitly labeled draft.

Confirmed malicious, attribution, and capability claims now carry structured evidence references, artifact families, observed behavior, ATT&CK mappings, incident clusters, and limitations. High-impact claims without enough independent corroboration are downgraded from confirmed to inference.

### 5. v0.2.2 behavior remains

Event-first triage, context records, retractable findings, partial phase states, targeted timelines, bounded IOC scanning, and the project self-modification guard are retained.

---

## v0.2.2 foundation retained

The following sections describe the event-led foundation introduced in v0.2.2 and retained in v0.3.

### 1. Event logs moved to the front

Old default order:

`disk baseline -> huge disk timeline -> memory -> artifact discovery -> event logs`

v0.2.2 default order was:

`preflight -> hash -> artifact discovery -> event logs -> event triage -> memory -> disk baseline -> pivots -> targeted timeline -> IOC review -> report`

`disk_timeline` remains available but is optional and explicit.

### 2. Richer event-log coverage

`artifact_discovery.py` now inventories all EVTX files and assigns telemetry tiers.

Tier 1 (always highest priority when present):
- Sysmon Operational
- Windows Defender Operational
- PowerShell Operational
- Security
- System
- Application

Tier 2 (automatically parsed subject to a safety cap):
- Task Scheduler
- WMI Activity
- Terminal Services / RDP
- WinRM
- BITS
- Firewall
- SMB
- DNS Client
- AppLocker
- Code Integrity
- Group Policy
- related high-value operational channels

Tier 3 remains inventoried for on-demand pivots.

### 3. Lead registry

New file:

`C:\Aries\cases\<case>\leads.jsonl`

A lead is an investigation seed, not a malicious verdict. Leads have IDs such as `L-0001`, type, value, score, priority, source, status, context matches, and parent/child relationships.

### 4. Automatic event triage

New script:

`scripts\event_triage.py`

It reviews parsed event logs and seeds leads from high-signal telemetry such as:
- Defender detections/actions
- Sysmon/Security process creation
- interesting Sysmon network/DNS events
- suspicious PowerShell logging
- service installation
- scheduled task changes
- account/group changes

The triage output is:

`output\event_triage.json`

### 5. Pivot engine

New script:

`scripts\pivot.py`

For each high-priority active lead, Aries searches high-value event, disk, and memory outputs for corroborating occurrences and related entities.

Outputs:

`output\pivots\L-0001\hits.jsonl`
`output\pivots\L-0001\pivot-plan.json`
`output\pivots\pivot-summary.json`

Repeatedly co-observed hashes/IPs/files/domains can become child leads.

### 6. Targeted timeline

New script:

`scripts\targeted_timeline.py`

Instead of generating multi-gigabyte whole-disk timelines by default, Aries builds a chronology only around active lead hits.

Outputs:

`timeline\targeted_timeline.csv`
`timeline\targeted_timeline.md`

The broad Dissect MFT/USN/SRUM timeline remains available with:

`investigate.py --case CASE --phase disk_timeline`

### 7. Context-aware case state

New file:

`case_context.json`

The analyst/agent can explicitly record known training activity, evidence acquisition, known-good activity, analyst activity, or environment context.

Example:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\case.py context-add `
  --case victim `
  --type training `
  --value "course_files" `
  --details "Known legitimate security-course material" `
  --source "analyst clarification" `
  --confidence high
```

### 8. Retractable findings

Findings now get stable IDs (`F-0001`, ...). They are audit-history records rather than disposable lines.

If Aries made a bad interpretation:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\case.py finding-retract `
  --case victim `
  --id F-0001 `
  --reason "Analyst confirmed this was legitimate training activity"
```

The report separates active findings from retracted/superseded ones.

### 9. Partial phase state

Phase execution now distinguishes:
- complete
- partial
- waiting (optional/manual phase awaiting input)
- degraded (optional/manual phase completed with reduced coverage)
- blocked (evidence/report gate stopped unsafe finalization)
- failed
- skipped
- interrupted

A Volatility run with 8/9 successful plugins is `partial`, not silently `complete`.

### 10. Targeted IOC scanning

IOC candidate scanning no longer automatically reads giant whole-disk timeline files. It focuses on high-value parser outputs, pivot output, and targeted timeline material, with a per-file size cap.

### 11. Project self-modification guard

During case work Aries is instructed to write only under:

`C:\Aries\cases\<case>\`

It should not create ad-hoc project scripts such as `C:\Aries\run_investigation.py` or edit the framework while investigating.

---

## Default v0.3.4 investigation phases

1. `preflight`
2. `evidence_integrity`
3. `artifact_discovery`
4. `eventlog_baseline`
5. `event_triage`
6. `artifact_baseline`
7. `artifact_triage`
8. `memory_baseline`
9. `disk_baseline`
10. `pivot`
11. `targeted_timeline`
12. `evidence_assessment`
13. `ioc_scan`
14. `report`

Optional:

15. `disk_timeline`

Each ordinary call to `investigate.py` runs one unfinished phase and returns the next phase so Hermes can inspect results/leads between long-running operations.

---

## Upgrade from v0.3.1 / earlier

Extract this release somewhere temporary and run PowerShell from inside the extracted directory:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Update-Aries.ps1
```

The updater preserves:
- `C:\Aries\.venv`
- `C:\Aries\cases`
- `C:\Aries\config`
- `C:\Tools`

It updates project scripts/instructions, repairs the Aries Hermes skill/profile files, refreshes the local tool inventory, and runs the health check.

Existing cases are migrated in place when loaded. Completed parsing/pivoting work is preserved. Waiting or failed review phases become skipped, while only assessment/report phases previously blocked by review are reset.

---

## Clean test recommended

For the victim evidence used during v0.2 testing, remove only the old Aries case directory if you want a true clean comparison:

```powershell
Remove-Item "C:\Aries\cases\victim" -Recurse -Force
```

Do **not** delete the original evidence.

Start Aries:

```powershell
C:\Aries\Start-Aries.ps1
```

Give it a natural request such as:

> I have an E01 at E:\Evidence\victim.E01 and a memory dump at E:\Evidence\memory.raw. Please investigate this case for malicious indicators and write an incident-response report with a timeline of significant events.

Do not initially tell it about `CrackedSoftware.exe`, Sysmon, Defender, or pivoting. We want to measure whether v0.3.4 performs the entire workflow from one natural request.

If it misclassifies known course/acquisition activity, correct it naturally. Aries should now record your clarification as case context and retract affected findings rather than merely appending contradictory conclusions.

---

## Create a small review bundle to send back

After the test finishes, create a compact ZIP containing case state, leads, findings, context, parser manifests, targeted timeline, and report — but **not** the E01/memory evidence or extracted binaries:

```powershell
C:\Aries\Export-Aries-Review.ps1 -Case victim
```

It writes a file similar to:

`C:\Aries\Aries-victim-review-YYYYMMDD-HHMMSS.zip`

That ZIP is the easiest artifact to send for the next review.

---

## Useful manual developer/analyst commands

Case status:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\case.py status --case victim
```

List active leads:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\case.py lead-list --case victim
```

Run/re-run pivoting:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\pivot.py --case victim
```

Regenerate targeted timeline:

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\targeted_timeline.py --case victim
```

The old orchestration command remains experimental and is intentionally omitted from the normal operator workflow. It is not required to complete a case.

Explicit whole-disk timeline (optional):

```powershell
C:\Aries\.venv\Scripts\python.exe C:\Aries\scripts\investigate.py --case victim --phase disk_timeline
```

---

## Main project files

- `AGENTS.md` — project operating rules for Aries
- `profile\SOUL.md` — Aries identity and core boundaries
- `skills\aries-dfir\SKILL.md` — DFIR workflow/investigation guidance used by Hermes
- `scripts\investigate.py` — resumable phase coordinator
- `scripts\case.py` — case/evidence/findings/leads/context/IOC/report manager
- `scripts\common.py` — shared phase/case logic and v0.2 migration
- `scripts\artifact_discovery.py` — disk artifact + EVTX inventory/tiering
- `scripts\run_ez_baseline.py` — Tier 1/2 EvtxECmd extraction/parsing
- `scripts\run_artifact_baseline.py` — loose-artifact routing/parsing
- `scripts\static_artifact.py` — safe archive extraction, extensionless text/script classification, and line-preserving static output
- `scripts\artifact_triage.py` — cautious loose-artifact lead seeding
- `scripts\event_triage.py` — high-signal event triage and lead seeding
- `scripts\run_volatility.py` — memory baseline
- `scripts\run_dissect.py` — disk baseline and optional broad timeline
- `scripts\pivot.py` — bounded recursive cross-source lead correlation
- `scripts\targeted_timeline.py` — lead-centered timeline
- `scripts\orchestration.py` — experimental optional second-opinion protocol; not used by default
- `scripts\records.py` — append-only finding/lead/context state helpers
- `scripts\evidence_assessment.py` — corroboration/contradiction/report-readiness gate
- `scripts\case_datalake.py` — case-scoped parsed-evidence indexing and cited retrieval for the assistant
- `scripts\web_workflow.py` — deterministic processing → bounded model analysis → final assessment/report sequencing
- `scripts\run_eztool.py` — generic Zimmerman tool adapter
- `scripts\extract_from_image.py` — safe artifact extraction from E01
- `scripts\tool_inventory.py` — scans `C:\Tools`
- `scripts\preflight.py` — capability/dependency check

---

## What v0.5.0 is not yet

The current web alpha is a local control plane, not yet a multi-user forensic data-lake platform. It has local artifact upload, case views, a case-scoped SQLite evidence index, an AI assistant, and one-click report access, but it does not yet provide authentication, centralized cross-case search, distributed workers, or hardened remote deployment.

The current case directory remains deliberately simple JSON/CSV/text/file output while the local workflow is stabilized.

ZIP and TAR support is built in. RAR and 7z require `7z.exe`/`7zz.exe`; the health check reports whether that optional backend is available. Password-protected archives are reported as unresolved rather than guessed or executed.
