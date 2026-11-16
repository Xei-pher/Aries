# Changelog

## v0.5.0

- Made unresolved-lead gating scope-aware: only high/critical unresolved leads tied to an analyst question or active finding can prevent Ready classification.
- Added causal-link validation for analyst answers with explicit bridge-evidence references and advisory row-level citation precision checks.
- Added deterministic finding deduplication and title normalization after confirmation downgrades.
- Reduced the default material queue to 12 leads and bounded targeted timelines to 2,000 rows with a 200-row per-lead cap.
- Added single-model wall-clock, iteration, API-call, token, and estimated-cost budgets with durable status reporting.
- Added a Windows-first public installation and repository surface, including license, security, privacy, platform support, contribution, third-party, CI, and publishing documentation.

## v0.4.17-web-alpha

- Fixed Windows RAR/7z members that are readable but reject metadata/stat inspection with `OSError: [Errno 22] Invalid argument`.
- Static artifact analysis now reads bounded bytes once and derives size/SHA256 without relying on recovered file timestamps or attributes.
- External archive extraction consumes the validated 7-Zip member list directly and rejects reported links.
- A wholly failed artifact baseline now returns a hard failure and prints each artifact's exact failure reason to the live command log.
- The web console detects parser failure and offers **Retry artifact processing**, resetting only the failed parser and dependent triage/report phases.
- Evidence assessment blocks absence claims when static artifact analysis failed.
- Review and diagnostics ZIPs now include the artifact baseline manifest and `static-analysis.json` metadata, while still excluding recovered content and source evidence.

## v0.4.16-web-alpha

- Added safe ZIP/TAR extraction and optional 7-Zip-backed RAR/7z extraction inside the case workspace.
- Reject archive path traversal, drive-qualified entries, links, excessive member counts, oversized members, and excessive expanded size.
- Classify extensionless loose or archived files by content and recognize PowerShell, batch, Python, JavaScript, and ordinary text without executing recovered content.
- Preserve decoded script content with stable line numbers under `output/artifacts` so model analysis, reports, and the case data lake can cite exact source lines.
- Seed cautious script leads from static classification while keeping detection separate from a malicious verdict.
- Skip empty event-log phases on artifact-only evidence sets.
- Lazy-load Dissect only for actual image evidence so loose-artifact discovery does not depend on an irrelevant disk parser.
- Add a 20-minute hard timeout to bounded AI synthesis; deterministic outputs and saved checkpoints survive timeout.
- Add health-check visibility for the optional RAR/7z backend.


## v0.4.15-web-alpha

- Made report generation unconditional after usable forensic processing; unresolved analysis affects completeness, not report availability.
- Added explicit complete versus partial report states instead of the looping Review-required label.
- Detect model/provider sessions that exit without a completed usage marker and preserve the failure in `analysis-status.json` and the report.
- Added a report-first model contract: answer analyst requirements in order and checkpoint each answer before unrelated lead work.
- Added deterministic evidence-hash answers that do not require an AI provider.
- Added bounded case-data-lake evidence candidates beneath pending report questions when AI synthesis is unavailable.
- Made unrelated open high-priority leads advisory rather than blocking report completion.
- Added **Retry AI synthesis**, which skips completed parsers and reruns only synthesis, assessment, and report finalization.
- Separated processing completion, report availability, and AI synthesis completion in the web UI.

## v0.4.14-web-alpha

- Convert broad prose briefs into durable investigative requirements and report/timeline deliverables instead of extracting only grammatical questions.
- Prevent incident-scope cases from becoming Ready through lead closure alone; require structured incident findings or an evidence-cited no-incident conclusion.
- Preserve directly observed download, execution, network, detection, crash, transfer, and persistence behavior in the report without forcing a confirmed-malicious classification.
- Treat private infrastructure as context-dependent rather than benign by definition when direct process/delivery evidence links it to the incident.
- Block Compatibility Assistant/AppCompat registry writes from being reported as timestomping and validate Sysmon Event ID 15 semantics.
- Restrict Defender detection seeding to Events 1116/1117 and suppress repeated no-op lead history updates.
- Include material observation/inference titles in the executive summary rather than listing only confirmed findings.
- Prevent repeated model runs on an unchanged report-ready case; analysts must add a question or refine the brief.
- Explicitly prohibit model-side framework verification, tests, and source edits during case analysis.

## v0.4.13-web-alpha

- Separated deterministic forensic processing from the model's analytical pass.
- Added a web workflow wrapper that finishes/resumes applicable parsers first, launches one bounded case-analysis session second, and always reruns assessment and report generation last.
- Skip the paid model turn when deterministic processing hard-fails before producing usable outputs; partial coverage and evidence-gate results remain analyzable.
- Changed the model prompt from supervising the full parser pipeline to answering structured analyst questions and adjudicating material leads from already-prepared outputs.
- Persisted the exact analysis prompt alongside the investigation log for audit and diagnostics.
- Kept provider failure from preventing deterministic report regeneration; incomplete cases remain explicitly Review required.
- Renamed the dashboard percentage to Processing and display unresolved analyst-request counts when processing is complete but analysis is not.
- Added command-audit separation between the outer web workflow, deterministic pipeline, bounded analysis, final assessment, and final report.
- Use a unique per-build SQLite staging file for the case assistant so a stale Windows lock on the old `.building` path no longer forces repeated degraded retrieval.

## v0.4.12-web-alpha

- Changed evidence assessment from a report-generation lock into a Ready versus Review-required quality classification.
- Always generate a report after assessment and render every unresolved question, lead, and evidence limitation inside it.
- Added a separate `report_available` state so incomplete reports remain viewable/downloadable without being mislabeled Ready.
- Automatically refresh stale assessments and finish deterministic report output after a model exits, including existing blocked cases.
- Prevented recursively derived, single-source leads from blocking reports without independent corroboration.
- Capped new recursive child leads at medium priority until their own cross-artifact correlation justifies promotion.
- Preserved completed parsing and allowed analysts to resume incomplete analysis later without rerunning forensic baselines.

## v0.4.11-web-alpha

- Fixed one uploaded primary image being displayed as both an image and an artifact-directory evidence source; existing affected cases migrate on load.
- Added structured analyst-request tracking for both questions and imperative deliverables in the pre-investigation brief.
- Required each request to be answered with exact case-relative evidence or explicitly marked unresolved with a limitation before assessment can complete.
- Rendered requested answers, citations, confidence, and limitations into the final Markdown report.
- Made report readiness require a current ready assessment, a report file, and a completed report phase.
- Added safe automatic report finalization when the model resolves assessment blockers near its tool-iteration limit.
- Reduced the Ask Aries packet and question ceiling to stay below the Windows process command-line limit and return actionable launch errors.
- Changed the dashboard and report to count/display only active high/critical material leads while retaining lower-priority leads in the searchable backlog.
- Rejected common forensic filenames such as `.pf`, `.inf`, `.mui`, and `.manifest` as derived domain leads.

## v0.4.10-web-alpha

- Reworked the case data lake so SQLite FTS5 is optional instead of a hard runtime dependency.
- Added an ordinary SQLite text-search backend for Windows Python builds without FTS5.
- Added one automatic rebuild for stale or corrupt case indexes and a bounded direct-text fallback if SQLite remains unavailable.
- Serialized first-time index builds per case to prevent concurrent assistant questions from racing the temporary database.
- Added explicit assistant-retrieval failure events to the case audit instead of allowing unexplained HTTP 500 responses.
- Moved ShellBags, RecentDocs, Jump Lists, and LNK parsing into the default disk baseline.
- Added a blocking evidence rule: local-versus-network access claims require a path-bearing access artifact and cannot rely on Prefetch or missing UNC text alone.

## v0.4.9-web-alpha

- Added a persistent assistant to every registered case.
- Added a case-scoped SQLite FTS forensic data lake over parsed outputs, timelines, leads, findings, context, IOCs, briefs, and reports.
- Excluded raw source evidence, extracted binaries, framework logs, and every other case from assistant retrieval.
- Added automatic incremental index refresh based on case-output changes.
- Added bounded retrieval packets with exact case-relative file-and-line citations.
- Added post-response citation validation that removes unsupported model-generated citations.
- Persisted assistant question/answer history and data-lake provenance with the case.
- Added an optional pre-investigation brief for scope, known facts, exclusions, context, priorities, and required questions.
- Saved and audited the brief, injected it into the investigation prompt, and exposed it to the case assistant.

## v0.4.8-web-alpha

- Removed delegated independent review from the default investigation and report critical path.
- Changed the normal workflow to one primary model: targeted timeline → deterministic evidence assessment → IOC review → report.
- Preserved exact evidence-reference, corroboration, context, temporal-linkage, overclaim, and unresolved-lead gates.
- Migrated waiting/degraded/blocked review phases to skipped without rerunning completed forensic parsers.
- Reset only assessment/report phases that had been blocked by the former review requirement.
- Simplified the model panel and Hermes prompt to a single-model workflow.
- Retained orchestration artifacts and code only as an experimental optional second opinion that cannot block reporting.

## v0.4.7-web-alpha

- Required both independent reviewers to cover exactly the same bounded lead and finding IDs.
- Rejected incomplete, duplicate, and out-of-snapshot review coverage before merge, preventing artificial `single_reviewer` report blockers.
- Advanced the orchestration revision so existing v0.4.4–v0.4.6 review rounds are replaced without rerunning completed forensic parsers.
- Made the updater refuse to copy framework files while a live case investigation is running.
- Made the updater stop a verified stale Aries web listener before installing new files while refusing to kill unrelated port owners.
- Made the web launcher reject an occupied port and report the already-running Aries version instead of silently leaving the analyst on old code.

## v0.4.6-web-alpha

- Reduced each independent-review packet from a 30,000-token ceiling to roughly 8,000 estimated tokens.
- Added one self-contained delegate envelope per role containing the goal, inline packet, and native dynamic JSON Schema.
- Required reviewer children to make zero tool calls; they no longer reread packet/schema files across multiple model turns.
- Restricted schema IDs to leads/findings that actually exist in the snapshot and forced `finding_reviews` empty when the case has no findings.
- Enumerated valid evidence-reference paths in the native schema to reduce invented and absolute paths.
- Explicitly forbade the parent from rebuilding compact packets, creating findings to satisfy review schema, or repairing reviewer JSON.
- Rejected placeholder provenance values including `none`, `unknown`, and `n/a`.
- Corrected Hermes model detection so the UI does not display `base_url` as the active model.

## v0.4.5-web-alpha

- Added Stop controls to the case header and live activity drawer.
- Stop terminates the Hermes coordinator and its complete child process tree, then marks running phases interrupted and safe to resume.
- Stopped cases unlock immediately for deletion or restart.
- Added an append-only `output/web/command-audit.jsonl` trace that records commands at launch and completion with component, timestamp, return code, and duration.
- Traced coordinator phases, preflight probes, Volatility plugins, Dissect functions, EvtxECmd parsing, EZ Tool runs, and loose-artifact parsers.
- Increased live activity refresh frequency to one second and placed the command trace first in the drawer.
- Redacted common API-key, token, password, secret, and authorization command-line values.

## v0.4.4-web-alpha

- Opened the activity console automatically as soon as an investigation is launched.
- Detected fast Hermes startup failures and displayed the exact CLI, profile, authentication, or provider error on the case page.
- Preserved the investigation log tail when a coordinator exits unexpectedly instead of replacing it with a generic interrupted message.
- Added a one-click diagnostics ZIP containing Aries/Hermes/model metadata, web state, audit records, and execution logs.
- Explicitly excluded E01/EWF, memory images, uploaded evidence, and bulk parser output from diagnostics bundles.

## v0.4.3-web-alpha

- Added permanent case deletion with exact-name confirmation, resolved-path containment checks, and refusal while investigations or uploads are active.
- Deletion removes the complete case directory plus matching external web logs.
- Added an openable/closable live activity drawer with web audit events, deterministic phase logs, Hermes final output, and model/token/cost usage data.
- Added automatic redacted Hermes session export after completion so AI messages and tool calls remain reviewable in the case audit trail.
- Recorded case creation, upload, registration, investigation, and case-assistant activity in append-only `web-audit.jsonl`.
- Required all confirmed findings to cite exact existing case-relative evidence and at least two independent artifact families.
- Required confirmed malicious claims to have direct malicious classification/binary or memory behavior plus corroboration, or at least three independent artifact families.
- Automatically downgraded findings that conflict with recorded training/known-good/admin context unless an evidence-based context resolution is supplied.
- Required both a cluster identifier and exact bridge evidence before joining activity more than 30 days apart.
- Made unsupported confirmed rootkit and exfiltration labels report-blocking errors.

## v0.4.2-web-alpha

- Replaced version-specific `hermes chat --oneshot --query-file -` calls with the cross-version `hermes -z PROMPT` scripted interface exposed by the installed CLI.
- Applied the same compatibility fix to full investigations and case-assistant questions.
- Fixed the New Case close and cancel controls so they close immediately without requiring a case name.
- Added regression tests for the Hermes invocation and modal button behavior.

## v0.4.1-web-alpha

- Replaced the ambiguous fixed 4% upload indicator with real browser transfer progress, transferred bytes, throughput, ETA, and a separate SHA256 finalization state.
- Streamed raw artifact bytes directly into the case evidence store instead of first constructing a multipart upload, reducing temporary duplication for large evidence files.
- Added upload cancellation, short-transfer detection, configured-size validation, and clearer failure states.
- Added a sidebar model-status card that resolves the Aries Hermes primary model and shows whether delegated reviewers inherit it.
- Added an in-app model help panel with the exact Hermes commands for switching the primary model and clearing reviewer overrides.
- Added automated coverage for raw streaming uploads, upload telemetry wiring, and Hermes model-output parsing.

## v0.4.0-web-alpha

- Added a localhost-only FastAPI control plane and responsive forensic case dashboard.
- Added streamed artifact uploads with path validation, collision prevention, configurable size limits, and upload-time SHA256.
- Added browser-driven evidence registration through the existing evidence-set case engine.
- Added one-click autonomous investigation through a non-interactive `hermes -p aries` session.
- Added live phase/log polling, leads, findings, targeted timeline, and evidence-gated report views.
- Added a case-scoped AI assistant that is instructed to use only existing case output and cite case-relative evidence.
- Added report and compact review-bundle downloads while excluding source evidence and extracted binaries.
- Added `Start-Aries-Web.ps1`; the server binds to `127.0.0.1:8787` by default.
- Added a private hosted UI preview that uses demonstration data only; real evidence never uploads to the hosted preview.

## v0.3.3

- Replaced open-ended reviewer case browsing with a self-contained review packet capped at roughly 120,000 characters / 30,000 estimated tokens.
- Added deterministic evidence excerpts so reviewers can challenge leads without loading large parser outputs.
- Added a 24-item material high/critical lead queue; overflow remains auditable in the medium-priority backlog instead of disappearing.
- Added `investigate.py --all --concise`, which runs remaining deterministic phases in one call while saving complete output under `output\logs`.
- Reduced delegated-child iteration allowance from 80 to 24.
- Configured the Aries Hermes profile with zero automatic API retries and recovery cycles to prevent repeated spend on provider failures.
- Billing, exhausted-credit, quota, and authentication failures now degrade orchestration immediately after one recorded failure.
- Standardized agent-facing terminal paths on native `C:/Aries/...` paths to avoid failed `/c/Aries/...` translation.
- Added v0.3.2 migration gating so existing cases receive a fresh bounded review round without rerunning completed parsers.
- Expanded automated coverage from 32 to 36 tests, including packet-size enforcement, non-retryable billing failures, lead budgeting, concise phase logs, and v0.3.2 migration.

## v0.3.2

- Changed delegated reviews from concurrent to sequential execution to reduce provider throttling while retaining separate fresh child contexts.
- Added provenance-tracked review submission with delegation ID, child ID, provider/model, response hash, and per-role receipt validation.
- Directly written or lead-authored reviewer files no longer satisfy orchestration; Aries must use `--submit-review`.
- Added provider-failure recording and bounded retry state. Three failures mark orchestration `degraded` rather than allowing fabricated fallback reviews.
- Added cross-case contamination rejection for foreign Aries case paths and candidate entities absent from their cited evidence.
- Added explicit case identity to every reviewer response/schema.
- High/critical lead disposition now requires a structured evidence reference, context ID, or adjudicated review item.
- Dispositioning a high-priority lead as `unresolved` no longer removes the final-report blocker.
- Confirmed high-priority leads require at least one structured finding before the report can become ready.
- Final report generation is blocked until evidence assessment is ready; `--allow-draft` is an explicit incomplete-report override.
- Validated IOC insertion now rejects blank values, missing evidence/source, contextual scope, uncited values, and private IPs without an explicit malicious-use override.
- Reports disclose reviewer provenance and filter obvious contextual/empty IOC rows inherited from older cases.
- Added regression coverage for self-authored reviews, provider 429 degradation, foreign-case contamination, unsupported candidate entities, unresolved-lead bypass, report gating, lead closure basis, and IOC validation.

## v0.3.1

- Added `orchestration_review` between the targeted timeline and evidence assessment.
- Added immutable, hashed case snapshots with bounded source catalogs for delegated reasoning.
- Added independent investigator and skeptical-validator task packets.
- Added native JSON output schemas for Hermes `delegate_task` batches.
- Added exit code `4` / `waiting` phase state so investigations pause safely for child reviews and resume without treating the checkpoint as a parser failure.
- Added strict role/task/snapshot validation and case-relative evidence-reference validation for child responses.
- Added deterministic review merging with explicit agreements, disagreements, proposed leads, contradictions, evidence gaps, and report blockers.
- Kept delegated reviews advisory: children never mutate authoritative leads/findings, and AI agreement never counts as forensic corroboration.
- Added append-only lead-agent dispositions for review items (`resolved`, `dismissed`, or `deferred`).
- Extended evidence assessment and reports with orchestration coverage and unadjudicated-review gates.
- Configured the Aries Hermes profile for at most two concurrent children, flat delegation, no nested orchestrator children, and an 80-iteration child budget.
- Extended compact review exports to include bounded orchestration records while continuing to exclude source evidence and extracted binaries.
- Expanded the automated suite from 16 to 23 tests, including waiting/resume state, immutable review packets, no child-state mutation, fabricated-reference rejection, deterministic merging, stale-review detection, migration gating, and review-item adjudication.

## v0.3.0

- Replaced E01/memory-only intake with a backward-compatible evidence-set model.
- Added first-class file and directory evidence registration, recursive artifact discovery, and per-file directory hashing.
- Added non-EWF disk-image routing for DD/IMG/VHD/VHDX/VMDK/QCOW/AFF4; raw `.raw` remains memory by default and can be registered explicitly as disk with `case.py init --disk`.
- Added loose-artifact classification for EVTX, registry hives, ShellBags, Prefetch, Amcache, SRUM, MFT/USN, LNK, Jump Lists, recycle-bin data, Windows Timeline, WebCache/browser databases, archives, and text logs.
- Added `run_artifact_baseline.py` with deterministic RECmd/SBECmd/PECmd/AmcacheParser/SrumECmd/MFTECmd/LECmd/JLECmd/RBCmd/WxTCmd routing.
- Added `artifact_triage.py` to seed cautious, non-verdict leads from parsed paths, archives, executables, UNC paths, and context-bearing artifact rows.
- Made preflight and the coordinator capability-aware so irrelevant disk/memory phases skip cleanly.
- Upgraded `pivot.py` to bounded recursive investigation (three hops by default), independent artifact-family tracking, and explicit unresolved/single-source status.
- Added structured finding claim scopes, exact evidence references, evidence families, observed behavior, ATT&CK mappings, incident clusters, and limitations.
- Added automatic downgrade of under-corroborated confirmed malicious/attribution/capability claims.
- Added `evidence_assessment.py` for open high-priority leads, contradictions, corroboration, temporal linkage, attribution/capability language, and behavior-backed ATT&CK validation.
- Reports now carry READY/DRAFT status and embed evidence-assessment issues, artifact coverage, structured evidence, and partial-phase limitations.
- Updated Aries identity/instructions to start the coordinator promptly for artifact folders and to close or disclose every high-priority lead.
- Expanded the test suite from 13 to 16 tests, including artifact-folder intake, directory hashing, evidence-discipline downgrade, and recursive child-lead processing.

## v0.2.2

Combined v0.2.1 investigation-quality work and planned v0.2.2 event triage improvements.

- Reordered the default pipeline to be event-led.
- Moved artifact/EVTX discovery and parsing ahead of memory/disk broad baselines.
- Added Tier 1 / Tier 2 / Tier 3 event-log inventory.
- Tier 1 + Tier 2 EVTX channels are automatically parsed with EvtxECmd (bounded by a configurable safety cap).
- Added deterministic `event_triage.py` to seed leads from Defender, Sysmon/Security process activity, network/DNS, PowerShell, service/task/account changes.
- Added `leads.jsonl` with stable IDs, priority, score, status, provenance, parent/child links, and relevance.
- Added `pivot.py` for cross-source lead correlation and bounded child-lead creation.
- Added `targeted_timeline.py` for lead-centered chronology.
- Made whole-disk `disk_timeline` optional instead of a mandatory baseline phase.
- Full Dissect baseline no longer implicitly generates the giant timeline.
- Added `case_context.json` and case context commands.
- Added stable finding IDs and append-only retraction/supersession support.
- Added partial phase state (exit code 3) for mixed-success Volatility/Dissect/EvtxECmd runs.
- Targeted IOC scanning excludes giant whole-disk timelines/oversized output by default.
- Added project self-modification guard instructions for case work.
- Added v0.2.0 phase migration (`eztools_baseline` -> `eventlog_baseline`).
- Removed generated `.pytest_cache` / `__pycache__` from release packaging.
- Expanded tests for event triage, pivot correlation, targeted timeline, context, and finding retraction.

## v0.2.0

- Added checkpointed/resumable phases and stale-running recovery.
- Changed normal coordinator behavior to one phase per invocation.
- Added automatic evidence SHA256 and `evidence_manifest.json` with hash reuse.
- Added preflight dependency/capability checks.
- Added high-value disk artifact inventory.
- Added automatic EvtxECmd parsing for priority Windows event logs.
- Added `windows.netstat` alongside `windows.netscan`.
- Added structured finding classifications.
- Added phase status/reset commands and report/evidence integrity sections.
