from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path

from common import case_dir, load_case, now_iso
from questions import load_questions, questions_path
from records import context_matches, materialize_history

DATE_RE = re.compile(r"\b(20\d\d[-/]\d\d[-/]\d\d)\b")
HIGH_IMPACT = {"malicious", "attribution", "capability"}
DIRECT_MALICIOUS_FAMILIES = {"defender", "antivirus", "edr", "yara", "binary_analysis", "memory_behavior", "sandbox"}
ACCESS_PATH_FAMILIES = {"shellbags", "lnk", "jumplist", "recentdocs"}
PRIORITY = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1}
ASSESSMENT_SCHEMA_VERSION = "0.5.0"
CAUSAL_LANGUAGE = (
    "companion staging", "installed by", "created by", "caused by", "resulted in",
    "part of the attack", "part of this attack", "used to establish", "follow-on activity",
    "deployed by", "dropped by", "same attack chain", "therefore installed",
)


def issue(code: str, severity: str, message: str, *, finding_id: str | None = None, lead_id: str | None = None, blocking: bool = False) -> dict:
    return {"code": code, "severity": severity, "message": message, "finding_id": finding_id, "lead_id": lead_id, "blocking": blocking}


def date_span_days(text: str) -> int:
    values = []
    for raw in DATE_RE.findall(text):
        try: values.append(datetime.strptime(raw.replace("/", "-"), "%Y-%m-%d"))
        except ValueError: pass
    return (max(values) - min(values)).days if len(values) >= 2 else 0


def lead_is_material_to_scope(lead: dict, questions: list[dict], findings: list[dict]) -> bool:
    """Return true only when durable case state ties the lead to the requested conclusion.

    An unresolved historical lead must remain visible, but it should not make an
    otherwise answered report permanently partial merely because it was once
    assigned a high triage score.
    """
    if lead.get("material_to_scope") is True or lead.get("material_to_questions"):
        return True
    needles = [str(lead.get("id") or "").lower(), str(lead.get("value") or "").strip().lower()]
    needles = [value for value in needles if len(value) >= 4]
    if not needles:
        return False
    scope_text = " ".join(
        str(value or "")
        for question in questions
        for value in (question.get("question"), question.get("answer"))
    ).lower()
    scope_text += " " + " ".join(
        str(value or "")
        for finding in findings
        for value in (finding.get("title"), finding.get("details"), finding.get("behavior"))
    ).lower()
    return any(needle in scope_text for needle in needles)


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate Aries findings, lead closure, temporal linkage, and report claims")
    ap.add_argument("--case", required=True); args = ap.parse_args(); load_case(args.case)
    root = case_dir(args.case)
    findings = [item for item in materialize_history(root / "findings.jsonl", "F") if item.get("status") == "active"]
    all_leads = materialize_history(root / "leads.jsonl", "L")
    leads = [item for item in all_leads if item.get("status") == "active"]
    issues: list[dict] = []

    artifact_manifest = root / "output" / "artifacts" / "artifact-baseline-manifest.json"
    try:
        artifact_results = json.loads(artifact_manifest.read_text(encoding="utf-8")).get("results", []) if artifact_manifest.is_file() else []
    except (OSError, json.JSONDecodeError):
        artifact_results = []
    for result in artifact_results:
        if result.get("status") in {"failed", "timeout"}:
            source_name = Path(str(result.get("source") or "artifact")).name
            issues.append(issue(
                "STATIC_ARTIFACT_ANALYSIS_FAILED",
                "high",
                f"Static analysis failed for {source_name}: {result.get('reason') or 'no failure reason was recorded'}. Retry artifact processing before relying on absence of script or archive findings.",
                blocking=True,
            ))

    question_state = load_questions(args.case) if questions_path(args.case).is_file() else {"questions": []}
    questions = question_state.get("questions", [])
    for question in questions:
        qid = str(question.get("id") or "question")
        status = question.get("status", "pending")
        if status == "pending":
            issues.append(issue(
                "ANALYST_QUESTION_UNANSWERED",
                "high",
                f"{qid} remains pending: {question.get('question', '')}",
                blocking=True,
            ))
        elif status == "answered" and not question.get("evidence_refs"):
            issues.append(issue(
                "ANALYST_ANSWER_UNCITED",
                "high",
                f"{qid} is marked answered without an exact case-relative evidence reference.",
                blocking=True,
            ))
        elif status == "answered":
            answer = str(question.get("answer") or "")
            lower_answer = answer.lower()
            bridge_refs = list(dict.fromkeys(question.get("bridge_evidence_refs") or []))
            for ref in list(question.get("evidence_refs") or []) + bridge_refs:
                candidate = (root / str(ref).replace("\\", "/")).resolve()
                try:
                    candidate.relative_to(root.resolve())
                except ValueError:
                    issues.append(issue("ANSWER_EVIDENCE_OUTSIDE_CASE", "high", f"{qid} references evidence outside the case: {ref}", blocking=True))
                    continue
                if not candidate.is_file():
                    issues.append(issue("ANSWER_EVIDENCE_MISSING", "high", f"{qid} references missing evidence: {ref}", blocking=True))
            if any(phrase in lower_answer for phrase in CAUSAL_LANGUAGE) and not bridge_refs:
                issues.append(issue(
                    "ANSWER_CAUSAL_LINK_UNSUPPORTED",
                    "high",
                    f"{qid} uses causal or attack-chain language without separately identifying the exact evidence that proves the link.",
                    blocking=True,
                ))
            refs = [str(ref).lower() for ref in question.get("evidence_refs") or []]
            if refs and all(ref.endswith(".evtx") for ref in refs):
                issues.append(issue(
                    "ANSWER_COARSE_EVIDENCE_REFERENCE",
                    "low",
                    f"{qid} cites only whole EVTX containers. Prefer the parsed CSV/JSON row or lead/pivot output that contains the exact event.",
                    blocking=False,
                ))
        elif status == "unresolved":
            issues.append(issue(
                "ANALYST_QUESTION_UNRESOLVED",
                "medium",
                f"{qid} could not be answered from the available evidence: {question.get('limitation') or question.get('answer')}",
                blocking=False,
            ))

    brief_path = root / "investigation-brief.json"
    try:
        brief = str(json.loads(brief_path.read_text(encoding="utf-8")).get("instructions") or "") if brief_path.is_file() else ""
    except (OSError, json.JSONDecodeError):
        brief = ""
    incident_scope = any(token in brief.lower() for token in ("compromised", "suspicious activity", "malicious", "incident", "soc team"))
    explicit_no_incident = any(
        item.get("status") == "answered"
        and any(token in str(item.get("answer") or "").lower() for token in ("no incident established", "no suspicious activity established", "no malicious activity established"))
        and item.get("evidence_refs")
        for item in questions
    )
    if incident_scope and not findings and not explicit_no_incident:
        issues.append(issue(
            "INCIDENT_SYNTHESIS_MISSING",
            "high",
            "The analyst requested an incident investigation, but the case has neither a substantive structured finding nor an evidence-cited conclusion that no incident was established. Lead closure alone is not a completed investigation.",
            blocking=True,
        ))

    for lead in leads:
        priority = PRIORITY.get(str(lead.get("priority")), 0)
        status = lead.get("pivot_status")
        if priority >= PRIORITY["high"] and status in {None, "unresolved", "single-source"}:
            sources = [str(lead.get("source") or "")] + [str(value) for value in lead.get("sources", [])]
            derived_only = any(value.startswith("Pivot:") for value in sources) and not any(
                value and not value.startswith("Pivot:") for value in sources
            )
            if derived_only:
                issues.append(issue(
                    "DERIVED_SINGLE_SOURCE_LEAD",
                    "medium",
                    f"{lead['id']} is a recursively derived {status or 'unpivoted'} lead. It remains in the searchable backlog but does not block reporting without independent corroboration.",
                    lead_id=lead["id"],
                    blocking=False,
                ))
            else:
                issues.append(issue("OPEN_HIGH_PRIORITY_LEAD", "medium", f"{lead['id']} remains open with pivot status {status or 'not pivoted'}. It is disclosed as an analysis limitation but does not prevent report delivery.", lead_id=lead["id"], blocking=False))

    for lead in all_leads:
        priority = PRIORITY.get(str(lead.get("priority")), 0)
        if priority < PRIORITY["high"] or lead.get("status") == "active":
            continue
        if lead.get("status") == "unresolved":
            material = lead_is_material_to_scope(lead, questions, findings)
            issues.append(issue(
                "UNRESOLVED_MATERIAL_HIGH_PRIORITY_LEAD" if material else "UNRESOLVED_HIGH_PRIORITY_LEAD",
                "high" if material else "medium",
                (f"{lead['id']} is unresolved and is directly tied to an analyst question or active finding."
                 if material else
                 f"{lead['id']} remains unresolved, but no durable case state ties it to an analyst-requested conclusion; it is disclosed as residual uncertainty."),
                lead_id=lead["id"],
                blocking=material,
            ))
            continue
        basis = lead.get("closure_basis") or {}
        if not any((basis.get("evidence_refs"), basis.get("context_id"))):
            issues.append(issue("UNSUPPORTED_HIGH_PRIORITY_DISPOSITION", "high", f"{lead['id']} was closed without a structured evidence or recorded-context basis. Reopen or disposition it with supported case state.", lead_id=lead["id"], blocking=True))

    confirmed_material_leads = [
        lead for lead in all_leads
        if lead.get("status") == "confirmed" and PRIORITY.get(str(lead.get("priority")), 0) >= PRIORITY["high"]
    ]
    if confirmed_material_leads and not findings:
        issues.append(issue(
            "CONFIRMED_LEADS_NOT_PROMOTED",
            "high",
            "One or more high/critical leads were confirmed, but no structured finding was recorded. Promote the supported incident conclusions with exact evidence references before final reporting.",
            blocking=True,
        ))

    for finding in findings:
        fid = finding.get("id"); kind = finding.get("kind", "observation"); scope = finding.get("claim_scope", "factual")
        refs = list(dict.fromkeys(finding.get("evidence_refs") or [])); families = list(dict.fromkeys(finding.get("artifact_families") or []))
        behavior = str(finding.get("behavior") or "").strip(); combined = f"{finding.get('title', '')} {finding.get('details', '')}".lower()
        matched_context = list(dict.fromkeys((finding.get("context_matches") or []) + context_matches(args.case, combined + " " + behavior.lower())))
        context_resolution = str(finding.get("context_resolution") or "").strip()
        bridge_refs = list(dict.fromkeys(finding.get("bridge_evidence_refs") or []))
        if not refs:
            issues.append(issue("MISSING_EVIDENCE_REFERENCE", "medium", "Material finding has no exact case-relative evidence reference.", finding_id=fid, blocking=kind in {"inference", "confirmed"}))
        for ref in refs + bridge_refs:
            candidate = (root / str(ref).replace("\\", "/")).resolve()
            try: candidate.relative_to(root.resolve())
            except ValueError:
                issues.append(issue("EVIDENCE_REFERENCE_OUTSIDE_CASE", "high", f"Finding evidence reference leaves the case directory: {ref}", finding_id=fid, blocking=True)); continue
            if not candidate.is_file():
                issues.append(issue("EVIDENCE_REFERENCE_MISSING", "high", f"Finding evidence reference does not exist: {ref}", finding_id=fid, blocking=True))
        if kind == "confirmed" and len(families) < 2:
            issues.append(issue("INSUFFICIENT_CORROBORATION", "high", f"Confirmed claim has {len(families)} independent artifact family/families; at least two are required.", finding_id=fid, blocking=True))
        if kind == "confirmed" and scope == "malicious" and not (DIRECT_MALICIOUS_FAMILIES & set(families)) and len(families) < 3:
            issues.append(issue("MALICIOUS_PROMOTION_TOO_WEAK", "high", "Confirmed malicious status requires direct malicious classification/binary or memory behavior plus corroboration, or at least three independent artifact families.", finding_id=fid, blocking=True))
        if kind == "confirmed" and matched_context and len(context_resolution) < 20:
            issues.append(issue("CONTEXT_CONFLICT_UNRESOLVED", "high", f"Finding intersects recorded context {', '.join(matched_context)} without a specific evidence-based resolution.", finding_id=fid, blocking=True))
        if scope == "attribution" and len(families) < 3:
            issues.append(issue("ATTRIBUTION_OVERCLAIM", "high", "Human attribution requires stronger identity linkage than an account/IP/session artifact alone.", finding_id=fid, blocking=True))
        if scope == "capability" and (not behavior or not ({"binary_analysis", "memory_behavior"} & set(families))):
            issues.append(issue("CAPABILITY_NOT_DEMONSTRATED", "high", "Exact malware capability is claimed without binary/memory behavior analysis and explicit observed behavior.", finding_id=fid, blocking=True))
        if finding.get("attack_techniques") and not behavior:
            issues.append(issue("ATTACK_MAPPING_WITHOUT_BEHAVIOR", "high", "ATT&CK techniques were recorded without the observed behavior that justifies the mapping.", finding_id=fid, blocking=True))
        if date_span_days(combined) > 30 and (not finding.get("incident_cluster") or not bridge_refs):
            issues.append(issue("TEMPORAL_LINK_UNSUPPORTED", "high", "Finding joins activity more than 30 days apart without both an incident cluster and exact bridge evidence.", finding_id=fid, blocking=True))
        if "rootkit" in combined and scope != "capability":
            issues.append(issue("ROOTKIT_LABEL_REQUIRES_VALIDATION", "high", "A suspicious driver/service path is not by itself proof of rootkit behavior.", finding_id=fid, blocking=kind == "confirmed"))
        if "attacker identity" in combined or "attacker's identity" in combined:
            if scope != "attribution": issues.append(issue("ATTRIBUTION_LANGUAGE_MISMATCH", "high", "Attacker-identity language must use attribution scope and meet attribution evidence requirements.", finding_id=fid, blocking=True))
        if "confirmed data exfiltration" in combined and not any(token in behavior.lower() for token in ["non-zero", "content", "transferred bytes", "file transfer completed"]):
            issues.append(issue("EXFILTRATION_OVERCLAIM", "high", "A transfer mechanism or zero-byte test does not establish meaningful data theft.", finding_id=fid, blocking=kind == "confirmed"))
        appcompat = "appcompat" in combined or "compatibility assistant" in combined
        timestomp = any(token in combined for token in ("timestomp", "timestamp manipulation", "time stomping", "t1099"))
        if appcompat and timestomp:
            issues.append(issue(
                "APPCOMPAT_TIMESTOMP_OVERCLAIM",
                "high",
                "A Compatibility Assistant/AppCompat registry write is normal Windows compatibility telemetry and is not evidence of timestamp manipulation by itself. Retract or rewrite this finding using the behavior actually observed.",
                finding_id=fid,
                blocking=True,
            ))
        if "filecreatestreamhash" in combined and any(token in combined for token in ("t1099", "timestamp", "timestomp")):
            issues.append(issue(
                "SYSMON_EVENT15_MISINTERPRETED",
                "high",
                "Sysmon Event ID 15 FileCreateStreamHash records alternate data stream content; it is not the FileCreateTime/timestomping event. Correct the event interpretation.",
                finding_id=fid,
                blocking=True,
            ))
        access_location_claim = any(token in combined for token in ["local drive", "local path", "network location", "network share", "unc path", "not network"])
        access_evidence = set(families) & ACCESS_PATH_FAMILIES
        ref_text = " ".join(str(ref).lower() for ref in refs)
        if any(token in ref_text for token in ["shellbag", "jumplist", "recentdoc", "lnk"]):
            access_evidence.add("referenced_access_artifact")
        if access_location_claim and not access_evidence:
            issues.append(issue(
                "ACCESS_LOCATION_UNCORROBORATED",
                "high",
                "Local-versus-network access cannot be concluded from Prefetch or the absence of a UNC string alone. Corroborate it with LNK, ShellBags, Jump Lists, or RecentDocs.",
                finding_id=fid,
                blocking=True,
            ))

    blocking = [item for item in issues if item["blocking"]]
    report = {"schema_version": ASSESSMENT_SCHEMA_VERSION, "generated_utc": now_iso(), "case": args.case,
              "report_ready": not blocking, "active_findings": len(findings), "active_leads": len(leads),
              "analyst_questions": len(questions), "answered_questions": sum(1 for item in questions if item.get("status") == "answered"),
              "unresolved_questions": sum(1 for item in questions if item.get("status") == "unresolved"),
              "blocking_issue_count": len(blocking), "issue_count": len(issues), "issues": issues,
              "second_opinion": {"status": "optional", "required_for_report": False},
              "standard": {"confirmed_finding": "At least two independent artifact families and exact existing case-relative evidence references", "confirmed_malicious": "Direct malicious classification/binary or memory behavior plus corroboration, or at least three independent artifact families", "context_conflict": "Recorded benign/training/admin context must be explicitly resolved with evidence before confirmation", "attribution": "At least three independent families plus explicit identity linkage", "attack_mapping": "Observed behavior required", "temporal_linkage": "Both an incident cluster and exact bridge evidence are required across distant activity", "answer_causality": "Causal or attack-chain language in analyst answers requires separate exact bridge evidence", "second_opinion": "Optional and advisory; it never counts as evidence or blocks reporting", "lead_disposition": "High/critical dispositions require structured evidence or recorded context; unresolved leads block only when tied to an analyst question or active finding"}}
    out = root / "output" / "evidence-assessment.json"; out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Evidence assessment: {'READY' if report['report_ready'] else 'NOT READY'}; {len(issues)} issue(s), {len(blocking)} blocking.")
    print(f"Assessment: {out}")
    if blocking:
        raise SystemExit(3)


if __name__ == "__main__":
    main()
