const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

const PHASE_LABELS = {
  preflight: "Preflight",
  evidence_integrity: "Evidence integrity",
  artifact_discovery: "Artifact discovery",
  eventlog_baseline: "Event log parsing",
  event_triage: "Event triage",
  artifact_baseline: "Artifact parsing",
  artifact_triage: "Artifact triage",
  memory_baseline: "Memory baseline",
  disk_baseline: "Disk baseline",
  pivot: "Recursive pivots",
  targeted_timeline: "Targeted timeline",
  evidence_assessment: "Evidence assessment",
  ioc_scan: "IOC review",
  report: "Final report",
};

const state = {
  api: true,
  cases: [],
  active: null,
  tab: "leads",
  timeline: [],
  report: "",
  assistantHistory: [],
  uploads: [],
  uploadSequence: 0,
  model: null,
  activityPoller: null,
  poller: null,
};

const demoPhases = Object.keys(PHASE_LABELS).map((name) => ({
  name,
  status: "complete",
  attempts: 1,
  message: "",
}));

const demoCase = {
  name: "IR-2026-014",
  description: "Suspected endpoint compromise — finance workstation",
  created_utc: "2026-11-04T02:12:00Z",
  updated_utc: "2026-11-04T03:04:00Z",
  status: "ready",
  registered: true,
  running: false,
  report_ready: true,
  report_available: true,
  evidence: [
    {kind: "e01", source_name: "FIN-WS07.E01", path: "FIN-WS07.E01", size_bytes: 68719476736},
    {kind: "memory", source_name: "FIN-WS07.raw", path: "FIN-WS07.raw", size_bytes: 17179869184},
    {kind: "artifact_directory", source_name: "triage", path: "triage", size_bytes: 481239040},
  ],
  uploaded_files: [],
  phases: demoPhases,
  leads: [
    {id: "L-0007", type: "process", value: "CrackedSoftware.exe", priority: "critical", score: 92, status: "active", independent_family_count: 4, reason: "Defender detection plus process, network, and filesystem telemetry"},
    {id: "L-0011", type: "ip", value: "192.168.112.153", priority: "high", score: 86, status: "active", independent_family_count: 3, reason: "Delivery and callback infrastructure associated with L-0007"},
    {id: "L-0016", type: "service", value: "3355986867.sys", priority: "medium", score: 58, status: "active", independent_family_count: 1, reason: "Kernel driver service from temporary path; relationship unresolved"},
    {id: "L-0022", type: "user", value: "soc20", priority: "medium", score: 52, status: "contextual", independent_family_count: 2, reason: "Interactive user context; training activity separated"},
  ],
  findings: [
    {id: "F-0003", kind: "confirmed", title: "Malicious executable ran and contacted suspected callback infrastructure", severity: "high", confidence: "high", artifact_families: ["event_logs", "disk", "memory"]},
    {id: "F-0005", kind: "inference", title: "Remote-access session preceded the incident window", severity: "medium", confidence: "medium", artifact_families: ["event_logs", "application_logs"]},
    {id: "F-0008", kind: "hypothesis", title: "Driver service may be related persistence", severity: "medium", confidence: "low", artifact_families: ["event_logs"]},
  ],
  assessment: {report_ready: true, issues: []},
  last_log: "EVIDENCE_ASSESSMENT=READY\nREPORT_STATUS=READY\nSingle-model investigation complete.",
};

const demoTimeline = [
  {timestamp: "2026-08-08 08:42:33", lead_id: "L-0007", artifact_family: "browser", event: "cracked_software.zip downloaded from 192.168.112.153:8000"},
  {timestamp: "2026-08-08 08:43:41", lead_id: "L-0007", artifact_family: "filesystem", event: "CrackedSoftware.exe created in user Downloads directory"},
  {timestamp: "2026-08-08 08:43:59", lead_id: "L-0007", artifact_family: "event_logs", event: "Process execution recorded by Sysmon"},
  {timestamp: "2026-08-08 08:44:00", lead_id: "L-0011", artifact_family: "network", event: "Process connected to 192.168.112.153:8080"},
  {timestamp: "2026-08-08 08:44:27", lead_id: "L-0007", artifact_family: "defender", event: "Defender detection and remediation activity"},
];

function escapeHtml(value = "") {
  return String(value).replace(/[&<>'"]/g, (char) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"}[char]));
}

function formatBytes(bytes) {
  if (!Number(bytes)) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / 1024 ** index).toFixed(index > 2 ? 1 : 0)} ${units[index]}`;
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds) || seconds < 0) return "estimating…";
  if (seconds < 60) return `${Math.max(1, Math.round(seconds))} sec`;
  if (seconds < 3600) return `${Math.ceil(seconds / 60)} min`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.ceil((seconds % 3600) / 60);
  return `${hours} hr${hours === 1 ? "" : "s"}${minutes ? ` ${minutes} min` : ""}`;
}

function renderModel(model) {
  state.model = model || {primary: "Not configured", workflow: "single_model"};
  $("#modelName").textContent = state.model.primary || "Not configured";
  $("#modelName").title = state.model.primary || "Not configured";
  $("#modelInheritance").textContent = "Single-model workflow";
  $("#modelDialogPrimary").textContent = state.model.primary || "Not configured";
  $("#modelDialogWorkflow").textContent = "One primary model; delegated review is disabled";
}

async function refreshModel() {
  if (!state.api) return renderModel({primary: "Demo mode", workflow: "single_model"});
  try {
    renderModel(await request("/api/model"));
    toast("Model status refreshed");
  } catch (error) { toast(error.message, true); }
}

function toast(message, error = false) {
  const node = $("#toast");
  node.textContent = message;
  node.className = `toast show${error ? " error" : ""}`;
  clearTimeout(node.timer);
  node.timer = setTimeout(() => node.className = "toast", 3200);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: options.body instanceof FormData ? options.headers : {"Content-Type": "application/json", ...(options.headers || {})},
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try { detail = (await response.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  const type = response.headers.get("content-type") || "";
  return type.includes("application/json") ? response.json() : response.text();
}

async function initialize() {
  try {
    const health = await request("/api/health");
    if (health.status !== "ok") throw new Error("No local API");
    state.api = true;
    $("#engineDot").classList.add("online");
    $("#engineLabel").textContent = "Engine connected";
    $("#engineVersion").textContent = `Aries ${health.version}`;
    renderModel(health.ai);
    await refreshCases();
  } catch (_) {
    state.api = false;
    state.cases = [{...demoCase}];
    $("#engineDot").classList.add("online");
    $("#engineLabel").textContent = "Interface preview";
    $("#engineVersion").textContent = "Demo evidence set";
    renderModel({primary: "Demo mode", workflow: "single_model"});
    renderCaseList();
    await openCase(demoCase.name);
  }
}

async function refreshCases(preferred = null) {
  const result = await request("/api/cases");
  state.cases = result.cases || [];
  renderCaseList();
  const target = preferred || state.active?.name || state.cases[0]?.name;
  if (target) await openCase(target);
  else showEmpty();
}

function renderCaseList() {
  $("#caseList").innerHTML = state.cases.map((item) => `
    <button class="case-item ${item.name === state.active?.name ? "active" : ""} ${item.running ? "running" : item.report_ready ? "ready" : ""}" data-case="${escapeHtml(item.name)}">
      <span class="case-dot"></span>
      <span><strong>${escapeHtml(item.name)}</strong><small>${item.running ? "Investigation running" : item.report_ready ? "Report complete" : item.report_available ? "Partial report available" : escapeHtml(item.status || "Draft")}</small></span>
      <small>›</small>
    </button>`).join("");
  $$(".case-item").forEach((button) => button.addEventListener("click", () => openCase(button.dataset.case)));
}

function showEmpty() {
  state.active = null;
  state.assistantHistory = [];
  $("#emptyState").classList.remove("hidden");
  $("#caseWorkspace").classList.add("hidden");
  $("#caseTitle").textContent = "Select a case";
  $("#caseStatus").textContent = "No case";
  $("#runButton").disabled = true;
  $("#bundleButton").disabled = true;
  $("#terminalButton").disabled = true;
  $("#assistantButton").disabled = true;
  $("#assistantFab").classList.add("hidden");
  $("#assistantPanel").classList.remove("open");
  $("#deleteCaseButton").disabled = true;
  closeTerminal();
}

async function openCase(name) {
  try {
    state.active = state.api ? await request(`/api/cases/${encodeURIComponent(name)}`) : state.cases.find((item) => item.name === name) || demoCase;
    state.timeline = state.api ? (await request(`/api/cases/${encodeURIComponent(name)}/timeline`)).rows : demoTimeline;
    if (state.api) {
      try {
        const assistant = await request(`/api/cases/${encodeURIComponent(name)}/assistant/history`);
        state.assistantHistory = assistant.messages || [];
        state.active.datalake = assistant.datalake || state.active.datalake;
      } catch (_) { state.assistantHistory = []; }
    } else { state.assistantHistory = []; }
    state.report = "";
    if (state.active.report_available || state.active.report_ready) {
      try { state.report = await request(`/api/cases/${encodeURIComponent(name)}/report`); } catch (_) {}
    }
    renderCaseList();
    renderWorkspace();
    renderAssistant();
    startPolling();
  } catch (error) {
    toast(error.message, true);
  }
}

function renderAssistant() {
  const active = state.active;
  $("#assistantCaseName").textContent = active ? `${active.name} evidence lake` : "Active case evidence lake";
  const lake = active?.datalake || {};
  $("#assistantLakeStatus").textContent = lake.status === "ready"
    ? `${lake.indexed_files || 0} files · ${lake.indexed_chunks || 0} searchable chunks · active case only`
    : "The index builds automatically when you ask a question.";
  const chat = $("#chatMessages");
  chat.innerHTML = "";
  if (!(state.assistantHistory || []).length) {
    appendMessage("Ask about a process, account, timestamp, IOC, contradiction, or report conclusion. I will search only this case and cite the exact files used.", "assistant-message");
    return;
  }
  for (const item of state.assistantHistory) {
    appendMessage(item.question, "user-message");
    appendMessage(item.answer, "assistant-message");
  }
}

function renderWorkspace() {
  const active = state.active;
  if (!active) return showEmpty();
  $("#emptyState").classList.add("hidden");
  $("#caseWorkspace").classList.remove("hidden");
  $("#caseTitle").textContent = active.name;
  $("#caseStatus").textContent = active.running ? "Running" : active.report_ready ? "Report complete" : active.report_available ? "Partial report" : active.status || "Ready";
  $("#runButton").disabled = !active.registered || active.running;
  $("#runButton").textContent = active.running
    ? "Investigation running"
    : active.processing_retry_required
      ? "Retry artifact processing"
      : active.report_ready
        ? "Refine report"
        : active.report_available
          ? "Retry AI synthesis"
          : "Run investigation";
  $("#bundleButton").disabled = !active.registered;
  $("#terminalButton").disabled = false;
  $("#assistantButton").disabled = !active.registered;
  $("#assistantFab").classList.toggle("hidden", !active.registered);
  $("#stopButton").classList.toggle("hidden", !active.running);
  $("#terminalStopButton").classList.toggle("hidden", !active.running);
  $("#deleteCaseButton").disabled = active.running;
  $("#registerButton").classList.toggle("hidden", active.registered || !(active.uploaded_files || []).length);

  const evidence = active.evidence?.length ? active.evidence : active.uploaded_files || [];
  const totalSize = evidence.reduce((sum, item) => sum + Number(item.size_bytes || 0), 0);
  const material = (active.leads || []).filter((item) => ["high", "critical"].includes(item.priority) && item.status === "active");
  const completed = (active.phases || []).filter((item) => ["complete", "partial", "skipped"].includes(item.status)).length;
  const percent = active.phases?.length ? Math.round(completed / active.phases.length * 100) : 0;
  const unresolvedQuestions = (active.analyst_questions?.questions || []).filter((item) => item.status !== "answered").length;
  $("#evidenceMetric").textContent = evidence.length;
  $("#evidenceSize").textContent = evidence.length ? `${formatBytes(totalSize)} registered` : "No artifacts registered";
  $("#leadMetric").textContent = material.length;
  $("#leadSummary").textContent = `${material.length} high/critical active`;
  $("#phaseMetric").textContent = `${percent}%`;
  $("#phaseSummary").textContent = active.running
    ? "Processing and analysis in progress"
    : active.report_available && unresolvedQuestions
      ? `Processing complete · ${unresolvedQuestions} analyst request(s) unresolved`
      : `${completed} of ${active.phases?.length || 0} processing phases complete`;
  $("#reportMetric").textContent = active.report_ready ? "Complete" : active.report_available ? "Partial" : "Pending";
  $("#reportSummary").textContent = active.report_ready ? "Evidence-supported report available" : active.report_available ? `Report available · ${active.assessment?.blocking_issue_count || 0} unresolved requirement(s)` : active.assessment?.issues?.[0]?.code?.replaceAll("_", " ") || "Evidence assessment not reached";
  $("#caseError").classList.toggle("hidden", !active.last_error);
  $("#caseError").textContent = active.last_error ? `${active.report_available ? "Review note" : "Investigation stopped"}:\n${active.last_error}` : "";
  renderUploads();
  renderPhases();
  renderTab();
}

function renderPhases() {
  const phases = state.active.phases?.length ? state.active.phases : Object.keys(PHASE_LABELS).map((name) => ({name, status: "pending"}));
  $("#phaseList").innerHTML = phases.map((phase) => {
    const status = phase.status || "pending";
    const icon = ["complete", "partial", "skipped"].includes(status) ? "✓" : ["running", "waiting"].includes(status) ? "…" : ["failed", "blocked", "degraded"].includes(status) ? "!" : "·";
    return `<div class="phase ${escapeHtml(status)}"><span class="phase-icon">${icon}</span><span><strong>${escapeHtml(PHASE_LABELS[phase.name] || phase.name.replaceAll("_", " "))}</strong><small>${escapeHtml(status)}${phase.attempts ? ` · ${phase.attempts} attempt${phase.attempts > 1 ? "s" : ""}` : ""}</small></span></div>`;
  }).join("");
  $("#liveChip").classList.toggle("hidden", !state.active.running);
  $("#liveLog").classList.toggle("hidden", !state.active.last_log);
  $("#liveLog").textContent = state.active.last_log || "";
}

function renderUploads() {
  const current = state.uploads.filter((item) => item.caseName === state.active.name);
  const represented = new Set(current.filter((item) => item.status === "Uploaded").map((item) => item.name));
  const saved = (state.active.uploaded_files || [])
    .filter((item) => !represented.has(item.name))
    .map((item) => ({id: `saved-${item.path}`, name: item.name, size: item.size_bytes, progress: 100, status: "Uploaded", detail: `${formatBytes(item.size_bytes)} · SHA256 recorded`}));
  const items = [...current, ...saved];
  $("#uploadQueue").innerHTML = items.map((item) => `
    <div class="upload-item ${escapeHtml((item.status || "").toLowerCase())}">
      <strong>${escapeHtml(item.name)}</strong>
      ${["Uploading", "Finalizing"].includes(item.status) ? `<button class="upload-cancel" data-upload-id="${escapeHtml(item.id)}">Cancel</button>` : `<small>${escapeHtml(item.status || formatBytes(item.size))}</small>`}
      <small class="upload-meta">${escapeHtml(item.detail || formatBytes(item.size))}</small>
      <div class="progress"><i style="width:${Math.max(0, Math.min(100, Number(item.progress || 0)))}%"></i></div>
    </div>`).join("");
  $$(".upload-cancel").forEach((button) => button.addEventListener("click", () => {
    const item = state.uploads.find((candidate) => candidate.id === button.dataset.uploadId);
    item?.xhr?.abort();
  }));
}

function renderTab() {
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === state.tab));
  const query = $("#tableSearch").value.trim().toLowerCase();
  if (state.tab === "leads") renderLeads(query);
  else if (state.tab === "findings") renderFindings(query);
  else if (state.tab === "timeline") renderTimeline(query);
  else renderReport();
}

function renderLeads(query) {
  const rows = (state.active.leads || []).filter((item) => JSON.stringify(item).toLowerCase().includes(query));
  if (!rows.length) return emptyTable("No leads yet. Run triage to seed evidence-backed investigation leads.");
  $("#tabContent").innerHTML = `<table><thead><tr><th>ID</th><th>Entity</th><th>Priority</th><th>Score</th><th>Evidence</th><th>Status</th></tr></thead><tbody>${rows.map((item) => `
    <tr><td><strong>${escapeHtml(item.id)}</strong></td><td><strong>${escapeHtml(item.value)}</strong><br><small>${escapeHtml(item.type || "other")}</small></td><td><span class="badge ${escapeHtml(item.priority)}">${escapeHtml(item.priority)}</span></td><td>${escapeHtml(item.score ?? "—")}</td><td>${escapeHtml(item.independent_family_count ?? 0)} families<br><small>${escapeHtml(item.reason || "")}</small></td><td><span class="badge ${escapeHtml(item.status)}">${escapeHtml(item.status || "active")}</span></td></tr>`).join("")}</tbody></table>`;
}

function renderFindings(query) {
  const rows = (state.active.findings || []).filter((item) => JSON.stringify(item).toLowerCase().includes(query));
  if (!rows.length) return emptyTable("No structured findings yet. Leads must be corroborated before promotion.");
  $("#tabContent").innerHTML = `<table><thead><tr><th>ID</th><th>Finding</th><th>Class</th><th>Severity</th><th>Confidence</th><th>Corroboration</th></tr></thead><tbody>${rows.map((item) => `
    <tr><td><strong>${escapeHtml(item.id)}</strong></td><td><strong>${escapeHtml(item.title || item.details)}</strong></td><td><span class="badge ${escapeHtml(item.kind)}">${escapeHtml(item.kind)}</span></td><td>${escapeHtml(item.severity || "—")}</td><td>${escapeHtml(item.confidence || "—")}</td><td>${escapeHtml((item.artifact_families || []).join(", ") || "Not recorded")}</td></tr>`).join("")}</tbody></table>`;
}

function renderTimeline(query) {
  const rows = (state.timeline || []).filter((item) => JSON.stringify(item).toLowerCase().includes(query));
  if (!rows.length) return emptyTable("The targeted timeline will appear after lead correlation.");
  const columns = [...new Set(rows.flatMap((item) => Object.keys(item)))].slice(0, 6);
  $("#tabContent").innerHTML = `<table><thead><tr>${columns.map((key) => `<th>${escapeHtml(key.replaceAll("_", " "))}</th>`).join("")}</tr></thead><tbody>${rows.map((item) => `<tr>${columns.map((key) => `<td>${escapeHtml(item[key] || "")}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}

function renderReport() {
  if (!state.active.report_available && !state.active.report_ready && !state.report) return emptyTable("The report will appear after the first assessment pass.");
  $("#tabContent").innerHTML = `<div class="report-actions"><button class="secondary" id="downloadReport">Download report</button></div><pre class="report-view">${escapeHtml(state.report || "Report is ready for download.")}</pre>`;
  $("#downloadReport")?.addEventListener("click", () => {
    if (state.api) window.location.href = `/api/cases/${encodeURIComponent(state.active.name)}/report/download`;
    else toast("Downloads are enabled in the local Aries console.");
  });
}

function emptyTable(message) {
  $("#tabContent").innerHTML = `<div class="empty-table"><div>${escapeHtml(message)}</div></div>`;
}

async function createCase(event) {
  event.preventDefault();
  const name = $("#caseNameInput").value.trim();
  const description = $("#caseDescriptionInput").value.trim();
  if (!name) return;
  try {
    if (state.api) {
      await request("/api/cases", {method: "POST", body: JSON.stringify({name, description})});
      await refreshCases(name);
    } else {
      const newCase = {name, description, status: "draft", registered: false, running: false, report_available: false, report_ready: false, evidence: [], uploaded_files: [], phases: [], leads: [], findings: []};
      state.cases.unshift(newCase);
      await openCase(name);
    }
    $("#newCaseDialog").close();
    event.target.reset();
    toast(`Case ${name} created`);
  } catch (error) { toast(error.message, true); }
}

async function uploadFiles(files) {
  if (!state.active) return toast("Create or select a case first", true);
  const list = [...files];
  $("#fileInput").value = "";
  for (const file of list) {
    const row = {id: `upload-${++state.uploadSequence}`, caseName: state.active.name, name: file.name, size: file.size, progress: 0, status: "Uploading", detail: `0 B of ${formatBytes(file.size)}`};
    state.uploads.push(row);
    renderUploads();
    try {
      if (state.api) {
        await uploadArtifact(file, row);
      } else {
        for (const progress of [24, 51, 78, 100]) { await new Promise((resolve) => setTimeout(resolve, 180)); row.progress = progress; renderUploads(); }
        state.active.uploaded_files.push({name: file.name, size_bytes: file.size, path: `evidence/${file.name}`});
      }
      row.progress = 100;
      row.status = "Uploaded";
      row.detail = `${formatBytes(file.size)} · SHA256 recorded`;
      renderUploads();
    } catch (error) {
      if (row.status !== "Cancelled") row.status = "Failed";
      row.detail = error.message;
      renderUploads();
      if (row.status !== "Cancelled") toast(`${file.name}: ${error.message}`, true);
    }
  }
  if (state.api) await openCase(state.active.name); else renderWorkspace();
}

function uploadArtifact(file, row) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    row.xhr = xhr;
    const started = performance.now();
    xhr.open("POST", `/api/cases/${encodeURIComponent(row.caseName)}/artifacts`);
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.setRequestHeader("X-Aries-Filename", encodeURIComponent(file.name));
    xhr.setRequestHeader("X-Aries-Relative-Path", encodeURIComponent(file.webkitRelativePath || file.name));
    xhr.setRequestHeader("X-Aries-Size", String(file.size));
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const elapsed = Math.max((performance.now() - started) / 1000, .1);
      const speed = event.loaded / elapsed;
      row.progress = Math.round(event.loaded / event.total * 1000) / 10;
      row.status = "Uploading";
      row.detail = `${formatBytes(event.loaded)} of ${formatBytes(event.total)} · ${formatBytes(speed)}/s · ${formatDuration((event.total - event.loaded) / speed)} left`;
      renderUploads();
    };
    xhr.upload.onload = () => {
      row.progress = 100;
      row.status = "Finalizing";
      row.detail = `${formatBytes(file.size)} transferred · verifying SHA256`;
      renderUploads();
    };
    xhr.onload = () => {
      row.xhr = null;
      if (xhr.status >= 200 && xhr.status < 300) {
        try { resolve(JSON.parse(xhr.responseText)); } catch (_) { resolve({}); }
        return;
      }
      let detail = `${xhr.status} ${xhr.statusText}`;
      try { detail = JSON.parse(xhr.responseText).detail || detail; } catch (_) {}
      reject(new Error(detail));
    };
    xhr.onerror = () => { row.xhr = null; reject(new Error("Network or local service error during upload")); };
    xhr.onabort = () => {
      row.xhr = null;
      row.status = "Cancelled";
      row.detail = `${formatBytes(row.progress / 100 * file.size)} transferred before cancellation`;
      renderUploads();
      reject(new Error("Upload cancelled"));
    };
    xhr.send(file);
  });
}

async function registerEvidence() {
  try {
    if (state.api) {
      await request(`/api/cases/${encodeURIComponent(state.active.name)}/register`, {method: "POST", body: JSON.stringify({description: state.active.description || ""})});
      await refreshCases(state.active.name);
    } else {
      state.active.registered = true;
      state.active.status = "ready";
      state.active.evidence = state.active.uploaded_files.map((item) => ({...item, kind: "artifact"}));
      state.active.phases = Object.keys(PHASE_LABELS).map((name) => ({name, status: "pending", attempts: 0}));
      renderWorkspace();
    }
    toast("Evidence registered. Investigation is ready.");
  } catch (error) { toast(error.message, true); }
}

function openInvestigationDialog() {
  if (!state.active?.registered) return toast("Register evidence before running the investigation", true);
  if (state.active.running) return;
  $("#investigationInstructions").value = state.active.investigation_brief?.instructions || "";
  $("#investigationDialog").showModal();
}

async function runInvestigation(event) {
  event.preventDefault();
  if (!state.active?.registered) return toast("Register evidence before running the investigation", true);
  const instructions = $("#investigationInstructions").value.trim();
  $("#investigationDialog").close();
  try {
    $("#terminalDrawer").classList.add("open");
    $("#terminalStatus").textContent = "Starting evidence workflow…";
    $("#terminalOutput").textContent = "Starting the Aries coordinator. Any launch or authentication error will appear here automatically.";
    if (state.api) {
      await request(`/api/cases/${encodeURIComponent(state.active.name)}/investigate`, {method: "POST", body: JSON.stringify({mode: "quick", instructions})});
      await openCase(state.active.name);
      await openTerminal();
    } else {
      state.active.running = true;
      state.active.status = "investigating";
      state.active.phases.forEach((phase) => { phase.status = "pending"; phase.attempts = 0; });
      renderWorkspace();
      simulateInvestigation(0);
    }
    toast(instructions ? "Investigation started with analyst brief" : "Investigation started");
  } catch (error) {
    if (state.api && state.active) {
      try { await openCase(state.active.name); } catch (_) {}
      await openTerminal();
    }
    toast(error.message, true);
  }
}

async function stopInvestigation() {
  if (!state.active?.running) return;
  if (!window.confirm(`Stop the investigation for ${state.active.name}? The complete Aries process tree will be terminated.`)) return;
  const name = state.active.name;
  $("#terminalStatus").textContent = "Stopping investigation process tree…";
  $("#stopButton").disabled = true;
  $("#terminalStopButton").disabled = true;
  try {
    if (state.api) {
      await request(`/api/cases/${encodeURIComponent(name)}/stop`, {method: "POST"});
      await openCase(name);
      await refreshActivity();
    } else {
      state.active.running = false;
      state.active.status = "stopped";
      renderWorkspace();
    }
    toast("Investigation stopped. You can now resume or delete the case.");
  } catch (error) {
    toast(error.message, true);
  } finally {
    $("#stopButton").disabled = false;
    $("#terminalStopButton").disabled = false;
  }
}

function simulateInvestigation(index) {
  if (!state.active?.running) return;
  if (index >= state.active.phases.length) {
    state.active.running = false;
    state.active.status = "complete";
    state.active.report_available = true;
    state.active.report_ready = true;
    state.report = "# Aries Incident Report\n\nStatus: READY\n\nThe interface preview completed a simulated evidence-gated workflow. The local console runs the real Aries engine and produces the full report from case evidence.";
    renderWorkspace();
    toast("Evidence-gated report is ready");
    return;
  }
  if (index > 0) state.active.phases[index - 1].status = "complete";
  state.active.phases[index].status = "running";
  state.active.phases[index].attempts = 1;
  state.active.last_log = `PHASE=${state.active.phases[index].name}\nSTATUS=RUNNING\nFull output is being written to the local case log.`;
  renderWorkspace();
  setTimeout(() => simulateInvestigation(index + 1), 420);
}

function startPolling() {
  clearInterval(state.poller);
  if (!state.api || !state.active?.running) return;
  state.poller = setInterval(async () => {
    if (!state.active) return;
    try {
      const updated = await request(`/api/cases/${encodeURIComponent(state.active.name)}`);
      const wasRunning = state.active.running;
      state.active = updated;
      renderWorkspace();
      if (wasRunning && !updated.running) {
        clearInterval(state.poller);
        toast(
          updated.report_ready
            ? "Investigation complete. Report complete."
            : updated.processing_retry_required
              ? "Artifact processing failed. Retry artifact processing; the existing evidence and report were preserved."
              : updated.report_available
                ? "Partial report generated. Retry AI synthesis when the model is available."
                : "Investigation stopped. Review the case status.",
          !updated.report_available
        );
      }
    } catch (_) {}
  }, 3500);
}

async function refreshActivity() {
  if (!state.active) return;
  if (!state.api) {
    $("#terminalOutput").textContent = state.active.last_log || "Demo mode has no local command transcript.";
    $("#terminalStatus").textContent = state.active.running ? "Simulation running" : "Demo activity";
    return;
  }
  try {
    const activity = await request(`/api/cases/${encodeURIComponent(state.active.name)}/activity`);
    const output = $("#terminalOutput");
    const pinned = output.scrollHeight - output.scrollTop - output.clientHeight < 45;
    output.textContent = activity.text;
    if (pinned) output.scrollTop = output.scrollHeight;
    const usage = activity.usage || {};
    const cost = Number.isFinite(Number(usage.estimated_cost_usd)) ? ` · $${Number(usage.estimated_cost_usd).toFixed(4)}` : "";
    const model = usage.model ? ` · ${usage.model}` : "";
    $("#terminalStatus").textContent = `${activity.running ? "Running" : activity.status}${model}${cost} · refreshed ${new Date().toLocaleTimeString()}`;
  } catch (error) {
    $("#terminalStatus").textContent = `Unable to load activity: ${error.message}`;
  }
}

async function openTerminal() {
  if (!state.active) return;
  $("#terminalDrawer").classList.add("open");
  await refreshActivity();
  clearInterval(state.activityPoller);
  state.activityPoller = setInterval(refreshActivity, 1000);
}

function closeTerminal() {
  $("#terminalDrawer")?.classList.remove("open");
  clearInterval(state.activityPoller);
  state.activityPoller = null;
}

function openDeleteDialog() {
  if (!state.active || state.active.running) return;
  $("#deleteCaseExpected").textContent = state.active.name;
  $("#deleteCaseConfirmation").value = "";
  $("#deleteCaseDialog").showModal();
}

async function deleteActiveCase(event) {
  event.preventDefault();
  if (!state.active) return;
  const name = state.active.name;
  const confirmation = $("#deleteCaseConfirmation").value;
  if (confirmation !== name) return toast("Type the exact case name to confirm deletion", true);
  try {
    if (state.api) {
      await request(`/api/cases/${encodeURIComponent(name)}`, {method: "DELETE", body: JSON.stringify({confirmation})});
    } else {
      state.cases = state.cases.filter((item) => item.name !== name);
    }
    state.uploads = state.uploads.filter((item) => item.caseName !== name);
    state.active = null;
    closeTerminal();
    $("#deleteCaseDialog").close();
    if (state.api) await refreshCases(); else { renderCaseList(); showEmpty(); }
    toast(`Case ${name} and all contents deleted`);
  } catch (error) { toast(error.message, true); }
}

async function askAries(event) {
  event.preventDefault();
  const input = $("#assistantInput");
  const question = input.value.trim();
  if (!question || !state.active) return;
  appendMessage(question, "user-message");
  input.value = "";
  const pending = appendMessage("Reviewing the active case…", "assistant-message");
  try {
    const response = state.api
      ? await request(`/api/cases/${encodeURIComponent(state.active.name)}/assistant`, {method: "POST", body: JSON.stringify({question})})
      : {answer: "Direct observation: Sysmon records CrackedSoftware.exe connecting to 192.168.112.153:8080 shortly after execution. Defender and filesystem artifacts independently support the executable’s presence. Inference: port 8080 is consistent with a callback channel, while port 8000 is better described as delivery infrastructure. The driver-service relationship remains unresolved.\n\n[output/event_triage.json:L20-L40]", datalake: {status: "ready", indexed_files: 42, indexed_chunks: 1800}};
    pending.textContent = response.answer;
    state.active.datalake = response.datalake || state.active.datalake;
    const lake = state.active.datalake || {};
    $("#assistantLakeStatus").textContent = `${lake.indexed_files || 0} files · ${lake.indexed_chunks || 0} searchable chunks · active case only`;
  } catch (error) { pending.textContent = `Unable to answer: ${error.message}`; }
}

function appendMessage(text, className) {
  const node = document.createElement("div");
  node.className = className;
  node.textContent = text;
  $("#chatMessages").append(node);
  node.scrollIntoView({behavior: "smooth", block: "end"});
  return node;
}

function openDialog() { $("#newCaseDialog").showModal(); }

$("#newCaseButton").addEventListener("click", openDialog);
$("#emptyNewCase").addEventListener("click", openDialog);
$("#newCaseForm").addEventListener("submit", createCase);
$("#closeNewCase").addEventListener("click", () => $("#newCaseDialog").close());
$("#cancelNewCase").addEventListener("click", () => $("#newCaseDialog").close());
$("#runButton").addEventListener("click", openInvestigationDialog);
$("#investigationForm").addEventListener("submit", runInvestigation);
$("#closeInvestigationDialog").addEventListener("click", () => $("#investigationDialog").close());
$("#cancelInvestigation").addEventListener("click", () => $("#investigationDialog").close());
$("#stopButton").addEventListener("click", stopInvestigation);
$("#terminalStopButton").addEventListener("click", stopInvestigation);
$("#terminalButton").addEventListener("click", openTerminal);
$("#closeTerminal").addEventListener("click", closeTerminal);
$("#refreshTerminal").addEventListener("click", refreshActivity);
$("#downloadDiagnostics").addEventListener("click", () => {
  if (!state.active) return;
  if (state.api) window.location.href = `/api/cases/${encodeURIComponent(state.active.name)}/diagnostics`;
  else toast("Diagnostics are generated by the local Aries service.");
});
$("#deleteCaseButton").addEventListener("click", openDeleteDialog);
$("#deleteCaseForm").addEventListener("submit", deleteActiveCase);
$("#closeDeleteCase").addEventListener("click", () => $("#deleteCaseDialog").close());
$("#cancelDeleteCase").addEventListener("click", () => $("#deleteCaseDialog").close());
$("#registerButton").addEventListener("click", registerEvidence);
$("#bundleButton").addEventListener("click", () => {
  if (state.api) window.location.href = `/api/cases/${encodeURIComponent(state.active.name)}/bundle`;
  else toast("Case bundle export is enabled in the local console.");
});
$("#dropzone").addEventListener("click", () => $("#fileInput").click());
$("#addEvidenceButton").addEventListener("click", () => $("#fileInput").click());
$("#fileInput").addEventListener("change", (event) => uploadFiles(event.target.files));
$("#dropzone").addEventListener("dragover", (event) => { event.preventDefault(); event.currentTarget.classList.add("dragging"); });
$("#dropzone").addEventListener("dragleave", (event) => event.currentTarget.classList.remove("dragging"));
$("#dropzone").addEventListener("drop", (event) => { event.preventDefault(); event.currentTarget.classList.remove("dragging"); uploadFiles(event.dataTransfer.files); });
$("#dropzone").addEventListener("keydown", (event) => { if (["Enter", " "].includes(event.key)) $("#fileInput").click(); });
$$('.tab').forEach((tab) => tab.addEventListener("click", () => { state.tab = tab.dataset.tab; renderTab(); }));
$("#tableSearch").addEventListener("input", renderTab);
$("#assistantFab").addEventListener("click", () => $("#assistantPanel").classList.add("open"));
$("#assistantButton").addEventListener("click", () => $("#assistantPanel").classList.add("open"));
$("#closeAssistant").addEventListener("click", () => $("#assistantPanel").classList.remove("open"));
$("#assistantForm").addEventListener("submit", askAries);
$("#modelButton").addEventListener("click", async () => { if (state.api) await refreshModel(); $("#modelDialog").showModal(); });
$("#closeModelDialog").addEventListener("click", () => $("#modelDialog").close());
$("#refreshModelButton").addEventListener("click", refreshModel);
$("#copyModelCommands").addEventListener("click", async () => {
  const commands = "hermes -p aries model";
  try { await navigator.clipboard.writeText(commands); toast("Model commands copied"); }
  catch (_) { toast("Copy failed. Select the commands manually.", true); }
});

initialize();
