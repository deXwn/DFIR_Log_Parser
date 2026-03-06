const rootInput = document.getElementById("rootPath");
const runDetectionsButton = document.getElementById("runDetectionsButton");
const detectionRulesInput = document.getElementById("detectionRules");
const customRuleNameInput = document.getElementById("customRuleName");
const saveCustomRuleButton = document.getElementById("saveCustomRuleButton");
const clearRuleSelectionButton = document.getElementById("clearRuleSelectionButton");
const refreshDetectionsButton = document.getElementById("refreshDetectionsButton");
const detectionsStatus = document.getElementById("detectionsStatus");
const detectionsBox = document.getElementById("detectionsBox");
const detectionsPrevButton = document.getElementById("detectionsPrevButton");
const detectionsNextButton = document.getElementById("detectionsNextButton");
const detectionsPageInfo = document.getElementById("detectionsPageInfo");
const includeFalsePositivesCheckbox = document.getElementById("includeFalsePositives");
const exportDetectionsCsvCheckbox = document.getElementById("exportDetectionsCsv");
const rulePresetButtons = document.getElementById("rulePresetButtons");
const customRuleButtons = document.getElementById("customRuleButtons");
const ROOT_PATH_STORAGE_KEY = "dfir_detection_root_path";

const state = {
  detectionsLoading: false,
  detectionsNextCursor: null,
  detectionsCursors: [null],
  detectionsCursorIndex: 0,
  detectionsRunId: null,
  activeRuleId: null,
  activeRuleSource: null,
  customRules: [],
};

const RULE_PRESETS = [
  {
    label: "Failed Burst",
    rule: {
      id: "failed_burst",
      name: "Failed Login Burst",
      severity: "high",
      regex: "failed|login|denied",
      conditions: [{ field: "status", op: "eq", value: "401" }],
      threshold: 5,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "SQLi Probe",
    rule: {
      id: "sqli_probe",
      name: "SQL Injection Probe",
      severity: "high",
      regex: "union\\s+select|or\\s+1=1|information_schema|sleep\\(|benchmark\\(",
      threshold: 3,
      time_window_seconds: 120,
      group_by: "src_ip",
    },
  },
  {
    label: "Path Traversal",
    rule: {
      id: "path_traversal_probe",
      name: "Path Traversal Probe",
      severity: "high",
      regex: "\\.\\./|%2e%2e%2f|%252e%252e%252f|\\.\\.\\\\",
      threshold: 5,
      time_window_seconds: 180,
      group_by: "src_ip",
    },
  },
  {
    label: "Cmd Injection",
    rule: {
      id: "command_injection_probe",
      name: "Command Injection Probe",
      severity: "high",
      regex: "(;|\\|\\||&&)\\s*(whoami|id|uname|curl|wget|powershell|cmd\\.exe|/bin/sh)",
      threshold: 3,
      time_window_seconds: 180,
      group_by: "src_ip",
    },
  },
  {
    label: "Webshell IOC",
    rule: {
      id: "webshell_activity",
      name: "Webshell IOC Pattern",
      severity: "critical",
      regex: "cmd=|c99|r57|webshell|shell\\.php|eval\\(|assert\\(",
      threshold: 2,
      time_window_seconds: 120,
      group_by: "src_ip",
    },
  },
  {
    label: "Scanner UA",
    rule: {
      id: "scanner_user_agent",
      name: "Known Scanner User-Agent",
      severity: "medium",
      regex: "sqlmap|nikto|masscan|nmap|acunetix|nessus|dirbuster|gobuster|wpscan",
      threshold: 3,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "Large Transfer",
    rule: {
      id: "large_transfer",
      name: "Large Transfer Burst",
      severity: "critical",
      regex: "GET|POST|download|export",
      conditions: [{ field: "bytes_received", op: "gte", value: "5000000" }],
      threshold: 3,
      time_window_seconds: 120,
      group_by: "src_ip",
    },
  },
  {
    label: "Encoded Payload",
    rule: {
      id: "encoded_payload",
      name: "Encoded Payload Pattern",
      severity: "medium",
      regex: "frombase64string|base64_decode\\(|[A-Za-z0-9+/]{200,}={0,2}",
      threshold: 2,
      time_window_seconds: 120,
      group_by: "src_ip",
    },
  },
  {
    label: "C2 Beacon",
    rule: {
      id: "c2_beacon_pattern",
      name: "C2 Beacon URI Pattern",
      severity: "high",
      regex: "/beacon|/checkin|/gate|/api/v1/ping|jitter|sleep\\s+\\d+",
      threshold: 6,
      time_window_seconds: 600,
      group_by: "src_ip",
    },
  },
  {
    label: "Archive Staging",
    rule: {
      id: "archive_staging",
      name: "Archive Staging / Exfil Prep",
      severity: "medium",
      regex: "\\.(7z|rar|zip|iso)\\b|rclone|mega\\.|dropbox|onedrive",
      threshold: 4,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "5xx Burst",
    rule: {
      id: "http_5xx_burst",
      name: "HTTP 5xx Burst",
      severity: "medium",
      conditions: [{ field: "status", op: "gte", value: "500" }],
      threshold: 10,
      time_window_seconds: 180,
      group_by: "dst_ip",
    },
  },
  {
    label: "SSH Bruteforce",
    rule: {
      id: "ssh_bruteforce",
      name: "SSH Bruteforce Pattern",
      severity: "high",
      regex: "failed password|authentication failure|invalid user",
      threshold: 10,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "RDP Failed Logon",
    rule: {
      id: "rdp_failed_logon_burst",
      name: "RDP Failed Logon Burst",
      severity: "high",
      regex: "EventCode=4625|An account failed to log on|Logon Type:\\s*10",
      threshold: 8,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "Kerberoast",
    rule: {
      id: "kerberoast_pattern",
      name: "Kerberoast Indicators",
      severity: "high",
      regex: "EventCode=4769|Ticket Encryption Type:\\s*0x17|Kerberoast",
      threshold: 3,
      time_window_seconds: 600,
      group_by: "src_ip",
    },
  },
  {
    label: "PowerShell IOC",
    rule: {
      id: "powershell_ioc",
      name: "PowerShell IOC Keywords",
      severity: "high",
      regex: "powershell|certutil|bitsadmin|mshta",
      threshold: 2,
      time_window_seconds: 120,
      group_by: "src_ip",
    },
  },
  {
    label: "DCSync IOC",
    rule: {
      id: "dcsync_pattern",
      name: "DCSync / Replication Abuse",
      severity: "critical",
      regex: "lsadump::dcsync|drsuapi|Replicating Directory Changes|mimikatz",
      threshold: 1,
      group_by: "global",
    },
  },
  {
    label: "Lateral Move",
    rule: {
      id: "lateral_movement_admin_share",
      name: "Lateral Movement via Admin Share",
      severity: "high",
      regex: "psexec|wmic\\s+process\\s+call\\s+create|winrm|\\\\\\\\[^\\\\]+\\\\ADMIN\\$|schtasks\\s+/create",
      threshold: 2,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
  {
    label: "Suspicious Admin",
    rule: {
      id: "suspicious_admin_path",
      name: "Suspicious Admin Endpoint",
      severity: "medium",
      regex: "/admin|/wp-admin|/phpmyadmin|/manager/html",
      threshold: 4,
      time_window_seconds: 300,
      group_by: "src_ip",
    },
  },
];

const DEFAULT_RULE_ID_SET = new Set(
  RULE_PRESETS.map((preset) => String(preset.rule.id || "").trim()).filter(Boolean)
);

const setDetectionStatus = (message, level = "info") => {
  detectionsStatus.textContent = message;
  detectionsStatus.classList.remove("error", "ok", "info");
  if (message) {
    detectionsStatus.classList.add(level);
  }
};

const parseDetectionRules = () => {
  const raw = detectionRulesInput.value.trim();
  if (!raw) return [];
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (_) {
    throw new Error("Rules JSON is invalid.");
  }
  if (Array.isArray(parsed)) return parsed;
  if (parsed && typeof parsed === "object") return [parsed];
  throw new Error("Rules JSON must be an array or a single object.");
};

const resetDetectionsPagination = () => {
  state.detectionsNextCursor = null;
  state.detectionsCursors = [null];
  state.detectionsCursorIndex = 0;
};

const updateDetectionsPagination = () => {
  detectionsPrevButton.disabled =
    state.detectionsLoading || state.detectionsCursorIndex === 0;
  detectionsNextButton.disabled =
    state.detectionsLoading || !state.detectionsNextCursor;
  detectionsPageInfo.textContent = `Detections page ${
    state.detectionsCursorIndex + 1
  }`;
};

const setDetectionsLoading = (value) => {
  state.detectionsLoading = value;
  runDetectionsButton.disabled = value;
  refreshDetectionsButton.disabled = value;
  saveCustomRuleButton.disabled = value;
  clearRuleSelectionButton.disabled = value;
  updateDetectionsPagination();
};

const buildDetectionsPayload = () => ({
  root_path: rootInput.value.trim(),
  terms: [],
  none: [],
  page: 1,
  page_size: 100,
  export_csv: false,
  status_code: null,
  case_sensitive: false,
  ip_scope: null,
  match_mode: "any",
  min_bytes_received: null,
  sort_mode: "file_position",
});

const runDetections = async () => {
  const payload = buildDetectionsPayload();
  if (!payload.root_path) {
    setDetectionStatus("Root path cannot be empty.", "error");
    return;
  }

  try {
    payload.rules = parseDetectionRules();
  } catch (error) {
    setDetectionStatus(error.message, "error");
    return;
  }

  if (!payload.rules.length) {
    setDetectionStatus("At least one rule is required.", "error");
    return;
  }

  setDetectionsLoading(true);
  setDetectionStatus("Running detections and persisting hits...", "info");
  try {
    const response = await fetch("/detections/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Detection run failed");
    }
    const data = await response.json();
    setDetectionStatus(
      `Run #${data.run_id} persisted ${formatNumber(data.total_hits)} hits in ${data.duration_ms} ms.`,
      "ok"
    );
    state.detectionsRunId = data.run_id;
    resetDetectionsPagination();
    await loadDetections(null, data.run_id);
    if (exportDetectionsCsvCheckbox.checked) {
      await exportDetectionsCsv();
    }
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  } finally {
    setDetectionsLoading(false);
  }
};

const loadDetections = async (cursor = null, runId = state.detectionsRunId) => {
  if (runId === null || runId === undefined) {
    setDetectionStatus("Use Run detections first.", "info");
    detectionsBox.textContent = "";
    return;
  }

  setDetectionsLoading(true);
  try {
    const params = new URLSearchParams({
      page_size: "20",
      sort_order: "desc",
      include_false_positives: includeFalsePositivesCheckbox.checked
        ? "true"
        : "false",
      run_id: String(runId),
    });
    if (cursor) {
      params.set("cursor", cursor);
    }
    const response = await fetch(`/detections/hits?${params.toString()}`);
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Failed to load detections");
    }
    const data = await response.json();
    state.detectionsNextCursor = data.next_cursor || null;
    renderDetections(data.hits || []);
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  } finally {
    setDetectionsLoading(false);
  }
};

const toggleFalsePositive = async (hitId, value) => {
  try {
    const response = await fetch(`/detections/hits/${hitId}/false_positive`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        value,
        note: value ? "Marked from UI" : null,
      }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Could not update false positive");
    }
    await loadDetections(
      state.detectionsCursors[state.detectionsCursorIndex],
      state.detectionsRunId
    );
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  }
};

const renderDetections = (hits) => {
  if (!hits.length) {
    detectionsBox.textContent = "No hits for current run.";
    updateDetectionsPagination();
    return;
  }

  detectionsBox.innerHTML = "";
  hits.forEach((hit) => {
    const item = document.createElement("div");
    item.className = "detection-hit";

    const head = document.createElement("div");
    head.className = "detection-head";
    const title = document.createElement("strong");
    title.textContent = hit.rule_name || hit.rule_id;
    const sev = document.createElement("span");
    const severityClass = (hit.severity || "medium").toLowerCase();
    sev.className = `severity-badge severity-${severityClass}`;
    sev.textContent = hit.severity || "medium";
    head.appendChild(title);
    head.appendChild(sev);

    const meta = document.createElement("div");
    meta.className = "detection-meta";
    const windowText =
      hit.window_start && hit.window_end
        ? `window: ${new Date(hit.window_start * 1000).toISOString()} → ${new Date(
            hit.window_end * 1000
          ).toISOString()}`
        : "window: n/a";
    meta.textContent = `${hit.file_path}:${hit.line_number} | ${windowText}`;

    const line = document.createElement("pre");
    line.className = "detection-line";
    line.innerHTML = syntaxHighlight(escapeHtml(hit.line));

    const actions = document.createElement("div");
    actions.className = "detection-actions";
    const fpBtn = document.createElement("button");
    fpBtn.type = "button";
    fpBtn.className = "secondary";
    fpBtn.textContent = hit.false_positive
      ? "Unmark false positive"
      : "Mark false positive";
    fpBtn.onclick = () => toggleFalsePositive(hit.id, !hit.false_positive);
    actions.appendChild(fpBtn);

    item.appendChild(head);
    item.appendChild(meta);
    item.appendChild(line);
    item.appendChild(actions);
    detectionsBox.appendChild(item);
  });
  updateDetectionsPagination();
};

const formatNumber = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "0";
  return Number(value).toLocaleString("en-US");
};

const syntaxHighlight = (text) => {
  return text
    .replace(
      /\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b/g,
      (m) => `<span class="hl-date">${m}</span>`
    )
    .replace(
      /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
      (m) => `<span class="hl-ip">${m}</span>`
    )
    .replace(
      /\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b/g,
      (m) => `<span class="hl-method">${m}</span>`
    )
    .replace(/\b(\d{3})\b/g, (m, code) => {
      const n = Number(code);
      const cls =
        n >= 500
          ? "hl-status-err"
          : n >= 400
          ? "hl-status-warn"
          : "hl-status-ok";
      return `<span class="${cls}">${m}</span>`;
    });
};

const escapeHtml = (text) =>
  text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const slugifyRuleName = (text) => {
  const normalized = text
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
  return normalized || "custom_rule";
};

const updateActiveRuleVisuals = () => {
  const allButtons = document.querySelectorAll(".rule-preset-button");
  allButtons.forEach((button) => {
    const id = button.dataset.ruleId || "";
    const source = button.dataset.ruleSource || "";
    const isActive = id === state.activeRuleId && source === state.activeRuleSource;
    button.classList.toggle("active", isActive);
  });
};

const setActiveRule = (id, source) => {
  state.activeRuleId = id || null;
  state.activeRuleSource = source || null;
  updateActiveRuleVisuals();
};

const loadRuleIntoEditor = (rule, source) => {
  detectionRulesInput.value = JSON.stringify([rule], null, 2);
  customRuleNameInput.value = rule.name || "";
  setActiveRule(rule.id || null, source);
  setDetectionStatus(
    `Loaded rule: ${rule.name || rule.id || "unnamed"}. You can edit and run.`,
    "info"
  );
  detectionRulesInput.focus();
};

const loadPresetRule = (preset) => {
  loadRuleIntoEditor(preset.rule, "default");
};

const clearRuleSelection = () => {
  customRuleNameInput.value = "";
  detectionRulesInput.value = "";
  setActiveRule(null, null);
  setDetectionStatus("Rule editor cleared.", "info");
};

const listPersistedRules = async () => {
  const response = await fetch("/detections/rules");
  if (!response.ok) {
    const err = await response.json().catch(() => null);
    throw new Error(err?.error || "Failed to load saved rules");
  }
  return response.json();
};

const renderCustomRuleButtons = () => {
  if (!customRuleButtons) return;
  customRuleButtons.innerHTML = "";

  if (!state.customRules.length) {
    const empty = document.createElement("div");
    empty.className = "rule-preset-empty";
    empty.textContent = "No custom rules yet.";
    customRuleButtons.appendChild(empty);
    return;
  }

  state.customRules.forEach((rule) => {
    const item = document.createElement("div");
    item.className = "rule-preset-item";

    const loadButton = document.createElement("button");
    loadButton.type = "button";
    loadButton.className = "secondary rule-preset-button";
    loadButton.textContent = rule.name || rule.id;
    loadButton.title = `${rule.name || rule.id} (${rule.id})`;
    loadButton.dataset.ruleId = rule.id;
    loadButton.dataset.ruleSource = "custom";
    loadButton.addEventListener("click", () => loadRuleIntoEditor(rule, "custom"));

    const deleteButton = document.createElement("button");
    deleteButton.type = "button";
    deleteButton.className = "secondary rule-delete-button";
    deleteButton.textContent = "Delete";
    deleteButton.addEventListener("click", () => deleteCustomRule(rule.id));

    item.appendChild(loadButton);
    item.appendChild(deleteButton);
    customRuleButtons.appendChild(item);
  });

  updateActiveRuleVisuals();
};

const refreshCustomRules = async () => {
  try {
    const persisted = await listPersistedRules();
    const customOnly = [];
    for (const item of persisted || []) {
      const id = String(item.id || "").trim();
      if (!id || DEFAULT_RULE_ID_SET.has(id)) continue;
      let parsedRule;
      try {
        parsedRule = JSON.parse(item.definition_json);
      } catch (_) {
        continue;
      }
      if (!parsedRule || typeof parsedRule !== "object") continue;
      parsedRule.id = id;
      parsedRule.name = (item.name || parsedRule.name || id).trim();
      customOnly.push(parsedRule);
    }
    state.customRules = customOnly;
    renderCustomRuleButtons();
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  }
};

const saveCustomRule = async () => {
  let parsedRules;
  try {
    parsedRules = parseDetectionRules();
  } catch (error) {
    setDetectionStatus(error.message, "error");
    return;
  }

  if (parsedRules.length !== 1) {
    setDetectionStatus("Save supports exactly one rule object.", "error");
    return;
  }

  const candidate = { ...parsedRules[0] };
  const typedName = customRuleNameInput.value.trim();
  const resolvedName = typedName || String(candidate.name || "").trim();
  if (!resolvedName) {
    setDetectionStatus("Custom Rule Name is required.", "error");
    return;
  }

  let ruleId = String(candidate.id || "").trim();
  if (!ruleId || state.activeRuleSource !== "custom") {
    ruleId = `custom_${slugifyRuleName(resolvedName)}_${Date.now()}`;
  }

  const rule = {
    ...candidate,
    id: ruleId,
    name: resolvedName,
  };

  try {
    saveCustomRuleButton.disabled = true;
    const response = await fetch("/detections/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        rule,
        enabled: true,
      }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Failed to save custom rule");
    }
    await response.json();
    customRuleNameInput.value = resolvedName;
    setActiveRule(ruleId, "custom");
    setDetectionStatus(`Custom rule saved: ${resolvedName}`, "ok");
    await refreshCustomRules();
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  } finally {
    saveCustomRuleButton.disabled = false;
  }
};

const deleteCustomRule = async (ruleId) => {
  if (!ruleId) return;
  try {
    const response = await fetch(
      `/detections/rules/${encodeURIComponent(ruleId)}/delete`,
      {
        method: "POST",
      }
    );
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Failed to delete custom rule");
    }
    if (state.activeRuleSource === "custom" && state.activeRuleId === ruleId) {
      clearRuleSelection();
    }
    setDetectionStatus(`Custom rule deleted: ${ruleId}`, "ok");
    await refreshCustomRules();
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  }
};

const inferSelectedRuleIdForExport = () => {
  if (state.activeRuleId) {
    return state.activeRuleId;
  }

  try {
    const rules = parseDetectionRules();
    if (rules.length === 1 && typeof rules[0]?.id === "string") {
      const candidate = rules[0].id.trim();
      if (candidate) return candidate;
    }
  } catch (_) {
    // Ignore parse errors here; export can still continue without rule filter.
  }

  const active = document.querySelector(".rule-preset-button.active");
  const presetRuleId = active?.dataset?.ruleId?.trim();
  return presetRuleId || null;
};

const triggerDownload = (path) => {
  const link = document.createElement("a");
  link.href = path;
  link.download = "";
  document.body.appendChild(link);
  link.click();
  link.remove();
};

const exportDetectionsCsv = async () => {
  if (state.detectionsRunId === null || state.detectionsRunId === undefined) {
    setDetectionStatus("Run detections first, then export CSV.", "info");
    return;
  }

  const selectedRuleId = inferSelectedRuleIdForExport();
  setDetectionsLoading(true);
  setDetectionStatus("Preparing detection CSV export...", "info");
  try {
    const response = await fetch("/detections/export", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        run_id: state.detectionsRunId,
        rule_id: selectedRuleId,
        include_false_positives: includeFalsePositivesCheckbox.checked,
      }),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "Failed to export detections");
    }
    const data = await response.json();
    setDetectionStatus(
      `Exported ${formatNumber(data.total_rows)} rows to ${data.export_path}`,
      "ok"
    );
    triggerDownload(data.export_path);
  } catch (error) {
    console.error(error);
    setDetectionStatus(error.message, "error");
  } finally {
    setDetectionsLoading(false);
  }
};

const renderRulePresets = () => {
  if (!rulePresetButtons) return;
  rulePresetButtons.innerHTML = "";
  RULE_PRESETS.forEach((preset) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary rule-preset-button";
    button.textContent = preset.label;
    button.title = preset.rule.name;
    button.dataset.ruleId = preset.rule.id || "";
    button.dataset.ruleSource = "default";
    button.addEventListener("click", () => loadPresetRule(preset));
    rulePresetButtons.appendChild(button);
  });
  updateActiveRuleVisuals();
};

runDetectionsButton.addEventListener("click", () => {
  if (state.detectionsLoading) return;
  runDetections();
});

saveCustomRuleButton.addEventListener("click", () => {
  if (state.detectionsLoading) return;
  saveCustomRule();
});

clearRuleSelectionButton.addEventListener("click", () => {
  if (state.detectionsLoading) return;
  clearRuleSelection();
});

refreshDetectionsButton.addEventListener("click", () => {
  if (state.detectionsLoading) return;
  if (state.detectionsRunId === null || state.detectionsRunId === undefined) {
    setDetectionStatus("Use Run detections first.", "info");
    detectionsBox.textContent = "";
    return;
  }
  resetDetectionsPagination();
  loadDetections(null, state.detectionsRunId);
});

detectionsPrevButton.addEventListener("click", () => {
  if (state.detectionsLoading || state.detectionsCursorIndex === 0) return;
  state.detectionsCursorIndex -= 1;
  loadDetections(state.detectionsCursors[state.detectionsCursorIndex]);
});

detectionsNextButton.addEventListener("click", () => {
  if (state.detectionsLoading || !state.detectionsNextCursor) return;
  state.detectionsCursorIndex += 1;
  state.detectionsCursors[state.detectionsCursorIndex] = state.detectionsNextCursor;
  loadDetections(state.detectionsNextCursor);
});

includeFalsePositivesCheckbox.addEventListener("change", () => {
  resetDetectionsPagination();
  loadDetections(null, state.detectionsRunId);
});

const savedRootPath = window.localStorage.getItem(ROOT_PATH_STORAGE_KEY);
if (savedRootPath) {
  rootInput.value = savedRootPath;
}
rootInput.addEventListener("input", () => {
  window.localStorage.setItem(ROOT_PATH_STORAGE_KEY, rootInput.value.trim());
});

renderRulePresets();
refreshCustomRules();
setDetectionStatus("Enter root path + rules, then run detections.", "info");
updateDetectionsPagination();
