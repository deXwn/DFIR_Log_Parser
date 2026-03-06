const form = document.getElementById("search-form");
const rootInput = document.getElementById("rootPath");
const noneInput = document.getElementById("noneKeywords");
const pageSizeSelect = document.getElementById("pageSize");
const statusSelect = document.getElementById("statusCode");
const caseCheckbox = document.getElementById("caseSensitive");
const exportCheckbox = document.getElementById("exportCsv");
const searchButton = document.getElementById("searchButton");
const loadingIndicator = document.getElementById("loading");
const statusBox = document.getElementById("status");
const summaryBox = document.getElementById("summary");
const ipSummaryBox = document.getElementById("ipSummaryBox");
const resultsBody = document.getElementById("resultsBody");
const prevButton = document.getElementById("prevButton");
const nextButton = document.getElementById("nextButton");
const pageInfo = document.getElementById("pageInfo");
const inspectionBox = document.getElementById("inspection");
const ipScopeSelect = document.getElementById("ipScope");
const keywordInput = document.getElementById("keywords");
const matchModeSelect = document.getElementById("matchMode");
const minBytesInput = document.getElementById("minBytesReceived");
const sortModeSelect = document.getElementById("sortMode");
const ipSummaryButton = document.getElementById("ipSummaryButton");
const runDetectionsButton = document.getElementById("runDetectionsButton");
const detectionRulesInput = document.getElementById("detectionRules");
const refreshDetectionsButton = document.getElementById("refreshDetectionsButton");
const detectionsStatus = document.getElementById("detectionsStatus");
const detectionsBox = document.getElementById("detectionsBox");
const detectionsPrevButton = document.getElementById("detectionsPrevButton");
const detectionsNextButton = document.getElementById("detectionsNextButton");
const detectionsPageInfo = document.getElementById("detectionsPageInfo");
const includeFalsePositivesCheckbox = document.getElementById("includeFalsePositives");
const hasDetectionUI = Boolean(
  runDetectionsButton &&
    detectionRulesInput &&
    refreshDetectionsButton &&
    detectionsStatus &&
    detectionsBox &&
    detectionsPrevButton &&
    detectionsNextButton &&
    detectionsPageInfo &&
    includeFalsePositivesCheckbox
);

const state = {
  page: 1,
  hasMore: false,
  loading: false,
  selection: null,
  detectionsLoading: false,
  detectionsNextCursor: null,
  detectionsCursors: [null],
  detectionsCursorIndex: 0,
  detectionsRunId: null,
};
let lastQuery = null;

const parseKeywords = (input) =>
  input
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);

const buildPayloadFromInputs = () => {
  const minBytesRaw = minBytesInput.value.trim();
  const digitsOnly = minBytesRaw.replace(/[^\d]/g, "");
  const parsedMinBytes = digitsOnly ? Number(digitsOnly) : null;
  return {
    root_path: rootInput.value.trim(),
    terms: parseKeywords(keywordInput.value),
    none: parseKeywords(noneInput.value),
    page_size: Number(pageSizeSelect.value) || 100,
    export_csv: exportCheckbox.checked,
    status_code: statusSelect.value ? Number(statusSelect.value) : null,
    case_sensitive: caseCheckbox.checked,
    ip_scope: ipScopeSelect.value || null,
    match_mode: matchModeSelect.value,
    min_bytes_received: parsedMinBytes,
    sort_mode: sortModeSelect.value || "file_position",
  };
};

const parseDetectionRules = () => {
  if (!hasDetectionUI) return [];
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

const setDetectionsLoading = (value) => {
  state.detectionsLoading = value;
  if (!hasDetectionUI) return;
  runDetectionsButton.disabled = value || state.loading;
  refreshDetectionsButton.disabled = value;
  updateDetectionsPagination();
};

const updateDetectionsPagination = () => {
  if (!hasDetectionUI) return;
  detectionsPrevButton.disabled =
    state.detectionsLoading || state.detectionsCursorIndex === 0;
  detectionsNextButton.disabled =
    state.detectionsLoading || !state.detectionsNextCursor;
  detectionsPageInfo.textContent = `Detections page ${
    state.detectionsCursorIndex + 1
  }`;
};

const buildDetectionsPayload = () => {
  const root = rootInput.value.trim();
  return {
    root_path: root,
    terms: [],
    none: [],
    page: 1,
    page_size: 100,
    export_csv: false,
    status_code: null,
    case_sensitive: caseCheckbox.checked,
    ip_scope: null,
    match_mode: "any",
    min_bytes_received: null,
    sort_mode: "file_position",
  };
};

const runDetections = async () => {
  if (!hasDetectionUI) return;
  const payload = buildDetectionsPayload();
  if (!payload.root_path) {
    detectionsStatus.textContent = "Root path cannot be empty.";
    return;
  }

  try {
    payload.rules = parseDetectionRules();
  } catch (error) {
    detectionsStatus.textContent = error.message;
    return;
  }

  setDetectionsLoading(true);
  detectionsStatus.textContent = "Running detections and persisting hits...";
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
    detectionsStatus.textContent = `Run #${data.run_id} persisted ${formatNumber(
      data.total_hits
    )} hits in ${data.duration_ms} ms.`;
    statusBox.textContent = detectionsStatus.textContent;
    state.detectionsRunId = data.run_id;
    resetDetectionsPagination();
    await loadDetections(null, data.run_id);
  } catch (error) {
    console.error(error);
    detectionsStatus.textContent = error.message;
    statusBox.textContent = error.message;
  } finally {
    setDetectionsLoading(false);
  }
};

const loadDetections = async (cursor = null, runId = state.detectionsRunId) => {
  if (!hasDetectionUI) return;
  setDetectionsLoading(true);
  try {
    const params = new URLSearchParams({
      page_size: "20",
      sort_order: "desc",
      include_false_positives: includeFalsePositivesCheckbox.checked
        ? "true"
        : "false",
    });
    if (cursor) {
      params.set("cursor", cursor);
    }
    if (runId !== null && runId !== undefined) {
      params.set("run_id", String(runId));
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
    detectionsStatus.textContent = error.message;
    statusBox.textContent = error.message;
  } finally {
    setDetectionsLoading(false);
  }
};

const toggleFalsePositive = async (hitId, value) => {
  if (!hasDetectionUI) return;
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
    detectionsStatus.textContent = error.message;
    statusBox.textContent = error.message;
  }
};

const renderDetections = (hits) => {
  if (!hasDetectionUI) return;
  if (!hits.length) {
    detectionsBox.textContent = "";
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
    line.innerHTML = highlightLine(hit.line, getHighlightTerms());

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

form.addEventListener("submit", (event) => {
  event.preventDefault();
  lastQuery = buildPayloadFromInputs();

  if (!lastQuery.root_path) {
    statusBox.textContent = "Root path cannot be empty.";
    return;
  }

  statusBox.textContent = "";
  runSearch(1);
});

prevButton.addEventListener("click", () => {
  if (state.page <= 1 || state.loading) return;
  runSearch(state.page - 1);
});

nextButton.addEventListener("click", () => {
  if (!state.hasMore || state.loading) return;
  runSearch(state.page + 1);
});

ipSummaryButton.addEventListener("click", () => {
  if (state.loading) return;
  runIpSummary();
});

if (hasDetectionUI) {
  runDetectionsButton.addEventListener("click", () => {
    if (state.loading || state.detectionsLoading) return;
    runDetections();
  });

  refreshDetectionsButton.addEventListener("click", () => {
    if (state.detectionsLoading) return;
    if (state.detectionsRunId === null || state.detectionsRunId === undefined) {
      detectionsStatus.textContent =
        "Current session has no detection run. Use Run detections first.";
      detectionsBox.textContent = "";
      resetDetectionsPagination();
      updateDetectionsPagination();
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
}

const runSearch = async (page) => {
  if (!lastQuery) return;
  resetInspection();
  resetIpSummary();
  const payload = {
    ...lastQuery,
    page,
    page_size: Number(lastQuery.page_size) || 100,
    export_csv: Boolean(lastQuery.export_csv),
    status_code: lastQuery.status_code ?? null,
    case_sensitive: Boolean(lastQuery.case_sensitive),
    ip_scope: lastQuery.ip_scope || null,
    match_mode: lastQuery.match_mode,
    min_bytes_received: lastQuery.min_bytes_received ?? null,
    sort_mode: lastQuery.sort_mode || "file_position",
  };

  setLoading(true);
  try {
    const response = await fetch("/search", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => null);
      throw new Error(error?.error || "Search failed");
    }

    const data = await response.json();
    lastQuery.page_size = data.page_size;
    pageSizeSelect.value = String(data.page_size);
    renderResults(data);
  } catch (error) {
    console.error(error);
    statusBox.textContent = error.message;
  } finally {
    setLoading(false);
  }
};

const runIpSummary = async () => {
  const payload = buildPayloadFromInputs();
  if (!payload.root_path) {
    statusBox.textContent = "Root path cannot be empty.";
    return;
  }
  payload.export_csv = true;

  ipSummaryBox.textContent = "IP summary is being generated...";
  try {
    const response = await fetch("/ip_summary", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const err = await response.json().catch(() => null);
      throw new Error(err?.error || "IP summary failed");
    }
    const data = await response.json();
    // Persist so the same parameters can be reused on subsequent requests
    lastQuery = payload;
    renderIpSummary(data);
  } catch (err) {
    console.error(err);
    ipSummaryBox.textContent = err.message;
  }
};

const renderResults = (data) => {
  const {
    results: rawResults,
    total_matches,
    files_scanned,
    bytes_scanned,
    duration_ms,
    page,
    page_size,
    has_more,
    export_path,
    export_total,
    applied_sort_mode,
    applied_min_bytes_received,
  } = data;

  // Trust server-provided values first; fall back to client selection
  const effectiveSortMode = applied_sort_mode || lastQuery?.sort_mode || "file_position";
  const effectiveMinBytes =
    applied_min_bytes_received ??
    (lastQuery?.min_bytes_received ?? null);

  // Client-side enforce filter/sort for display robustness
  let results = rawResults.slice();
  if (effectiveMinBytes !== null && effectiveMinBytes !== undefined) {
    results = results.filter(
      (r) => (r.bytes_received ?? 0) >= effectiveMinBytes
    );
  }
  if (effectiveSortMode === "bytes_received_desc") {
    results.sort(
      (a, b) => (b.bytes_received ?? 0) - (a.bytes_received ?? 0)
    );
  } else if (effectiveSortMode === "bytes_received_asc") {
    results.sort(
      (a, b) => (a.bytes_received ?? 0) - (b.bytes_received ?? 0)
    );
  }

  state.page = page;
  state.hasMore = has_more;

  const exportInfo = export_path
    ? ` | CSV: <a href="${export_path}" download>${export_path.split('/').pop()}</a> (${export_total ?? 0} rows)`
    : "";
  const statusInfo = lastQuery?.status_code
    ? ` | HTTP status: ${lastQuery.status_code}`
    : "";
  const modeInfo =
    lastQuery?.match_mode === "all" ? "AND" : "OR";
  const ipInfo = lastQuery?.ip_scope ? ` | IP scope: ${lastQuery.ip_scope}` : "";
  const bytesInfo = effectiveMinBytes
    ? ` | bytes_received ≥ ${formatNumber(effectiveMinBytes)}`
    : "";
  const sortInfo =
    effectiveSortMode && effectiveSortMode !== "file_position"
      ? ` | sort: ${describeSortMode(effectiveSortMode)}`
      : "";
  summaryBox.innerHTML = `This page <strong>${formatNumber(
    results.length
  )}</strong> rows | Total <strong>${formatNumber(
    total_matches
  )}</strong> matches | <strong>${formatNumber(
    files_scanned
  )}</strong> files scanned | <strong>${formatBytes(
    bytes_scanned
  )}</strong> read | <strong>${duration_ms} ms</strong> | mode: <strong>${modeInfo}</strong>${statusInfo}${ipInfo}${bytesInfo}${sortInfo}${exportInfo}`;
  statusBox.textContent = export_path
    ? `All matches were exported to CSV: ${export_path}`
    : "";

  resultsBody.innerHTML = "";
  if (!results.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "No matching rows on this page.";
    row.appendChild(cell);
    resultsBody.appendChild(row);
  } else {
    const highlightTerms = getHighlightTerms();
    let currentFile = null;
    results.forEach((entry) => {
      if (entry.file_path !== currentFile) {
        currentFile = entry.file_path;
        const fileRow = document.createElement("tr");
        const fileCell = document.createElement("td");
        fileCell.colSpan = 3;
        fileCell.textContent = `file: ${currentFile}`;
        fileRow.classList.add("file-header");
        resultsBody.appendChild(fileRow);
      }

      const row = document.createElement("tr");
      const actionCell = document.createElement("td");
      actionCell.style.width = "110px";
      const ctxBtn = document.createElement("button");
      ctxBtn.textContent = "Context";
      ctxBtn.onclick = (e) => {
        e.stopPropagation();
        showContext(entry);
      };
      actionCell.appendChild(ctxBtn);
      const lineCell = document.createElement("td");
      lineCell.textContent = entry.line_number;
      const logCell = document.createElement("td");
      if (entry.bytes_received !== undefined && entry.bytes_received !== null) {
        const bytesBadge = document.createElement("div");
        bytesBadge.className = "bytes-badge";
        bytesBadge.textContent = `bytes_received: ${formatNumber(
          entry.bytes_received
        )}`;
        logCell.appendChild(bytesBadge);
      }
      const pre = document.createElement("pre");
      pre.innerHTML = highlightLine(entry.line, highlightTerms);
      logCell.appendChild(pre);

      row.appendChild(actionCell);
      row.appendChild(lineCell);
      row.appendChild(logCell);
      row.addEventListener("click", () => setInspection(entry));
      resultsBody.appendChild(row);
    });
  }

  pageInfo.textContent = `Page ${page} (size ${page_size})${
    has_more ? "" : " • end of results"
  }`;
  updatePaginationControls();
};

const setLoading = (value) => {
  state.loading = value;
  searchButton.disabled = value;
  if (runDetectionsButton) {
    runDetectionsButton.disabled = value || state.detectionsLoading;
  }
  loadingIndicator.hidden = !value;
  updatePaginationControls();
};

const updatePaginationControls = () => {
  prevButton.disabled = state.loading || state.page <= 1;
  nextButton.disabled = state.loading || !state.hasMore;
};

const setInspection = (entry) => {
  state.selection = entry;
  const bytesNote =
    entry.bytes_received !== undefined && entry.bytes_received !== null
      ? ` | bytes_received: ${formatNumber(entry.bytes_received)}`
      : "";
  inspectionBox.innerHTML = `<div><strong>Inspecting file:</strong> ${entry.file_path} (line ${entry.line_number}${bytesNote})</div>`;
};

const resetInspection = () => {
  state.selection = null;
  inspectionBox.textContent = "No log line selected yet.";
};

const resetIpSummary = () => {
  ipSummaryBox.textContent =
    'No IP summary yet. Run a search, then click "IP summary".';
};

const formatBytes = (value) => {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const order = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  );
  const size = value / Math.pow(1024, order);
  return `${size.toFixed(order === 0 ? 0 : 1)} ${units[order]}`;
};

const formatNumber = (value) => {
  if (value === null || value === undefined || Number.isNaN(value)) return "0";
  return Number(value).toLocaleString("en-US");
};

const describeSortMode = (mode) => {
  switch (mode) {
    case "bytes_received_desc":
      return "bytes_received ↓";
    case "bytes_received_asc":
      return "bytes_received ↑";
    default:
      return "file & line";
  }
};

const getHighlightTerms = () => {
  if (!lastQuery) return [];
  return Array.from(new Set((lastQuery.terms || []).filter(Boolean)));
};

const highlightLine = (line, terms) => {
  const escaped = escapeHtml(line);
  const keyworded = applyKeywordHighlight(escaped, terms);
  return keyworded
    .split(/(<mark>.*?<\/mark>)/)
    .map((segment) =>
      segment.startsWith("<mark>") ? segment : syntaxHighlight(segment)
    )
    .join("");
};

const applyKeywordHighlight = (text, terms) => {
  if (!terms.length) return text;
  const flags = lastQuery?.case_sensitive ? "g" : "gi";
  const pattern = new RegExp(
    terms.map((term) => escapeRegExp(term)).join("|"),
    flags
  );
  let match;
  let lastIndex = 0;
  let output = "";
  while ((match = pattern.exec(text)) !== null) {
    output += text.slice(lastIndex, match.index);
    output += `<mark>${match[0]}</mark>`;
    lastIndex = match.index + match[0].length;
  }
  output += text.slice(lastIndex);
  return output;
};

resultsBody.addEventListener("click", (e) => {
  const target = e.target;
  if (target.classList.contains("pivot") && target.dataset.term) {
    e.stopPropagation();
    addPivotAndSearch(target.dataset.term);
  }
});

const addPivotAndSearch = (term) => {
  const current = parseKeywords(keywordInput.value);
  if (!current.includes(term)) {
    current.push(term);
    keywordInput.value = current.join(", ");
  }
  form.requestSubmit();
};

const showContext = async (entry) => {
  try {
    const response = await fetch("/context", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        root_path: lastQuery.root_path,
        file_path: entry.file_path,
        line: entry.line_number,
        radius: 5,
      }),
    });
    if (!response.ok) {
      throw new Error("Context could not be loaded");
    }
    const data = await response.json();
    renderContext(data, getHighlightTerms());
  } catch (err) {
    console.error(err);
    alert(err.message);
  }
};

const modal = document.getElementById("modal");
const modalBody = document.getElementById("modalBody");
document.getElementById("closeModal").addEventListener("click", () => {
  modal.classList.add("hidden");
});

const renderContext = (data, terms) => {
  modalBody.innerHTML = `
    <div><strong>${data.file_path}</strong> line ${data.start_line} - ${data.end_line}</div>
    <div class="context-lines">
      ${data.lines
        .map(
          (l) =>
            `<div class="context-line"><span>${l.line_number}</span><span>${highlightLine(
              l.line,
              terms
            )}</span></div>`
        )
        .join("")}
    </div>
  `;
  modal.classList.remove("hidden");
};

const renderIpSummary = (data) => {
  const {
    ips = [],
    total_matches,
    files_scanned,
    bytes_scanned,
    duration_ms,
    unique_ips,
    src_ips = [],
    dst_ips = [],
    unique_src_ips,
    unique_dst_ips,
    export_path,
  } = data;
  if (!ips.length && !src_ips.length && !dst_ips.length) {
    ipSummaryBox.textContent = "No matching IPs were found.";
    return;
  }
  const makeList = (items) =>
    items
      .slice(0, 300)
      .map(
        (item) =>
          `<div class="ip-chip"><span>${item.ip}</span><span>${formatNumber(
            item.count
          )}</span></div>`
      )
      .join("");

  ipSummaryBox.innerHTML = `
    <div><strong>${formatNumber(
      unique_ips ?? ips.length
    )}</strong> unique IPs | <strong>${formatNumber(
    total_matches
  )}</strong> lines contained IPs | <strong>${files_scanned}</strong> files scanned | <strong>${formatBytes(
    bytes_scanned
  )}</strong> read | <strong>${duration_ms} ms</strong></div>
    ${
      export_path
        ? `<div>CSV: <a href="${export_path}" download>${export_path
            .split("/")
            .pop()}</a></div>`
        : ""
    }
    <div class="ip-summary-list">${makeList(ips)}</div>
    <div class="ip-summary-list" style="margin-top:8px">
      <div class="ip-chip"><strong>SRC IP</strong><span>${formatNumber(
        unique_src_ips ?? src_ips.length
      )}</span></div>
      <div class="ip-chip"><strong>DST IP</strong><span>${formatNumber(
        unique_dst_ips ?? dst_ips.length
      )}</span></div>
    </div>
    <div class="ip-summary-list">${makeList(src_ips)}</div>
    <div class="ip-summary-list">${makeList(dst_ips)}</div>
  `;
};

const syntaxHighlight = (text) => {
  return text
    .replace(
      /\b\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\b/g,
      (m) => `<span class="hl-date pivot" data-term="${m}">${m}</span>`
    )
    .replace(
      /\b\d{1,3}(?:\.\d{1,3}){3}\b/g,
      (m) => `<span class="hl-ip pivot" data-term="${m}">${m}</span>`
    )
    .replace(
      /\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b/g,
      (m) => `<span class="hl-method pivot" data-term="${m}">${m}</span>`
    )
    .replace(/\b(\d{3})\b/g, (m, code) => {
      const n = Number(code);
      const cls =
        n >= 500
          ? "hl-status-err"
          : n >= 400
          ? "hl-status-warn"
          : "hl-status-ok";
      return `<span class="${cls} pivot" data-term="${m}">${m}</span>`;
    });
};

const escapeHtml = (text) =>
  text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const escapeRegExp = (text) =>
  text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

updateDetectionsPagination();
