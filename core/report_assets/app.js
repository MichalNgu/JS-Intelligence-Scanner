"use strict";

(() => {
  const state = {
    report: null,
    findings: [],
    resources: [],
    importedFile: null
  };

  const element = (id) => document.getElementById(id);
  const text = (value) => {
    if (value === null || value === undefined || value === "") return "—";
    if (typeof value === "object") {
      try {
        return JSON.stringify(value, null, 2);
      } catch {
        return "[unavailable]";
      }
    }
    return String(value);
  };
  const clear = (node) => node.replaceChildren();

  function setLoadStatus(message, kind) {
    const node = element("load-status");
    node.textContent = message;
    node.className = `load-status${kind ? ` ${kind}` : ""}`;
  }

  function appendCell(row, value, className) {
    const cell = document.createElement("td");
    if (className) cell.className = className;
    cell.textContent = text(value);
    row.appendChild(cell);
    return cell;
  }

  function appendEmptyRow(body, columnCount, message) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.className = "empty-state";
    cell.colSpan = columnCount;
    cell.textContent = message;
    row.appendChild(cell);
    body.appendChild(row);
  }

  function renderRisk(value) {
    const cell = document.createElement("td");
    const badge = document.createElement("span");
    const raw = text(value);
    const normalized = raw.toLowerCase();
    const knownRisks = ["critical", "high", "medium", "low", "info"];
    badge.className = `risk-badge risk-${knownRisks.includes(normalized) ? normalized : "unknown"}`;
    badge.textContent = raw;
    cell.appendChild(badge);
    return cell;
  }

  function appendFindingDetails(cell, finding) {
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = "Expand";
    const content = document.createElement("div");
    content.className = "finding-details";
    const list = document.createElement("dl");
    const fields = [
      ["Reason", finding.reason],
      ["Context", finding.context],
      ["Metadata", finding.metadata]
    ];

    for (const [label, value] of fields) {
      const term = document.createElement("dt");
      term.textContent = label;
      const description = document.createElement("dd");
      description.textContent = text(value);
      list.append(term, description);
    }

    content.appendChild(list);
    details.append(summary, content);
    cell.appendChild(details);
  }

  function renderFindingRows() {
    const body = element("findings-body");
    clear(body);
    const query = element("finding-search").value.trim().toLowerCase();
    const selectedRisk = element("risk-filter").value.toLowerCase();
    const selectedType = element("type-filter").value;
    const visibleFindings = state.findings.filter((finding) => {
      const risk = text(finding.risk).toLowerCase();
      const type = text(finding.type);
      if (selectedRisk && risk !== selectedRisk) return false;
      if (selectedType && type !== selectedType) return false;
      if (!query) return true;
      return JSON.stringify(finding).toLowerCase().includes(query);
    });

    element("finding-count").textContent =
      `${visibleFindings.length} of ${state.findings.length} findings`;
    if (visibleFindings.length === 0) {
      appendEmptyRow(body, 8, state.findings.length ? "No findings match these filters." : "No findings in this report.");
      return;
    }

    for (const finding of visibleFindings) {
      const row = document.createElement("tr");
      row.appendChild(renderRisk(finding.risk));
      appendCell(row, finding.type, "wrap");
      appendCell(row, finding.value, "wrap");
      appendCell(row, finding.category, "wrap");
      appendCell(row, finding.source || finding.source_url, "wrap");
      appendCell(row, finding.line_number);
      appendCell(row, finding.confidence);
      const detailsCell = document.createElement("td");
      appendFindingDetails(detailsCell, finding);
      row.appendChild(detailsCell);
      body.appendChild(row);
    }
  }

  function populateFilters() {
    const risks = new Set();
    const types = new Set();
    for (const finding of state.findings) {
      if (finding.risk !== undefined && finding.risk !== null) risks.add(String(finding.risk));
      if (finding.type !== undefined && finding.type !== null) types.add(String(finding.type));
    }

    const riskFilter = element("risk-filter");
    const typeFilter = element("type-filter");
    const selectedRisk = riskFilter.value;
    const selectedType = typeFilter.value;
    clear(riskFilter);
    clear(typeFilter);
    const allRisks = document.createElement("option");
    allRisks.value = "";
    allRisks.textContent = "All risks";
    riskFilter.appendChild(allRisks);
    const allTypes = document.createElement("option");
    allTypes.value = "";
    allTypes.textContent = "All types";
    typeFilter.appendChild(allTypes);

    for (const risk of [...risks].sort()) {
      const option = document.createElement("option");
      option.value = risk;
      option.textContent = risk;
      riskFilter.appendChild(option);
    }
    for (const type of [...types].sort()) {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      typeFilter.appendChild(option);
    }
    riskFilter.value = risks.has(selectedRisk) ? selectedRisk : "";
    typeFilter.value = types.has(selectedType) ? selectedType : "";
  }

  function renderResources() {
    const body = element("resources-body");
    clear(body);
    element("resource-count").textContent = `${state.resources.length} resources`;
    if (state.resources.length === 0) {
      appendEmptyRow(body, 4, "No JavaScript resources in this report.");
      return;
    }
    for (const resource of state.resources) {
      const row = document.createElement("tr");
      appendCell(row, resource.url, "wrap");
      appendCell(row, resource.status);
      appendCell(row, resource.size === undefined ? "—" : `${text(resource.size)} bytes`);
      appendCell(row, resource.sha256, "hash-cell");
      body.appendChild(row);
    }
  }

  function renderGroupedRows(bodyId, rows, columns, emptyMessage) {
    const body = element(bodyId);
    clear(body);
    if (!rows.length) {
      appendEmptyRow(body, columns.length, emptyMessage);
      return;
    }
    for (const values of rows) {
      const row = document.createElement("tr");
      for (const [value, className] of values) appendCell(row, value, className);
      body.appendChild(row);
    }
  }

  function renderAnalysisSections() {
    const endpoints = state.findings
      .filter((finding) => finding.type === "api_endpoint")
      .map((finding) => [
        [finding.value, "wrap"],
        [finding.risk],
        [finding.source || finding.source_url, "wrap"]
      ]);
    renderGroupedRows("endpoints-body", endpoints, ["", "", ""], "No endpoints found.");

    const infrastructureTypes = new Set([
      "private_ip", "internal_hostname", "network_url",
      "environment_indicator", "external_api_domain", "cloud_infrastructure"
    ]);
    const infrastructure = state.findings
      .filter((finding) => infrastructureTypes.has(finding.type))
      .map((finding) => [
        [finding.type, "wrap"],
        [finding.value, "wrap"],
        [finding.source || finding.source_url, "wrap"]
      ]);
    renderGroupedRows(
      "infrastructure-body",
      infrastructure,
      ["", "", ""],
      "No infrastructure references found."
    );

    const secrets = state.findings
      .filter((finding) => ["potential_secret", "confirmed_secret"].includes(finding.type))
      .map((finding) => [
        [finding.type, "wrap"],
        [finding.risk],
        [finding.value, "wrap"],
        [finding.source || finding.source_url, "wrap"],
        [finding.line_number]
      ]);
    renderGroupedRows(
      "secrets-body",
      secrets,
      ["", "", "", "", ""],
      "No secret-like values found."
    );
  }

  function numberOr(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
  }

  function countType(type, fallback) {
    if (Array.isArray(state.report.findings)) {
      return state.findings.filter((finding) => finding.type === type).length;
    }
    return numberOr(fallback, 0);
  }

  function renderVerificationSteps() {
    const list = element("verification-list");
    clear(list);
    const steps = Array.isArray(state.report.manual_verification_steps)
      ? state.report.manual_verification_steps
      : [];
    const safeSteps = steps.filter((step) => typeof step === "string");
    if (safeSteps.length === 0) {
      safeSteps.push(
        "Verify authorization scope before reviewing discovered endpoints.",
        "Review credential-like values without authenticating or using them.",
        "Manually assess infrastructure references and potential false positives."
      );
    }
    for (const step of safeSteps) {
      const item = document.createElement("li");
      item.textContent = step;
      list.appendChild(item);
    }
  }

  function renderReport(report) {
    if (!report || typeof report !== "object" || Array.isArray(report)) {
      throw new Error("The JSON root must be an object.");
    }
    state.report = report;
    state.findings = Array.isArray(report.findings)
      ? report.findings.filter((item) => item && typeof item === "object" && !Array.isArray(item))
      : [];
    state.resources = Array.isArray(report.javascript_resources)
      ? report.javascript_resources.filter((item) => item && typeof item === "object" && !Array.isArray(item))
      : [];

    const statistics = report.statistics && typeof report.statistics === "object"
      ? report.statistics
      : {};
    element("target-url").textContent = text(report.target);
    element("scan-timestamp").textContent = text(report.generated_at || report.started_at);
    const duration = numberOr(report.scan_duration_seconds, NaN);
    element("scan-duration").textContent = Number.isFinite(duration) ? `${duration.toFixed(2)} s` : "—";

    const status = element("scan-status");
    status.textContent = text(report.scan_status || "Unknown");
    status.className = `status-pill${String(report.scan_status).toLowerCase() === "failed" ? " status-error" : ""}`;

    element("metric-findings").textContent = text(numberOr(statistics.total_findings, state.findings.length));
    element("metric-confirmed").textContent = text(countType("confirmed_secret", statistics.confirmed_secret_candidates));
    const potentialFallback = numberOr(statistics.potential_secrets, 0);
    element("metric-potential").textContent = text(countType("potential_secret", potentialFallback));
    element("metric-endpoints").textContent = text(countType("api_endpoint", statistics.endpoints));
    element("metric-hosts").textContent = text(countType("internal_hostname", statistics.internal_hosts));
    element("metric-private-ips").textContent = text(countType("private_ip", statistics.private_ip_references));
    element("metric-resources").textContent = text(numberOr(statistics.javascript_files, state.resources.length));
    element("metric-requests").textContent = text(numberOr(statistics.http_requests, 0));

    populateFilters();
    renderFindingRows();
    renderResources();
    renderAnalysisSections();
    renderVerificationSteps();
    setLoadStatus("Report loaded. This dashboard runs locally and uses no external services.", "success");
  }

  async function loadFromFile(file) {
    setLoadStatus(`Reading ${file.name}…`);
    try {
      const report = JSON.parse(await file.text());
      renderReport(report);
      state.importedFile = file;
    } catch (error) {
      setLoadStatus(`Could not read report JSON: ${text(error.message || error)}`, "error");
    }
  }

  async function loadAdjacentReport() {
    setLoadStatus("Loading report.json…");
    try {
      const response = await fetch("./report.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const report = await response.json();
      renderReport(report);
      state.importedFile = null;
    } catch (error) {
      setLoadStatus(
        `Could not load report.json: ${text(error.message || error)}. Use Import JSON to select the report file.`,
        "error"
      );
    }
  }

  element("finding-search").addEventListener("input", renderFindingRows);
  element("risk-filter").addEventListener("change", renderFindingRows);
  element("type-filter").addEventListener("change", renderFindingRows);
  element("report-file").addEventListener("change", async (event) => {
    const file = event.target.files && event.target.files[0];
    if (file) await loadFromFile(file);
    event.target.value = "";
  });
  element("reload-report").addEventListener("click", () => {
    if (state.importedFile) {
      loadFromFile(state.importedFile);
    } else if (window.location.protocol === "file:") {
      setLoadStatus("For offline use, select this scan's report.json with Import JSON.");
    } else {
      loadAdjacentReport();
    }
  });

  if (window.location.protocol === "file:") {
    setLoadStatus("Offline dashboard ready. Select this scan's report.json with Import JSON.");
  } else {
    loadAdjacentReport();
  }
})();
