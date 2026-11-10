const byId = (id) => document.getElementById(id);
const state = { engines: [], providers: [], scans: [], selectedScan: null };
const severityLabels = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "信息", unknown: "未评级",
};
const statusLabels = { completed: "已完成", imported: "已导入", failed: "失败" };

function showNotice(message, kind = "") {
  const notice = byId("notice");
  notice.textContent = message;
  notice.className = `notice ${kind}`.trim();
  notice.hidden = !message;
}

async function request(path, options) {
  const response = await fetch(path, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.error || `请求失败（${response.status}）`);
  return payload;
}

function addCell(row, text, className = "") {
  const cell = document.createElement("td");
  if (className) cell.className = className;
  cell.textContent = text ?? "";
  row.append(cell);
  return cell;
}

function addEmptyRow(tbody, columns, text) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = columns;
  cell.className = "emptyRow";
  cell.textContent = text;
  row.append(cell);
  tbody.replaceChildren(row);
}

function formatTime(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : `${new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short", timeZone: "UTC" }).format(date)} UTC`;
}

function renderEngines() {
  const tbody = byId("engineRows");
  tbody.replaceChildren();
  const runnable = state.engines.filter((engine) => engine.runnable);
  for (const engine of state.engines) {
    const row = document.createElement("tr");
    const name = addCell(row, engine.id);
    const source = document.createElement("small");
    source.textContent = `${engine.source} · ${engine.license}`;
    name.append(source);
    addCell(row, engine.purpose);
    addCell(row, engine.boundary);
    const status = document.createElement("span");
    status.className = `statusPill ${engine.runnable ? "ready" : engine.available ? "gated" : "missing"}`;
    status.textContent = engine.runnable ? "可运行" : engine.available ? "已安装，当前受限" : "未安装";
    const statusCell = document.createElement("td");
    statusCell.append(status);
    row.append(statusCell);
    tbody.append(row);
  }
  if (!state.engines.length) addEmptyRow(tbody, 4, "暂时没有引擎信息。");
  byId("engineCount").textContent = `${runnable.length} 个可运行 · 共 ${state.engines.length} 个`;
  const select = byId("scanEngine");
  const previous = select.value;
  select.replaceChildren();
  for (const engine of runnable) {
    const option = document.createElement("option");
    option.value = engine.id;
    option.textContent = engine.id;
    select.append(option);
  }
  if (runnable.some((engine) => engine.id === previous)) select.value = previous;
  byId("scanButton").disabled = runnable.length === 0;
  updateEngineBoundary();
}

function updateEngineBoundary() {
  const engine = state.engines.find((item) => item.id === byId("scanEngine").value);
  byId("engineBoundary").textContent = engine
    ? `${engine.source} · ${engine.boundary}`
    : "请先安装扫描引擎，或直接导入 SARIF/JSON 报告。";
}

function renderProviders() {
  const tbody = byId("providerRows");
  tbody.replaceChildren();
  const selected = state.providers.find((provider) => provider.selected);
  byId("providerSelection").textContent = selected
    ? `当前主用：${selected.name}`
    : "尚未选择模型供应商";
  for (const provider of state.providers) {
    const row = document.createElement("tr");
    addCell(row, provider.name);
    addCell(row, provider.role === "primary" ? "主用" : "候选");
    const codex = provider.codex_profile || {};
    addCell(row, codex.wire_api ? `${codex.wire_api} · ${codex.base_url || "未配置"}` : "Codex 中未找到");
    const scanner = provider.scanner_profile || {};
    addCell(row, scanner.wire_api ? `${scanner.wire_api} · ${scanner.base_url || "未配置"}` : "未配置");
    addCell(row, scanner.model || "未配置");
    const status = document.createElement("span");
    status.className = `statusPill ${scanner.configured ? (provider.selected ? "ready" : "gated") : "missing"}`;
    status.textContent = scanner.configured
      ? (provider.selected ? "已选用" : "候选已配置")
      : (provider.selected ? "当前供应商，待配置密钥" : "候选，待配置");
    const statusCell = document.createElement("td");
    statusCell.append(status);
    if (scanner.credential_source && scanner.credential_source !== "not configured") {
      const credential = document.createElement("small");
      credential.textContent = `密钥来源：${scanner.credential_source}`;
      statusCell.append(credential);
    }
    row.append(statusCell);
    tbody.append(row);
  }
  if (!state.providers.length) addEmptyRow(tbody, 6, "没有读取到模型供应商配置。");
}

async function renderSummary() {
  const summary = await request("/api/summary");
  byId("metricScans").textContent = summary.scans;
  byId("metricFindings").textContent = summary.findings;
  byId("metricHigh").textContent = summary.high_or_critical;
  byId("metricLatest").textContent = formatTime(summary.latest_scan);
}

async function renderScans() {
  const payload = await request("/api/scans?limit=50");
  state.scans = payload.scans;
  const tbody = byId("scanRows");
  tbody.replaceChildren();
  for (const scan of state.scans) {
    const row = document.createElement("tr");
    addCell(row, scan.engine);
    addCell(row, scan.target);
    const statusCell = document.createElement("td");
    const status = document.createElement("span");
    status.className = `statusPill ${scan.status}`;
    status.textContent = statusLabels[scan.status] || scan.status;
    statusCell.append(status);
    row.append(statusCell);
    addCell(row, String(scan.finding_count));
    addCell(row, formatTime(scan.finished_at));
    row.tabIndex = 0;
    row.setAttribute("role", "button");
    row.addEventListener("click", () => loadFindings(scan.scan_id));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") loadFindings(scan.scan_id);
    });
    tbody.append(row);
  }
  if (!state.scans.length) addEmptyRow(tbody, 5, "暂无扫描记录。开始扫描或导入报告后，记录会显示在这里。");
  byId("scanCount").textContent = `最近 ${state.scans.length} 条`;
  const findings = [];
  for (const scan of state.scans.slice(0, 10)) {
    const detail = await request(`/api/scans/${scan.scan_id}`);
    findings.push(...detail.findings.map((item) => ({ ...item, scan_id: scan.scan_id })));
  }
  renderFindings(findings.slice(0, 100));
}

function renderFindings(findings) {
  const tbody = byId("findingRows");
  tbody.replaceChildren();
  for (const finding of findings) {
    const row = document.createElement("tr");
    const severityCell = document.createElement("td");
    const severity = document.createElement("span");
    severity.className = `severityPill ${finding.severity}`;
    severity.textContent = severityLabels[finding.severity] || "未评级";
    severityCell.append(severity);
    row.append(severityCell);
    addCell(row, finding.risk_score == null ? "—" : String(Number(finding.risk_score.toFixed(2))));
    addCell(row, finding.engine);
    addCell(row, finding.rule_id);
    const titleCell = addCell(row, finding.title);
    if (finding.message && finding.message !== finding.title) {
      const message = document.createElement("small");
      message.textContent = finding.message;
      titleCell.append(message);
    }
    addCell(row, finding.file ? `${finding.file}${finding.line ? `:${finding.line}` : ""}` : "—");
    tbody.append(row);
  }
  if (!findings.length) addEmptyRow(tbody, 6, "选择一条扫描记录，或导入报告以查看发现项。");
  byId("findingCount").textContent = `显示 ${findings.length} 条`;
}

async function refresh() {
  try {
    const [engines, providers] = await Promise.all([
      request("/api/engines"),
      request("/api/providers"),
      renderSummary(),
    ]);
    state.engines = engines.engines;
    state.providers = providers.providers;
    renderProviders();
    renderEngines();
    await renderScans();
  } catch (error) {
    showNotice(error.message, "error");
  }
}

async function loadFindings(scanId) {
  try {
    const detail = await request(`/api/scans/${scanId}`);
    state.selectedScan = scanId;
    renderFindings(detail.findings);
    byId("findingCount").textContent = `当前扫描共 ${detail.findings.length} 条`;
    location.hash = "findings";
  } catch (error) {
    showNotice(error.message, "error");
  }
}

byId("scanEngine").addEventListener("change", updateEngineBoundary);
byId("refreshButton").addEventListener("click", refresh);

byId("scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("scanButton");
  button.disabled = true;
  button.textContent = "扫描中…";
  showNotice("正在运行扫描，可能需要几分钟。");
  try {
    const result = await request("/api/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ engine: byId("scanEngine").value, target: byId("scanTarget").value.trim() }),
    });
    showNotice(`${result.engine} 扫描完成，发现 ${result.finding_count} 项。`, "success");
    await refresh();
    await loadFindings(result.scan_id);
  } catch (error) {
    showNotice(error.message, "error");
  } finally {
    button.disabled = false;
    button.textContent = "开始扫描";
  }
});

byId("importForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const file = byId("reportFile").files[0];
  if (!file) return;
  try {
    const report = JSON.parse(await file.text());
    const result = await request("/api/scans/import", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ engine: byId("reportEngine").value.trim(), target: byId("reportTarget").value.trim(), report }),
    });
    showNotice(`已从 ${result.engine} 导入 ${result.finding_count} 项发现。`, "success");
    await refresh();
    await loadFindings(result.scan_id);
  } catch (error) {
    showNotice(error.message, "error");
  }
});

refresh();
