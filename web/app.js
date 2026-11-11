const byId = (id) => document.getElementById(id);
const state = { engines: [], providers: [], scans: [], selectedScan: null, user: null };
const roleLabels = { admin: "管理员", operator: "操作员", viewer: "只读" };
const severityLabels = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "信息", unknown: "未评级",
};
const statusLabels = { completed: "已完成", imported: "已导入", failed: "失败" };

class UnauthenticatedError extends Error {}

function showNotice(message, kind = "") {
  const notice = byId("notice");
  notice.textContent = message;
  notice.className = `notice ${kind}`.trim();
  notice.hidden = !message;
}

function showAuthGate(message = "") {
  byId("authGate").hidden = false;
  byId("sessionChip").hidden = true;
  const error = byId("loginError");
  error.textContent = message;
  error.hidden = !message;
  byId("loginPassword").value = "";
  byId("loginUser").focus();
}

function hideAuthGate() {
  byId("authGate").hidden = true;
  byId("loginError").hidden = true;
  const chip = byId("sessionChip");
  chip.hidden = !state.user;
  if (state.user) {
    byId("sessionUser").textContent = `${state.user.username} · ${roleLabels[state.user.role] || state.user.role}`;
  }
}

async function request(path, options) {
  const response = await fetch(path, options);
  if (response.status === 401) {
    // 会话缺失或已失效：转到登录页，不把 401 当普通错误弹提示。
    showAuthGate("会话已失效，请重新登录。");
    throw new UnauthenticatedError("未认证");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error((typeof payload.error === "object" ? payload.error.code : payload.error) || `请求失败（${response.status}）`);
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
    await refreshRuntime();
    await refreshApprovals();
  } catch (error) {
    if (error instanceof UnauthenticatedError) return;  // 已跳登录页
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
    if (error instanceof UnauthenticatedError) return;  // 已跳登录页
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

byId("loginForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = byId("loginButton");
  button.disabled = true;
  byId("loginError").hidden = true;
  try {
    const session = await request("/api/session", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: byId("loginUser").value.trim(),
        password: byId("loginPassword").value,
      }),
    });
    state.user = { username: session.username, role: session.role };
    hideAuthGate();
    showNotice(`已登录：${session.username}`, "success");
    await refresh();
  } catch (error) {
    if (error instanceof UnauthenticatedError) return;
    byId("loginError").textContent = error.message;
    byId("loginError").hidden = false;
  } finally {
    button.disabled = false;
  }
});

byId("logoutButton").addEventListener("click", async () => {
  try {
    await request("/api/session", { method: "DELETE" });
  } catch (error) {
    if (!(error instanceof UnauthenticatedError)) {
      showNotice(error.message, "error");
      return;
    }
  }
  state.user = null;
  state.scans = [];
  showAuthGate("已退出登录。");
});

async function boot() {
  try {
    // /api/session 同时充当"会话是否还有效"的探针。
    const session = await request("/api/session");
    state.user = { username: session.username, role: session.role };
    hideAuthGate();
    await refresh();
  } catch (error) {
    if (error instanceof UnauthenticatedError) showAuthGate();
    else showNotice(error.message, "error");
  }
}

boot();

let runtimeCursor = null;
let runtimeExecution = null;
async function refreshRuntime() {
  const [catalog, result] = await Promise.all([
    request('/api/v1/products'), request('/api/v1/executions?limit=100'),
  ]);
  const products = byId('runtimeProducts');
  products.replaceChildren();
  for (const product of catalog.products) {
    const line = document.createElement('p');
    const verified = product.events.length > 0 && product.events.every((event) => event.verification === 'verified');
    line.textContent = `${product.product_id} ${product.product_version} · ${verified ? '事件观测已验证' : '事件观测未验证'} · ${product.mediated_approval_supported ? 'ASGP 调用审批可用' : 'ASGP 调用审批未验证'} · ${product.boundary}`;
    products.append(line);
  }
  const select = byId('runtimeExecution');
  const previous = select.value;
  select.replaceChildren();
  for (const execution of result.executions) {
    const option = document.createElement('option');
    option.value = execution.execution_id;
    option.textContent = `${execution.product} ${execution.product_version} · ${execution.host_id} · ${formatTime(execution.started_at)} · ${execution.outcome}`;
    select.append(option);
  }
  if (result.executions.some((execution) => execution.execution_id === previous)) select.value = previous;
  byId('runtimeEmpty').hidden = result.executions.length > 0;
  if (select.value) await showRuntimeTimeline(false);
  else byId('runtimeEntries').replaceChildren();
}

async function showRuntimeTimeline(append) {
  const id = byId('runtimeExecution').value;
  if (!id) return;
  const cursor = append && runtimeExecution === id ? runtimeCursor : null;
  const response = await request(`/api/v1/executions/${encodeURIComponent(id)}/timeline?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`);
  const list = byId('runtimeEntries');
  if (!append) list.replaceChildren();
  for (const entry of response.entries) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = `${formatTime(entry.occurred_at)} · ${entry.kind === 'intent' ? entry.data.tool_name : entry.data.event_type}`;
    const detail = document.createElement('p');
    detail.textContent = entry.kind === 'intent'
      ? `调用 ${entry.data.tool_call_id || '未提供调用 ID'} · 决策记录 ${entry.data.decision} · 结果 ${entry.data.product_result || '尚未观测'} · 参数值已省略`
      : `${entry.data.action || ''} ${entry.data.result || ''} · 归因候选 ${(entry.data.attributions || []).length}`;
    item.append(title, detail); list.append(item);
  }
  byId('runtimeBoundary').textContent = `本次执行版本的观测验证：${response.capability_verification === 'verified' ? '已验证' : '未验证'}。归因以证据候选展示，可能冲突；关联发现项与策略闭环未整合到此时间线，决策记录不能作为阻断成功证明。`;
  runtimeExecution = id; runtimeCursor = response.next_cursor;
  byId('runtimeMore').hidden = !runtimeCursor;
}

byId('runtimeRefresh').addEventListener('click', () => refreshRuntime().catch((error) => {
  if (!(error instanceof UnauthenticatedError)) showNotice(error.message, 'error');
}));
byId('runtimeExecution').addEventListener('change', () => showRuntimeTimeline(false).catch((error) => showNotice(error.message, 'error')));
byId('runtimeMore').addEventListener('click', () => showRuntimeTimeline(true).catch((error) => showNotice(error.message, 'error')));

async function refreshApprovals() {
  const result = await request('/api/v1/approvals');
  const box = byId('approvalRequests'); box.replaceChildren();
  for (const row of result.approvals) {
    const item = document.createElement('article'); item.className = 'runtimeItem';
    const label = document.createElement('p');
    label.textContent = `${row.host_id} · ${row.product} ${row.product_version} · ${row.tool_name} · ${row.state} · 截止 ${formatTime(row.expires_at)}`;
    const digest = document.createElement('code'); digest.textContent = `参数 SHA-256: ${row.params_sha256}`;
    item.append(label,digest);
    if (row.state === 'pending' && ['admin','operator'].includes(state.user?.role)) {
      for (const [decision, text] of [['approved','批准本次调用'],['denied','拒绝本次调用']]) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'secondaryButton'; button.textContent = text;
        button.addEventListener('click',async () => {
          button.disabled = true;
          try {
            await request(`/api/v1/approvals/${encodeURIComponent(row.approval_id)}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({decision,params_sha256:row.params_sha256})});
            await refreshApprovals();
          } catch (error) { showNotice(error.message,'error'); button.disabled=false; }
        }); item.append(button);
      }
    }
    box.append(item);
  }
  if (!result.approvals.length) box.textContent = '暂无调用审批请求。';
}

async function refreshHostEvents() {
  const host = byId('runtimeHost').value.trim();
  if (!host) return;
  const result = await request(`/api/v1/runtime-events?host_id=${encodeURIComponent(host)}`);
  const box = byId('hostEvents');box.replaceChildren();
  for (const row of result.events) {
    const item=document.createElement('li');
    item.textContent=`${formatTime(row.occurred_at)} · ${row.event_type} · PID ${row.pid ?? '未知'} / PPID ${row.ppid ?? '未知'} · ${row.executable || ''} · ${row.resource_path || row.resource_host || ''} · ${row.result || ''} · ${row.execution_id ? '有执行上下文' : '未归因'}`;
    box.append(item);
  }
  if (!result.events.length) box.textContent='该设备尚无运行事件。';
}

async function correlateCurrent() {
  const id=byId('runtimeExecution').value;if(!id)return;
  const result=await request(`/api/v1/executions/${encodeURIComponent(id)}/correlate`,{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
  const edges=await request(`/api/v1/executions/${encodeURIComponent(id)}/attributions`);
  const box=byId('attributionCandidates');box.replaceChildren();
  const summary=document.createElement('p');summary.textContent=`候选 ${result.candidate_count} · 强候选选择 ${result.selected_count} · 本次扫描未归因 ${result.unattributed_count}（同主机事件可能属于其他会话）`;box.append(summary);
  for(const edge of edges.attributions){const line=document.createElement('p');line.textContent=`${edge.event_id} → ${edge.intent_id} · ${edge.method} · ${edge.confidence} · ${edge.selected ? '当前选择，仍须核验证据' : '未选择候选'}`;box.append(line);}
}

async function refreshGovernance() {
  const box=byId('governanceItems');box.replaceChildren();
  for(const [path,label] of [['risk-assessments','风险评估'],['policy-decisions','策略决定'],['admissions','准入检查'],['incidents','Incident']]){
    const result=await request('/api/v1/'+path);const section=document.createElement('section');
    const title=document.createElement('h3');title.textContent=`${label} · ${result.items.length}`;section.append(title);
    for(const row of result.items){const line=document.createElement('p');line.textContent=path==='risk-assessments'?`固有 ${row.intrinsic_risk} / 运行 ${row.runtime_risk} / 暴露 ${row.exposure_risk} · ${row.confidence}`:path==='policy-decisions'?`${row.action} · ${row.policy_version} · ${row.subject_kind}:${row.subject_id}`:path==='admissions'?`${row.asset_instance_id} · ${row.state} · ${row.content_hash}`:`${row.title} · ${row.status} · ${row.severity}`;section.append(line);}
    box.append(section);
  }
}

function guarded(action) { return () => action().catch(error => {if(!(error instanceof UnauthenticatedError))showNotice(error.message,'error');}); }
byId('approvalRefresh').addEventListener('click',guarded(refreshApprovals));
byId('hostEventsRefresh').addEventListener('click',guarded(refreshHostEvents));
byId('correlateExecution').addEventListener('click',guarded(correlateCurrent));
byId('governanceRefresh').addEventListener('click',guarded(refreshGovernance));

let approvalRefreshBusy = false;
setInterval(async () => {
  if (!state.user || document.hidden || location.hash !== '#approvals' || approvalRefreshBusy) return;
  approvalRefreshBusy = true;
  try { await refreshApprovals(); }
  catch (error) { if (!(error instanceof UnauthenticatedError)) showNotice(error.message, 'error'); }
  finally { approvalRefreshBusy = false; }
}, 2000);
