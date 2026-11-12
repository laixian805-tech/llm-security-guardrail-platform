const byId = (id) => document.getElementById(id);
const state = {
  engines: [], providers: [], scans: [], selectedScan: null, user: null,
  products: [], executions: [], findings: [], hostEvents: [],
  assessments: [], decisions: [], admissions: [], incidents: [],
  policyVersions: [], activePolicy: null,
};
const roleLabels = { admin: "管理员", operator: "操作员", viewer: "只读" };
const severityLabels = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "信息", unknown: "未评级",
};
const statusLabels = { completed: "已完成", imported: "已导入", failed: "失败" };
const admissionStateLabels = {
  check: "待审批", approved: "已批准", staged: "已暂存", committed: "已提交",
  verified: "已验证", reconciled: "已复核", rolled_back: "已回滚", failed: "失败",
};
const policyStatusLabels = { draft: "草稿", active: "生效中", retired: "已停用" };
const actionLabels = { allow: "放行", audit: "记录", confirm: "需确认", block: "阻断" };
const incidentStatusLabels = {
  open: "待处理", investigating: "调查中", confirmed: "已确认", false_positive: "误报",
  mitigating: "修复中", verifying: "复测中", closed: "已关闭", reopened: "重新打开",
};
const verificationLabels = { verified: "已验证", unverified: "未验证" };
const hookEventLabels = {
  session_start: "会话开始", pre_tool_use: "工具调用前",
  post_tool_use: "工具调用后", session_end: "会话结束",
};
const capabilityLabels = { observe: "观测", confirm: "确认", deny: "拒绝" };
// 与服务端 incident_transition 的转移表一致；服务端仍是权威校验方。
const incidentTransitions = {
  open: ["investigating"],
  investigating: ["confirmed", "false_positive"],
  confirmed: ["mitigating"],
  mitigating: ["verifying"],
  verifying: ["closed", "mitigating"],
  false_positive: ["closed"],
  closed: ["reopened"],
  reopened: ["investigating"],
};
const evidenceKinds = { finding: "发现项", execution: "执行", retest_run: "复测运行", attribution: "归因" };
const JSON_HEADERS = { "Content-Type": "application/json" };

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

function addHashCell(row, value) {
  const cell = document.createElement("td");
  if (value) {
    const code = document.createElement("code");
    code.textContent = `${value.slice(0, 16)}…`;
    code.title = value;
    cell.append(code);
  } else {
    cell.textContent = "—";
  }
  row.append(cell);
  return cell;
}

function addPillCell(row, value, labels = {}, pillClass = "statusPill") {
  const cell = document.createElement("td");
  const pill = document.createElement("span");
  pill.className = `${pillClass} ${value}`;
  pill.textContent = labels[value] || value;
  cell.append(pill);
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

function guarded(action) { return () => action().catch(error => {if(!(error instanceof UnauthenticatedError))showNotice(error.message,'error');}); }

// 写操作统一要求 govern 权限（operator/admin）；只读账号看到的按钮置灰而不是隐藏，
// 避免界面看起来"没有这个功能"。
const canGovern = () => ['admin','operator'].includes(state.user?.role);

function applyGovernanceGating() {
  const govern = canGovern();
  const controls = ['riskSubmit','evaluateSubmit','policyDraftSubmit','policyTemplateButton',
    'admissionSubmit','incidentSubmit','correlateExecution','riskAsset','riskExecution',
    'exposurePrivileged','exposureNetwork','exposureUntrusted','evalSubjectKind','evalSubjectId',
    'policyVersionName','policyRulesJson','admissionAsset','admissionHash','admissionTransaction',
    'incidentTitle','incidentSeverity','incidentOwner','incidentSummary'];
  for (const id of controls) {
    const element = byId(id);
    if (!element) continue;
    element.disabled = !govern;
    if (element.tagName === 'BUTTON') element.title = govern ? '' : '需要 operator 或 admin 权限';
  }
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
  state.findings = findings;
  renderFindings(findings.slice(0, 100));
  renderFindingChoices();
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
    await Promise.all([
      loadCenter(refreshRuntime),
      loadCenter(refreshApprovals),
      loadCenter(refreshAssets),
      loadCenter(refreshPolicy),
      loadCenter(refreshAdmissions),
      loadCenter(refreshIncidents),
    ]);
  } catch (error) {
    if (error instanceof UnauthenticatedError) return;  // 已跳登录页
    showNotice(error.message, "error");
  }
}

// 单个工作台加载失败只提示自己的错误，不连带其它中心一起空白。
async function loadCenter(loader) {
  try {
    await loader();
  } catch (error) {
    if (error instanceof UnauthenticatedError) throw error;
    showNotice(error.message, "error");
  }
}

async function loadFindings(scanId) {
  try {
    const detail = await request(`/api/scans/${scanId}`);
    state.selectedScan = scanId;
    renderFindings(detail.findings);
    byId("findingCount").textContent = `当前扫描共 ${detail.findings.length} 条`;
    location.hash = "detections";
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
      headers: JSON_HEADERS,
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
      headers: JSON_HEADERS,
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
      headers: JSON_HEADERS,
      body: JSON.stringify({
        username: byId("loginUser").value.trim(),
        password: byId("loginPassword").value,
      }),
    });
    state.user = { username: session.username, role: session.role };
    hideAuthGate();
    applyGovernanceGating();
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
    applyGovernanceGating();
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

byId('runtimeRefresh').addEventListener('click', guarded(refreshRuntime));
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
    if (row.state === 'pending' && canGovern()) {
      for (const [decision, text] of [['approved','批准本次调用'],['denied','拒绝本次调用']]) {
        const button = document.createElement('button'); button.type = 'button'; button.className = 'secondaryButton'; button.textContent = text;
        button.addEventListener('click',async () => {
          button.disabled = true;
          try {
            await request(`/api/v1/approvals/${encodeURIComponent(row.approval_id)}`,{method:'POST',headers:JSON_HEADERS,body:JSON.stringify({decision,params_sha256:row.params_sha256})});
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
  state.hostEvents = result.events;
  const box = byId('hostEvents');box.replaceChildren();
  for (const row of result.events) {
    const item=document.createElement('li');
    item.textContent=`${formatTime(row.occurred_at)} · ${row.event_type} · PID ${row.pid ?? '未知'} / PPID ${row.ppid ?? '未知'} · ${row.executable || ''} · ${row.resource_path || row.resource_host || ''} · ${row.result || ''} · ${row.execution_id ? '有执行上下文' : '未归因'}`;
    box.append(item);
  }
  if (!result.events.length) box.textContent='该设备尚无运行事件。';
  renderEventChoices();
}

async function correlateCurrent() {
  const id=byId('runtimeExecution').value;if(!id)return;
  const result=await request(`/api/v1/executions/${encodeURIComponent(id)}/correlate`,{method:'POST',headers:JSON_HEADERS,body:'{}'});
  const edges=await request(`/api/v1/executions/${encodeURIComponent(id)}/attributions`);
  const box=byId('attributionCandidates');box.replaceChildren();
  const summary=document.createElement('p');summary.textContent=`候选 ${result.candidate_count} · 强候选选择 ${result.selected_count} · 本次扫描未归因 ${result.unattributed_count}（同主机事件可能属于其他会话）`;box.append(summary);
  for(const edge of edges.attributions){const line=document.createElement('p');line.textContent=`${edge.event_id} → ${edge.intent_id} · ${edge.method} · ${edge.confidence} · ${edge.selected ? '当前选择，仍须核验证据' : '未选择候选'}`;box.append(line);}
}

/* ---------- 资产中心 ---------- */

async function refreshAssets() {
  const [catalog, executions] = await Promise.all([
    request('/api/v1/products'), request('/api/v1/executions?limit=200'),
  ]);
  state.products = catalog.products;
  state.executions = executions.executions;
  renderAssetProducts();
  renderAssetHosts();
  renderExecutionChoices();
}

// 产品级验证等级取最保守的条目：适配器上的 verification 是计算属性，不出现在
// 序列化结果里，因此按事件逐条聚合，任一条未实测整个产品就是未实测。
function productVerification(product) {
  if (!product.events.length) return 'unverified';
  return product.events.every((event) => event.verification === 'verified') ? 'verified' : 'unverified';
}

function renderAssetProducts() {
  const tbody = byId('assetProductRows');
  tbody.replaceChildren();
  for (const product of state.products) {
    const row = document.createElement('tr');
    const name = addCell(row, `${product.product_id} ${product.product_version}`);
    const adapter = document.createElement('small');
    adapter.textContent = `适配器 ${product.adapter_version}`;
    name.append(adapter);
    addCell(row, product.vendor);
    addCell(row, product.hook_transport);
    addCell(row, product.collector_id);
    const verified = product.events.filter((event) => event.verification === 'verified').length;
    const observation = addPillCell(row, productVerification(product), verificationLabels);
    const detail = document.createElement('small');
    detail.textContent = `${verified}/${product.events.length} 类事件已验证`;
    observation.append(detail);
    for (const event of product.events) {
      const line = document.createElement('small');
      const capabilities = event.capabilities.map((name) => capabilityLabels[name] || name).join('/');
      line.textContent = `${hookEventLabels[event.hook_event_type] || event.hook_event_type}: ${capabilities}${event.pre_execution ? '（执行前）' : ''}`;
      observation.append(line);
    }
    const approval = document.createElement('td');
    const pill = document.createElement('span');
    pill.className = `statusPill ${product.mediated_approval_supported ? 'ready' : 'missing'}`;
    pill.textContent = product.mediated_approval_supported ? '可用' : '未验证';
    approval.append(pill);
    const protocol = document.createElement('small');
    protocol.textContent = product.mediated_approval_protocol || 'none';
    approval.append(protocol);
    row.append(approval);
    const ingest = document.createElement('td');
    const ingestPill = document.createElement('span');
    ingestPill.className = `statusPill ${product.ingest_supported ? 'ready' : 'missing'}`;
    ingestPill.textContent = product.ingest_supported ? '可摄入' : '不可摄入';
    ingest.append(ingestPill);
    const ingestDetail = document.createElement('small');
    ingestDetail.textContent = product.ingest_supported
      ? `${product.events.length} 类 Hook 事件`
      : product.unsupported_reason;
    ingest.append(ingestDetail);
    row.append(ingest);
    tbody.append(row);
  }
  if (!state.products.length) addEmptyRow(tbody, 7, '没有读取到产品能力矩阵。');
}

function renderAssetHosts() {
  const tbody = byId('assetHostRows');
  tbody.replaceChildren();
  const hosts = new Map();
  for (const execution of state.executions) {
    const entry = hosts.get(execution.host_id) || {
      count: 0, products: new Set(), instances: new Set(), latest: execution.started_at,
    };
    entry.count += 1;
    entry.products.add(`${execution.product} ${execution.product_version}`);
    if (execution.asset_instance_id) entry.instances.add(execution.asset_instance_id);
    if (new Date(execution.started_at) > new Date(entry.latest)) entry.latest = execution.started_at;
    hosts.set(execution.host_id, entry);
  }
  const rows = [...hosts.entries()].sort((left, right) => new Date(right[1].latest) - new Date(left[1].latest));
  for (const [host, entry] of rows) {
    const row = document.createElement('tr');
    addCell(row, host);
    addCell(row, String(entry.count));
    addCell(row, [...entry.products].join('、'));
    addCell(row, entry.instances.size ? [...entry.instances].join('、') : '未引用');
    addCell(row, formatTime(entry.latest));
    tbody.append(row);
  }
  if (!rows.length) addEmptyRow(tbody, 5, '暂无上报执行。在已登记测试设备运行 Agent 后刷新。');
  byId('assetHostCount').textContent = `${rows.length} 台主机 · ${state.executions.length} 次执行`;
}

function renderExecutionChoices() {
  const select = byId('riskExecution');
  const previous = select.value;
  select.replaceChildren();
  const empty = document.createElement('option');
  empty.value = '';
  empty.textContent = '不关联执行';
  select.append(empty);
  for (const execution of state.executions) {
    const option = document.createElement('option');
    option.value = execution.execution_id;
    option.textContent = `${execution.product} ${execution.product_version} · ${execution.host_id} · ${formatTime(execution.started_at)}`;
    select.append(option);
  }
  if (state.executions.some((execution) => execution.execution_id === previous)) select.value = previous;
}

/* ---------- 风险与策略 ---------- */

async function refreshPolicy() {
  const [assessments, decisions, versions, active] = await Promise.all([
    request('/api/v1/risk-assessments'), request('/api/v1/policy-decisions'),
    request('/api/v1/policies/versions'), request('/api/v1/policies/active'),
  ]);
  state.assessments = assessments.items;
  state.decisions = decisions.items;
  state.policyVersions = versions.items;
  state.activePolicy = active.active;
  renderActivePolicy();
  renderPolicyVersions();
  renderAssessmentChoices();
  renderRiskAssessments();
  renderDecisions();
}

function describeConditions(rule) {
  const parts = [];
  if (rule.intrinsic_risk_min != null) parts.push(`固有 ≥ ${rule.intrinsic_risk_min}`);
  if (rule.runtime_risk_min != null) parts.push(`运行 ≥ ${rule.runtime_risk_min}`);
  if (rule.exposure_risk_min != null) parts.push(`暴露 ≥ ${rule.exposure_risk_min}`);
  if (rule.any_dimension_above != null) parts.push(`任一维度 > ${rule.any_dimension_above}`);
  if (rule.peak_at_most != null) parts.push(`最高维度 ≤ ${rule.peak_at_most}`);
  return parts.length ? `条件：${parts.join('，')}` : '无条件兜底规则';
}

function renderActivePolicy() {
  const box = byId('policyActive');
  box.replaceChildren();
  const version = state.activePolicy;
  byId('policyActiveMeta').textContent = version
    ? `创建者 ${version.created_by} · 激活于 ${formatTime(version.activated_at)}`
    : '';
  if (!version) {
    const hint = document.createElement('p');
    hint.className = 'fieldHint';
    hint.textContent = '没有活跃策略版本：求值会返回 500 no_active_policy，平台不静默回退到写死规则。请创建草稿版本并激活。';
    box.append(hint);
    return;
  }
  const title = document.createElement('p');
  title.textContent = `${version.policy_version} · ${version.rules.length} 条规则 · 依序首个命中者胜出`;
  box.append(title);
  for (const rule of version.rules) {
    const item = document.createElement('article');
    item.className = 'ruleRow';
    const head = document.createElement('strong');
    head.textContent = `${rule.rule_id} → ${actionLabels[rule.action] || rule.action}`;
    const reason = document.createElement('p');
    reason.textContent = rule.reason;
    const conditions = document.createElement('p');
    conditions.className = 'fieldHint';
    conditions.textContent = describeConditions(rule);
    item.append(head, reason, conditions);
    box.append(item);
  }
}

function renderPolicyVersions() {
  const tbody = byId('policyVersionRows');
  tbody.replaceChildren();
  for (const version of state.policyVersions) {
    const row = document.createElement('tr');
    addCell(row, version.policy_version);
    addPillCell(row, version.status, policyStatusLabels);
    addCell(row, String(version.rules.length));
    addCell(row, version.created_by);
    addCell(row, formatTime(version.created_at));
    addCell(row, formatTime(version.activated_at));
    const actions = document.createElement('td');
    actions.className = 'actionCell';
    if (version.status === 'active') {
      actions.textContent = '生效中';
    } else {
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'secondaryButton';
      button.textContent = '激活';
      button.disabled = !canGovern();
      button.title = canGovern() ? '原子激活：旧版本停用与新版本生效在同一事务' : '需要 operator 或 admin 权限';
      button.addEventListener('click', guarded(async () => {
        button.disabled = true;
        try {
          await request(`/api/v1/policies/versions/${encodeURIComponent(version.policy_version)}/activate`,
            { method: 'POST', headers: JSON_HEADERS, body: '{}' });
          showNotice(`已激活策略版本 ${version.policy_version}`, 'success');
          await refreshPolicy();
        } catch (error) {
          showNotice(error.message, 'error');
          button.disabled = !canGovern();
        }
      }));
      actions.append(button);
    }
    row.append(actions);
    tbody.append(row);
  }
  if (!state.policyVersions.length) addEmptyRow(tbody, 7, '暂无策略版本。');
  byId('policyVersionCount').textContent = `${state.policyVersions.length} 个版本`;
}

function renderAssessmentChoices() {
  const select = byId('evalAssessment');
  const previous = select.value;
  select.replaceChildren();
  for (const assessment of state.assessments) {
    const option = document.createElement('option');
    option.value = assessment.assessment_id;
    option.textContent = `${assessment.assessment_id} · 固有 ${assessment.intrinsic_risk} / 运行 ${assessment.runtime_risk} / 暴露 ${assessment.exposure_risk}`;
    select.append(option);
  }
  if (state.assessments.some((assessment) => assessment.assessment_id === previous)) select.value = previous;
  byId('evaluateSubmit').disabled = !canGovern() || !state.assessments.length;
}

function renderRiskAssessments() {
  const box = byId('riskList');
  box.replaceChildren();
  if (!state.assessments.length) {
    box.textContent = '暂无风险评估。';
    return;
  }
  for (const assessment of state.assessments) {
    const item = document.createElement('article');
    item.className = 'recordItem';
    const head = document.createElement('strong');
    head.textContent = `${assessment.assessment_id} · 固有 ${assessment.intrinsic_risk} / 运行 ${assessment.runtime_risk} / 暴露 ${assessment.exposure_risk} · 置信度 ${assessment.confidence}`;
    const meta = document.createElement('p');
    meta.textContent = `资产 ${assessment.asset_id || '未关联'} · 执行 ${assessment.execution_id || '未关联'} · 证据 ${assessment.evidence_refs.length} 条 · 规则 ${assessment.rule_version} · ${formatTime(assessment.created_at)}`;
    const reasons = document.createElement('p');
    reasons.textContent = assessment.reasons.join('；');
    item.append(head, meta, reasons);
    box.append(item);
  }
}

function renderDecisions() {
  const box = byId('decisionList');
  box.replaceChildren();
  if (!state.decisions.length) {
    box.textContent = '暂无策略决定。';
    return;
  }
  for (const decision of state.decisions) {
    const item = document.createElement('article');
    item.className = 'recordItem';
    const head = document.createElement('strong');
    head.textContent = `${actionLabels[decision.action] || decision.action} · ${decision.policy_version} · ${decision.subject_kind}:${decision.subject_id}`;
    const meta = document.createElement('p');
    meta.textContent = `${decision.reason} · ${formatTime(decision.created_at)} · 过期 ${formatTime(decision.expires_at)}`;
    const boundary = document.createElement('p');
    boundary.className = 'fieldHint';
    boundary.textContent = `enforcement_expected=${decision.enforcement_expected}：本条只是决定记录，不是执行回执。`;
    item.append(head, meta, boundary);
    box.append(item);
  }
}

function renderFindingChoices() {
  const box = byId('riskFindings');
  const previous = new Set([...box.querySelectorAll('input:checked')].map((input) => input.value));
  box.replaceChildren();
  if (!state.findings.length) {
    box.textContent = '暂无发现项。请先在检测中心加载扫描记录。';
    return;
  }
  for (const finding of state.findings.slice(0, 40)) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = finding.finding_id;
    input.checked = previous.has(finding.finding_id);
    input.disabled = !canGovern();
    const text = document.createElement('span');
    text.textContent = `${severityLabels[finding.severity] || finding.severity} · ${finding.engine} ${finding.rule_id} · ${finding.title}`;
    label.append(input, text);
    box.append(label);
  }
  if (state.findings.length > 40) {
    const hint = document.createElement('p');
    hint.className = 'fieldHint';
    hint.textContent = `仅显示最近 40 条发现项（共 ${state.findings.length} 条）。`;
    box.append(hint);
  }
}

function renderEventChoices() {
  const box = byId('riskEvents');
  const previous = new Set([...box.querySelectorAll('input:checked')].map((input) => input.value));
  box.replaceChildren();
  if (!state.hostEvents.length) {
    box.textContent = '暂无运行事件。请先在主机运行事件按主机加载。';
    return;
  }
  for (const event of state.hostEvents.slice(0, 60)) {
    const label = document.createElement('label');
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.value = JSON.stringify({
      host_id: event.host_id, collector_id: event.collector_id, event_id: event.event_id,
    });
    input.checked = previous.has(input.value);
    input.disabled = !canGovern();
    const text = document.createElement('span');
    text.textContent = `${formatTime(event.occurred_at)} · ${event.event_type} · PID ${event.pid ?? '未知'} · ${event.executable || ''} · ${event.execution_id ? '有执行上下文' : '未归因'}`;
    label.append(input, text);
    box.append(label);
  }
}

function checkedInputs(id) {
  return [...byId(id).querySelectorAll('input:checked')];
}

byId('riskForm').addEventListener('submit', guarded(async () => {
  const body = {};
  const asset = byId('riskAsset').value.trim();
  const execution = byId('riskExecution').value;
  if (asset) body.asset_id = asset;
  if (execution) body.execution_id = execution;
  body.finding_ids = checkedInputs('riskFindings').map((input) => input.value);
  body.event_ids = checkedInputs('riskEvents').map((input) => JSON.parse(input.value));
  const exposure = {};
  if (byId('exposurePrivileged').checked) exposure.privileged = true;
  if (byId('exposureNetwork').checked) exposure.network_access = true;
  if (byId('exposureUntrusted').checked) exposure.untrusted_source = true;
  if (Object.keys(exposure).length) body.exposure = exposure;
  const button = byId('riskSubmit');
  button.disabled = true;
  try {
    const result = await request('/api/v1/risk-assessments', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });
    showNotice(`已创建风险评估 ${result.assessment_id}：固有 ${result.intrinsic_risk} / 运行 ${result.runtime_risk} / 暴露 ${result.exposure_risk}`, 'success');
    await refreshPolicy();
    byId('evalAssessment').value = result.assessment_id;
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern();
  }
}));

byId('evaluateForm').addEventListener('submit', guarded(async () => {
  const body = {
    assessment_id: byId('evalAssessment').value,
    subject_kind: byId('evalSubjectKind').value.trim(),
    subject_id: byId('evalSubjectId').value.trim(),
  };
  if (!body.assessment_id) { showNotice('请先创建或选择一条风险评估。', 'error'); return; }
  if (!body.subject_kind || !body.subject_id) { showNotice('主体类型与主体 ID 都必须填写。', 'error'); return; }
  const button = byId('evaluateSubmit');
  button.disabled = true;
  try {
    const result = await request('/api/v1/policies/evaluate', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });
    showNotice(`策略决定 ${result.action} · 版本 ${result.policy_version} · ${result.reason}`, 'success');
    await refreshPolicy();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern() || !state.assessments.length;
  }
}));

byId('policyDraftForm').addEventListener('submit', guarded(async () => {
  const name = byId('policyVersionName').value.trim();
  let rules;
  try {
    rules = JSON.parse(byId('policyRulesJson').value);
  } catch (error) {
    showNotice('规则不是合法 JSON，请检查后重试。', 'error');
    return;
  }
  if (!Array.isArray(rules)) { showNotice('规则必须是 JSON 数组。', 'error'); return; }
  const button = byId('policyDraftSubmit');
  button.disabled = true;
  try {
    const result = await request('/api/v1/policies/versions',
      { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ policy_version: name, rules }) });
    showNotice(`已创建草稿版本 ${result.policy_version}（${result.rules.length} 条规则），激活后才会参与求值。`, 'success');
    byId('policyRulesJson').value = '';
    await refreshPolicy();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern();
  }
}));

const POLICY_TEMPLATE = [
  {
    rule_id: 'block-critical-intrinsic',
    action: 'block',
    reason: 'intrinsic risk at or above 90',
    intrinsic_risk_min: 90,
  },
  {
    rule_id: 'confirm-high-intrinsic',
    action: 'confirm',
    reason: 'intrinsic risk at or above 70',
    intrinsic_risk_min: 70,
  },
  {
    rule_id: 'audit-observed',
    action: 'audit',
    reason: 'any risk dimension observed',
    any_dimension_above: 0,
  },
  {
    rule_id: 'allow-clean',
    action: 'allow',
    reason: 'no risk dimension observed',
    peak_at_most: 0,
  },
];
byId('policyTemplateButton').addEventListener('click', () => {
  byId('policyRulesJson').value = JSON.stringify(POLICY_TEMPLATE, null, 2);
});

/* ---------- 准入安装 ---------- */

async function refreshAdmissions() {
  const result = await request('/api/v1/admissions');
  state.admissions = result.items;
  renderAdmissions();
}

function renderAdmissions() {
  const tbody = byId('admissionRows');
  tbody.replaceChildren();
  if (!state.admissions.length) {
    addEmptyRow(tbody, 8, '暂无准入检查。创建检查后按 批准 → 暂存 → 提交 → 校验 → 复核 推进。');
    return;
  }
  for (const admission of state.admissions) {
    const row = document.createElement('tr');
    const id = addCell(row, admission.admission_id);
    const transaction = document.createElement('small');
    transaction.textContent = `事务 ${admission.transaction_id}`;
    id.append(transaction);
    addCell(row, admission.asset_instance_id);
    addHashCell(row, admission.content_hash);
    addHashCell(row, admission.observed_content_hash);
    addPillCell(row, admission.state, admissionStateLabels);
    addCell(row, admission.rollback_ref || '未提交');
    addCell(row, admission.failure_reason || '—');
    const actions = document.createElement('td');
    actions.className = 'actionCell';
    renderAdmissionActions(actions, admission);
    row.append(actions);
    tbody.append(row);
  }
}

function renderAdmissionActions(cell, admission) {
  const govern = canGovern();
  const post = (action, buildBody) => request(
    `/api/v1/admissions/${encodeURIComponent(admission.admission_id)}/${action}`,
    { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(buildBody ? buildBody() : {}) },
  );
  const addButton = (text, action, buildBody, title = '') => {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'secondaryButton';
    button.textContent = text;
    button.disabled = !govern;
    button.title = govern ? title : '需要 operator 或 admin 权限';
    button.addEventListener('click', guarded(async () => {
      button.disabled = true;
      try {
        const result = await post(action, buildBody);
        showNotice(`${admission.admission_id} ${text}完成：${result.state}${result.failure_reason ? ` · ${result.failure_reason}` : ''}`, 'success');
        await refreshAdmissions();
      } catch (error) {
        showNotice(error.message, 'error');
        button.disabled = !govern;
      }
    }));
    cell.append(button);
    return button;
  };

  if (admission.state === 'check') {
    addButton('批准', 'approve', null, '记录实际授权操作者');
    return;
  }
  if (admission.state === 'approved') {
    const source = document.createElement('input');
    source.placeholder = 'inbound 下的相对路径';
    source.title = '托管 inbound 目录下的相对路径，例如 pkg-demo';
    source.disabled = !govern;
    cell.append(source);
    addButton('暂存', 'stage', () => ({ source_path: source.value.trim() }), '复制进暂存区并实测哈希，与审批声明不一致直接失败');
    return;
  }
  if (admission.state === 'staged') {
    addButton('提交', 'commit', null, '复核哈希后原子替换已安装内容，旧版本先快照');
    addButton('回滚', 'rollback', null, '未提交事务只丢弃暂存，不动已安装内容');
    return;
  }
  if (admission.state === 'committed') {
    addButton('校验', 'verify', null, '重算已安装内容哈希，不一致记 failed');
    addButton('回滚', 'rollback', null, '恢复本次提交前快照，或移除首次安装');
    return;
  }
  if (admission.state === 'verified') {
    addButton('复核', 'reconcile', null, '再次核对落盘内容与审批哈希');
    addButton('回滚', 'rollback', null, '恢复本次提交前快照，或移除首次安装');
    return;
  }
  if (admission.state === 'reconciled' || admission.state === 'failed') {
    addButton('回滚', 'rollback', null, '恢复本次提交前快照；从未提交的事务不会有文件系统后果');
    return;
  }
  cell.textContent = '—';
}

byId('admissionForm').addEventListener('submit', guarded(async () => {
  const body = {
    asset_instance_id: byId('admissionAsset').value.trim(),
    content_hash: byId('admissionHash').value.trim(),
    transaction_id: byId('admissionTransaction').value.trim(),
  };
  const button = byId('admissionSubmit');
  button.disabled = true;
  try {
    const result = await request('/api/v1/admissions/check', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });
    showNotice(`已创建准入检查 ${result.admission_id}（${result.state}）`, 'success');
    byId('admissionAsset').value = '';
    byId('admissionHash').value = '';
    byId('admissionTransaction').value = '';
    await refreshAdmissions();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern();
  }
}));

/* ---------- Incident 中心 ---------- */

async function refreshIncidents() {
  const result = await request('/api/v1/incidents');
  state.incidents = result.items;
  renderIncidents();
}

function renderIncidents() {
  const tbody = byId('incidentRows');
  tbody.replaceChildren();
  for (const incident of state.incidents) {
    const row = document.createElement('tr');
    const title = addCell(row, incident.title);
    const summary = document.createElement('small');
    summary.textContent = `${incident.incident_id}${incident.summary ? ` · ${incident.summary}` : ''}`;
    title.append(summary);
    addPillCell(row, incident.severity, severityLabels, 'severityPill');
    addPillCell(row, incident.status, incidentStatusLabels);
    addCell(row, incident.owner || '未指派');
    addCell(row, formatTime(incident.opened_at));
    addCell(row, formatTime(incident.closed_at));
    addPillCell(row, incident.severity, severityLabels, 'severityPill');
    const actions = document.createElement('td');
    actions.className = 'actionCell';
    renderIncidentActions(actions, incident);
    row.append(actions);
    tbody.append(row);
  }
  if (!state.incidents.length) addEmptyRow(tbody, 7, '暂无 Incident 工单。');
}

function renderIncidentActions(cell, incident) {
  const govern = canGovern();
  const next = incidentTransitions[incident.status] || [];
  if (!next.length) {
    cell.textContent = '—';
    return;
  }
  const select = document.createElement('select');
  select.title = '下一个状态';
  select.disabled = !govern;
  for (const status of next) {
    const option = document.createElement('option');
    option.value = status;
    option.textContent = incidentStatusLabels[status] || status;
    select.append(option);
  }
  cell.append(select);

  const kind = document.createElement('select');
  kind.title = '证据类型';
  kind.disabled = !govern;
  for (const [value, label] of Object.entries(evidenceKinds)) {
    const option = document.createElement('option');
    option.value = value;
    option.textContent = label;
    kind.append(option);
  }
  cell.append(kind);

  const evidenceId = document.createElement('input');
  evidenceId.placeholder = '证据 ID';
  evidenceId.title = 'Finding / Execution / DetectorRun / Attribution ID';
  evidenceId.disabled = !govern;
  cell.append(evidenceId);

  const update = document.createElement('button');
  update.type = 'button';
  update.className = 'secondaryButton';
  update.textContent = '更新状态';
  update.disabled = !govern;
  update.title = govern
    ? (next.includes('closed') ? '关闭需要工单开启后同检测器同目标的 clean 复测证据' : '流转工单状态')
    : '需要 operator 或 admin 权限';
  update.addEventListener('click', guarded(async () => {
    update.disabled = true;
    try {
      await request(`/api/v1/incidents/${encodeURIComponent(incident.incident_id)}`,
        { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ status: select.value }) });
      showNotice(`${incident.incident_id} 状态已更新为 ${incidentStatusLabels[select.value] || select.value}`, 'success');
      await refreshIncidents();
    } catch (error) {
      showNotice(error.message, 'error');
      update.disabled = !govern;
    }
  }));
  cell.append(update);

  const attach = document.createElement('button');
  attach.type = 'button';
  attach.className = 'secondaryButton';
  attach.textContent = '关联证据';
  attach.disabled = !govern;
  attach.title = govern ? '关联已存在的证据记录' : '需要 operator 或 admin 权限';
  attach.addEventListener('click', guarded(async () => {
    const value = evidenceId.value.trim();
    if (!value) { showNotice('请填写证据 ID。', 'error'); return; }
    attach.disabled = true;
    try {
      await request(`/api/v1/incidents/${encodeURIComponent(incident.incident_id)}/evidence`,
        { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ evidence_kind: kind.value, evidence_id: value }) });
      showNotice(`已关联${evidenceKinds[kind.value]}证据 ${value}`, 'success');
      evidenceId.value = '';
    } catch (error) {
      showNotice(error.message, 'error');
      attach.disabled = !govern;
    }
  }));
  cell.append(attach);
}

byId('incidentForm').addEventListener('submit', guarded(async () => {
  const body = {
    title: byId('incidentTitle').value.trim(),
    severity: byId('incidentSeverity').value,
    owner: byId('incidentOwner').value.trim() || undefined,
    summary: byId('incidentSummary').value.trim() || undefined,
  };
  const button = byId('incidentSubmit');
  button.disabled = true;
  try {
    const result = await request('/api/v1/incidents', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });
    showNotice(`已创建工单 ${result.incident_id}`, 'success');
    byId('incidentTitle').value = '';
    byId('incidentOwner').value = '';
    byId('incidentSummary').value = '';
    await refreshIncidents();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern();
  }
}));

byId('assetsRefresh').addEventListener('click', guarded(refreshAssets));
byId('policyRefresh').addEventListener('click', guarded(refreshPolicy));
byId('admissionsRefresh').addEventListener('click', guarded(refreshAdmissions));
byId('incidentsRefresh').addEventListener('click', guarded(refreshIncidents));
byId('hostEventsRefresh').addEventListener('click', guarded(refreshHostEvents));
byId('approvalRefresh').addEventListener('click', guarded(refreshApprovals));
byId('correlateExecution').addEventListener('click', guarded(correlateCurrent));

let approvalRefreshBusy = false;
setInterval(async () => {
  if (!state.user || document.hidden || location.hash !== '#approvals' || approvalRefreshBusy) return;
  approvalRefreshBusy = true;
  try { await refreshApprovals(); }
  catch (error) { if (!(error instanceof UnauthenticatedError)) showNotice(error.message, 'error'); }
  finally { approvalRefreshBusy = false; }
}, 2000);
