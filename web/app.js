const byId = (id) => document.getElementById(id);
const state = {
  engines: [], providers: [], scans: [], selectedScan: null, user: null,
  products: [], executions: [], findings: [], hostEvents: [],
  assessments: [], decisions: [], admissions: [], incidents: [],
  policyVersions: [], activePolicy: null, ledger: { items: [], links: {} },
  coverage: null,
};
const roleLabels = { admin: "管理员", operator: "操作员", viewer: "只读" };
const severityLabels = {
  critical: "严重", high: "高", medium: "中", low: "低", info: "信息", unknown: "未评级",
};
const statusLabels = { completed: "已完成", imported: "已导入", failed: "失败" };
const findingStatusLabels = {
  new: "新建", triaged: "已分级", resolved: "已解决",
  false_positive: "误报", reopened: "重新打开",
};
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
const confidenceLabels = { high: "高", medium: "中", low: "低", unknown: "未测量" };
const riskDimensionLabels = { intrinsic: "固有风险", runtime: "运行风险", exposure: "暴露风险" };
const hookEventLabels = {
  session_start: "会话开始", pre_tool_use: "工具调用前",
  post_tool_use: "工具调用后", session_end: "会话结束",
};
const capabilityLabels = { observe: "观测", confirm: "确认", deny: "拒绝" };
const assetTypeLabels = {
  agent: "Agent", skill: "Skill", mcp_server: "MCP Server", plugin: "插件", tool: "工具",
};
const installationStateLabels = {
  unknown: "未知", installed: "已安装", absent: "缺失", broken: "损坏",
};
const activationStateLabels = { unknown: "未知", disabled: "已停用", enabled: "已启用" };
const runtimeStateLabels = { unknown: "未知", running: "运行中", stopped: "已停止", idle: "空闲" };
const timelineSectionLabels = {
  intent: "Hook 意图", runtime_event: "运行事件", attribution: "归因候选",
  finding: "发现项", policy_decision: "策略决定", admission: "准入事务",
};
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

// 参数必须透传：submit 处理函数要拿 event 调 preventDefault，否则表单会走原生
// GET 提交把整页刷掉。
function guarded(action) { return (...args) => action(...args).catch(error => {if(!(error instanceof UnauthenticatedError))showNotice(error.message,'error');}); }

// 写操作统一要求 govern 权限（operator/admin）；只读账号看到的按钮置灰而不是隐藏，
// 避免界面看起来"没有这个功能"。
const canGovern = () => ['admin','operator'].includes(state.user?.role);

function applyGovernanceGating() {
  const govern = canGovern();
  const controls = ['riskSubmit','evaluateSubmit','policyDraftSubmit','policyTemplateButton',
    'admissionSubmit','incidentSubmit','correlateExecution','riskAsset','riskExecution',
    'exposurePrivileged','exposureNetwork','exposureUntrusted','evalSubjectKind','evalSubjectId',
    'policyVersionName','policyRulesJson','admissionAsset','admissionHash','admissionTransaction',
    'incidentTitle','incidentSeverity','incidentOwner','incidentSummary',
    'assetType','assetName','assetProduct','assetPublisher','assetHost','assetScope',
    'assetInstallPath','assetVersion','assetHash','assetPublisherId','assetSignature',
    'assetRegisterSubmit','publisherName','publisherKey','publisherSubmit','runtimeCorrelateBtn'];
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
      loadCenter(refreshCoverage),
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
  else {
    byId('runtimeEntries').replaceChildren();
    byId('effectDiffSummary').hidden = true;
    byId('effectDiffList').replaceChildren();
  }
}

const SOURCE_KIND_LABELS = {
  user_task: '用户任务（高信任）',
  workspace_config: '工作区配置（中信任）',
  installed_skill: '已安装 Skill（低信任）',
  mcp_server: 'MCP Server（低信任）',
  tool_output: '工具输出/网页（非信任）',
  unknown: '来源未标定',
};
const VERDICT_META = {
  undeclared_side_effect: { label: '越界副作用', cls: 'danger' },
  within_expected: { label: '符合预期', cls: 'ok' },
  no_observed_effect: { label: '无 OS 观测', cls: '' },
  unverified: { label: '待核验', cls: 'warn' },
};

function jumpToGovernanceWithEvidence(targetHash, executionId, summaryText) {
  location.hash = targetHash;
  if (targetHash === '#policy' && byId('riskExecution')) {
    byId('riskExecution').value = executionId;
  } else if (targetHash === '#incidents') {
    if (byId('incidentTitle') && !byId('incidentTitle').value) {
      byId('incidentTitle').value = `越界副作用排查：${executionId.slice(0, 14)}`;
    }
    if (byId('incidentSummary')) {
      byId('incidentSummary').value = summaryText;
    }
  }
}

async function renderEffectDiff(executionId) {
  const strip = byId('effectDiffSummary');
  const list = byId('effectDiffList');
  const hint = byId('effectDiffHint');
  strip.replaceChildren();
  list.replaceChildren();
  let data;
  try {
    data = await request('/api/v1/executions/' + encodeURIComponent(executionId) + '/effect-diff');
  } catch (error) {
    if (error instanceof UnauthenticatedError) return;
    throw error;
  }
  strip.hidden = false;
  const stats = [
    ['来源覆盖 Intent', String(data.intent_count), ''],
    ['强/候选归因 OS 事件', String(data.attributed_event_count), 'ok'],
    ['诚实留空（未归因）', String(data.unattributed_event_count), 'warn'],
    ['越界副作用检出', String(data.undeclared_count), data.undeclared_count > 0 ? 'danger' : 'ok'],
  ];
  for (const [label, value, cls] of stats) {
    const card = document.createElement('div');
    card.className = 'diffStat';
    const s = document.createElement('span'); s.textContent = label;
    const v = document.createElement('strong'); v.className = cls; v.textContent = value;
    card.append(s, v);
    strip.append(card);
  }
  const sourceSummary = Object.entries(data.by_source_kind || {})
    .map(([k, n]) => `${SOURCE_KIND_LABELS[k] || k}: ${n}`).join(' · ');
  hint.textContent = `${data.rule_version}${sourceSummary ? ' · ' + sourceSummary : ''}`;

  if (!(data.items || []).length) {
    const empty = document.createElement('p');
    empty.className = 'fieldHint';
    empty.textContent = '本次执行暂无 Intent 记录。';
    list.append(empty);
    return;
  }
  for (const item of data.items) {
    const meta = VERDICT_META[item.verdict] || { label: item.verdict, cls: '' };
    const card = document.createElement('article');
    card.className = `diffCard verdict-${item.verdict}`;
    const head = document.createElement('div');
    head.className = 'diffCardHead';
    const title = document.createElement('strong');
    title.textContent = `${item.tool_name} · ${SOURCE_KIND_LABELS[item.source_kind] || item.source_kind}${item.source_ref ? ` (${item.source_ref})` : ''}`;
    const badge = document.createElement('span');
    badge.className = `diffBadge ${meta.cls}`.trim();
    badge.textContent = meta.label;
    head.append(title, badge);

    const cols = document.createElement('div');
    cols.className = 'diffCols';
    const left = document.createElement('div');
    left.textContent = `预期边界：${item.expected_scope}`;
    const right = document.createElement('div');
    right.textContent = item.event_id
      ? `OS 实测：${item.event_type} → ${item.observed_target}（${item.attribution_method} / ${item.attribution_confidence}）`
      : 'OS 实测：未归因到系统事件（留空）';
    cols.append(left, right);

    const reason = document.createElement('p');
    reason.className = 'fieldHint';
    reason.style.margin = '0';
    reason.textContent = `差分依据：${item.reason}`;
    card.append(head, cols, reason);

    if (item.verdict === 'undeclared_side_effect') {
      const actions = document.createElement('div');
      actions.className = 'quickActions';
      const toRisk = document.createElement('button');
      toRisk.type = 'button'; toRisk.className = 'secondaryButton';
      toRisk.textContent = '带此执行去风险评估';
      toRisk.addEventListener('click', () => jumpToGovernanceWithEvidence('#policy', executionId, item.reason));
      const toInc = document.createElement('button');
      toInc.type = 'button'; toInc.className = 'secondaryButton';
      toInc.textContent = '发起 Incident 工单';
      toInc.addEventListener('click', () => jumpToGovernanceWithEvidence(
        '#incidents', executionId,
        `${item.tool_name} (${item.source_kind}) 触发越界副作用：${item.observed_target} — ${item.reason}`
      ));
      actions.append(toRisk, toInc);
      card.append(actions);
    }
    list.append(card);
  }
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
    title.textContent = `${formatTime(entry.occurred_at)} · ${timelineEntryTitle(entry)}`;
    const detail = document.createElement('p');
    detail.textContent = timelineEntryDetail(entry);
    item.append(title, detail); list.append(item);
  }
  byId('runtimeBoundary').textContent = `本次执行版本的观测验证：${response.capability_verification === 'verified' ? '已验证' : '未验证'}。归因以证据候选展示，可能冲突；策略决定不等于执行，阻断成功必须另有执行证据。`;
  const links = byId('runtimeSectionLinks');
  links.replaceChildren();
  const supported = document.createElement('span');
  supported.textContent = `已接入分段：${response.sections_supported.map((name) => timelineSectionLabels[name] || name).join('、')}${response.sections_pending.length ? `；未实现：${response.sections_pending.join('、')}` : ''}`;
  links.append(supported);
  for (const [key, text] of Object.entries(response.section_links || {})) {
    const line = document.createElement('small');
    line.textContent = `${timelineSectionLabels[key] || key}：${text}`;
    links.append(line);
  }
  runtimeExecution = id; runtimeCursor = response.next_cursor;
  byId('runtimeMore').hidden = !runtimeCursor;
  if (!append) {
    await Promise.all([
      renderEffectDiff(id),
      renderAttributionLane(id),
      renderDataFlow(id),
    ]);
  }
}

function timelineEntryTitle(entry) {
  const data = entry.data;
  switch (entry.kind) {
    case 'intent': return data.tool_name;
    case 'runtime_event': return data.event_type;
    case 'finding': return `发现项 ${data.finding_id}`;
    case 'admission': return `准入 ${data.transaction_id}`;
    case 'policy_decision': return `策略决定 ${data.decision_id}`;
    default: return entry.kind;
  }
}

function timelineEntryDetail(entry) {
  const data = entry.data;
  switch (entry.kind) {
    case 'intent':
      return `调用 ${data.tool_call_id || '未提供调用 ID'} · 决策记录 ${data.decision} · 结果 ${data.product_result || '尚未观测'} · 参数值已省略`;
    case 'runtime_event':
      return `${data.action || ''} ${data.result || ''} · 归因候选 ${(data.attributions || []).length} · 事件 ID ${data.event_id}`;
    case 'finding':
      return `${data.title} · 严重级别 ${severityLabels[data.severity] || data.severity} · 状态 ${findingStatusLabels[data.status] || data.status} · 分析员 ${data.linked_by || '未登记'}${data.link_note ? ` · ${data.link_note}` : ''}`;
    case 'admission':
      return `${admissionStateLabels[data.state] || data.state} · 声明 ${data.content_hash.slice(0, 16)}… · 实测 ${data.observed_content_hash ? `${data.observed_content_hash.slice(0, 16)}…` : '未测量'} · 实例 ${data.asset_instance_id}`;
    case 'policy_decision':
      return `${data.subject_kind || ''} ${data.subject_id} · 动作 ${actionLabels[data.action] || data.action} · 策略版本 ${data.policy_version} · 执行预期 ${data.enforcement_expected ? '是' : '否'}`;
    default:
      return entry.id;
  }
}

byId('runtimeRefresh').addEventListener('click', guarded(refreshRuntime));
byId('coverageRefresh').addEventListener('click', guarded(refreshCoverage));
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

async function refreshCoverage() {
  const result = await request('/api/v1/coverage?window_hours=24');
  state.coverage = result;
  const summary = byId('coverageSummary');
  const warned = result.hosts.filter((host) => host.warn).length;
  const silent = result.hosts.filter((host) => host.silent).length;
  summary.textContent = `窗口 ${result.window_hours} 小时 · 上报主机 ${result.hosts.length} 台 · 触发告警 ${warned} 台 · 采集器静默 ${silent} 台 · 有执行但无对账上报 ${result.active_hosts_without_reports.length} 台`;
  const box = byId('coverageHosts');box.replaceChildren();
  if (!result.hosts.length) { box.textContent='窗口内没有覆盖度上报。'; return; }
  for (const host of result.hosts) {
    const item=document.createElement('article');item.className='recordItem';
    const head=document.createElement('strong');
    head.textContent=`${host.host_id} · 丢失率 ${host.loss_rate==null?'无数据':(host.loss_rate*100).toFixed(3)+'%'} · 尝试 ${host.attempted} / 丢失 ${host.lost}`;
    const meta=document.createElement('p');
    const gaps=host.gaps.length?` · 量级未知的缺口 ${host.gaps.join('、')}`:'';
    const kinds=Object.keys(host.drop_kinds).length?` · 丢失构成 ${Object.entries(host.drop_kinds).map(([kind,count])=>`${kind} ${count}`).join('、')}`:'';
    meta.textContent=`对账 ${host.reports} 条 · 采集器 ${host.collectors.join('、')||'未知'} · 积压 ${host.backlog} · 窗口内执行 ${host.executions_in_window} 次 · 最后对账 ${formatTime(host.last_report_at)}${gaps}${kinds}`;
    const flags=document.createElement('p');
    flags.textContent=[host.warn?'丢失率超过阈值或存在未知缺口':'丢失率正常',host.silent?`超过 ${result.silence_after_minutes} 分钟无对账上报，采集器疑似已停止`:''].filter(Boolean).join(' · ');
    item.append(head,meta,flags);box.append(item);
  }
}

/* ---------- 归因泳道图 ------------------------------------------------
   把"哪条事件属于哪次调用"画出来，是理解这套归因唯一直观的方式：
   左列是 Intent，右列是 Event，连线是边。没有连线的 Event 就是"留空"——
   平台承认自己不知道它属于谁，而不是硬连一个最近邻。
   ------------------------------------------------------------------- */
const METHOD_STYLE = {
  hook_id: {color: '#34d399', label: 'Hook ID', dash: ''},
  process_tree: {color: '#60a5fa', label: '进程树', dash: ''},
  temporal_feature: {color: '#94a3b8', label: '资源/时间', dash: '4 4'},
};
const LANE_LIMIT = 14;

function svgEl(name, attrs) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', name);
  Object.keys(attrs).forEach(function (key) { node.setAttribute(key, attrs[key]); });
  return node;
}

function svgText(x, y, content, attrs) {
  const node = svgEl('text', Object.assign({x: x, y: y}, attrs || {}));
  node.textContent = content;
  return node;
}

async function renderAttributionLane(executionId) {
  const svg = byId('attributionLane');
  const foot = byId('laneFoot');
  svg.replaceChildren();
  let data;
  try { data = await request('/api/v1/executions/' + encodeURIComponent(executionId) + '/attribution-graph'); }
  catch (error) { if (error instanceof UnauthenticatedError) return; throw error; }

  const intents = (data.intents || []).slice(0, LANE_LIMIT);
  const events = (data.events || []).slice(0, LANE_LIMIT);
  const edges = data.edges || [];
  if (!intents.length) {
    svg.setAttribute('viewBox', '0 0 600 120');
    svg.appendChild(svgText(24, 60, '这次执行没有 Intent 记录', {fill: '#7c8b87', 'font-size': 13}));
    foot.textContent = '';
    return;
  }

  const ROW_I = 54, ROW_E = 46, PAD = 16, BOX_W = 250, GAP = 150;
  const width = PAD + BOX_W + GAP + BOX_W + PAD;
  const rows = Math.max(intents.length, events.length, 3);
  const height = PAD * 2 + rows * Math.max(ROW_I, ROW_E);
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('height', String(height));

  const intentY = {}, eventY = {};
  const xIntents = PAD, xEvents = PAD + BOX_W + GAP;

  // 列标题
  svg.appendChild(svgText(xIntents, PAD - 2, 'INTENT（工具调用）', {'font-size': 10, fill: '#6f7d79', 'letter-spacing': 1}));
  svg.appendChild(svgText(xEvents, PAD - 2, 'EVENT（系统事件）', {'font-size': 10, fill: '#6f7d79', 'letter-spacing': 1}));

  intents.forEach(function (intent, index) {
    const y = PAD + 12 + index * ROW_I;
    intentY[intent.intent_id] = y + 18;
    const box = svgEl('rect', {x: xIntents, y: y, width: BOX_W, height: 38, rx: 8,
      fill: 'rgba(79,209,176,.06)', stroke: 'rgba(79,209,176,.22)'});
    svg.appendChild(box);
    svg.appendChild(svgText(xIntents + 12, y + 16,
      String(intent.tool_name || 'intent').slice(0, 30), {'font-size': 12, fill: '#d5e2de'}));
    svg.appendChild(svgText(xIntents + 12, y + 30,
      String(intent.occurred_at || '').slice(11, 19) + ' · ' + String(intent.decision || '').slice(0, 12),
      {'font-size': 10, fill: '#7c8b87'}));
  });

  events.forEach(function (event, index) {
    const y = PAD + 12 + index * ROW_E;
    eventY[event.event_id] = y + 15;
    const resource = event.resource_host
      ? event.resource_host + (event.resource_port ? ':' + event.resource_port : '')
      : (event.resource_path || '');
    const box = svgEl('rect', {x: xEvents, y: y, width: BOX_W, height: 32, rx: 8,
      fill: 'rgba(255,255,255,.03)', stroke: 'rgba(255,255,255,.1)'});
    svg.appendChild(box);
    svg.appendChild(svgText(xEvents + 12, y + 14,
      String(event.event_type || 'event'), {'font-size': 12, fill: '#c9d6d2'}));
    svg.appendChild(svgText(xEvents + 12, y + 26, String(resource).slice(0, 34),
      {'font-size': 10, fill: '#7c8b87'}));
  });

  edges.forEach(function (edge) {
    const y1 = intentY[edge.intent_id], y2 = eventY[edge.event_id];
    if (y1 === undefined || y2 === undefined) return;
    const style = METHOD_STYLE[edge.method] || {color: '#94a3b8', dash: ''};
    const x1 = xIntents + BOX_W, x2 = xEvents;
    const path = svgEl('path', {
      d: 'M ' + x1 + ' ' + y1 + ' C ' + (x1 + 60) + ' ' + y1 + ', ' + (x2 - 60) + ' ' + y2
         + ', ' + x2 + ' ' + y2,
      fill: 'none', stroke: style.color,
      'stroke-width': edge.selected ? 2.4 : 1.2,
      'stroke-opacity': edge.selected ? 0.9 : 0.45,
    });
    if (style.dash) path.setAttribute('stroke-dasharray', style.dash);
    const tip = svgEl('title', {});
    tip.textContent = edge.method + ' · ' + edge.confidence + ' · ' + Number(edge.score).toFixed(2)
      + (edge.selected ? ' · 当前选择' : ' · 未选择候选');
    path.appendChild(tip);
    svg.appendChild(path);
    if (edge.selected) {
      svg.appendChild(svgEl('circle', {cx: x2, cy: y2, r: 3, fill: style.color}));
    }
  });

  // 图例
  const used = Array.from(new Set(edges.map(function (e) { return e.method; })));
  byId('laneLegend').innerHTML = used.map(function (method) {
    const style = METHOD_STYLE[method] || {color: '#94a3b8', label: method};
    return '<span><b style="background:' + style.color + '"></b>' + style.label + '</span>';
  }).join('');

  const selected = edges.filter(function (e) { return e.selected; }).length;
  const parts = [
    '本次执行 ' + (data.intents || []).length + ' 个 Intent',
    (data.events || []).length + ' 个已归因 Event',
    selected + ' 条选定边',
  ];
  if (data.unattributed_events > 0) {
    parts.push('同期还有 ' + data.unattributed_events + ' 条事件未归因 —— 没有证据时留空，不硬连最近邻');
  }
  if ((data.intents || []).length > LANE_LIMIT) parts.push('仅展示前 ' + LANE_LIMIT + ' 条');
  foot.textContent = parts.join(' · ');
}

/* ---------- 数据流链 ------------------------------------------------
   source（读了敏感文件）→ hop（中转）→ sink（连到外部地址）。
   刻意只在"有 sink"时画链：读了私钥但没有外连，不算外发——这条规则决定
   误报率，也是它敢在 git push 场景下不出声的原因。
   ------------------------------------------------------------------- */
const FLOW_TONE = {medium: '#fbbf24', low: '#94a3b8'};

async function renderDataFlow(executionId) {
  const svg = byId('dataflowChain');
  const foot = byId('dataflowFoot');
  svg.replaceChildren();
  let data;
  try { data = await request('/api/v1/executions/' + encodeURIComponent(executionId) + '/data-flows'); }
  catch (error) { if (error instanceof UnauthenticatedError) return; throw error; }

  const flows = data.flows || [];
  if (!flows.length) {
    svg.setAttribute('viewBox', '0 0 900 90');
    svg.setAttribute('height', '90');
    svg.appendChild(svgText(16, 38, '未发现外发链', {fill: '#c9d6d2', 'font-size': 13}));
    svg.appendChild(svgText(16, 60,
      '读了敏感文件但没有外部连接，或连接目标属于内网/可信域名 —— 按设计不产链。',
      {fill: '#7c8b87', 'font-size': 11}));
    foot.textContent = data.note || '';
    return;
  }

  const BOX_W = 190, BOX_H = 56, GAP = 72, PAD = 16, ROW = 92;
  const maxNodes = Math.max.apply(null, flows.map(function (f) { return f.hops.length + 2; }));
  const width = PAD * 2 + maxNodes * BOX_W + (maxNodes - 1) * GAP;
  const height = PAD * 2 + flows.length * ROW;
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('height', String(height));

  flows.forEach(function (flow, rowIndex) {
    const y = PAD + rowIndex * ROW;
    const nodes = [{kind: 'source', label: flow.source.path, sub: flow.source.tool_name}]
      .concat(flow.hops.map(function (hop) {
        return {kind: 'hop', label: (hop.paths && hop.paths[0]) || '(中转)', sub: hop.tool_name};
      }))
      .concat([{kind: 'sink',
        label: flow.sink.host + (flow.sink.port ? ':' + flow.sink.port : ''),
        sub: '外部连接 · ' + (flow.sink_basis === 'time_window' ? '时间窗匹配' : '精确归属')}]);

    nodes.forEach(function (node, index) {
      const x = PAD + index * (BOX_W + GAP);
      const tone = node.kind === 'source' ? '#f87171'
        : node.kind === 'sink' ? '#c084fc' : '#60a5fa';
      svg.appendChild(svgEl('rect', {x: x, y: y, width: BOX_W, height: BOX_H, rx: 10,
        fill: 'rgba(255,255,255,.03)', stroke: tone, 'stroke-opacity': .45}));
      svg.appendChild(svgEl('rect', {x: x, y: y, width: 3, height: BOX_H, rx: 1.5, fill: tone}));
      svg.appendChild(svgText(x + 12, y + 22,
        String(node.label).slice(0, 26), {'font-size': 12, fill: '#dbe7e3'}));
      svg.appendChild(svgText(x + 12, y + 40,
        String(node.sub || '').slice(0, 30), {'font-size': 10, fill: '#7c8b87'}));
      if (index < nodes.length - 1) {
        const x1 = x + BOX_W, x2 = x + BOX_W + GAP;
        const mid = y + BOX_H / 2;
        svg.appendChild(svgEl('path', {
          d: 'M ' + x1 + ' ' + mid + ' L ' + (x2 - 8) + ' ' + mid,
          stroke: 'rgba(255,255,255,.25)', 'stroke-width': 1.4, fill: 'none'}));
        svg.appendChild(svgEl('path', {
          d: 'M ' + (x2 - 12) + ' ' + (mid - 4) + ' L ' + x2 + ' ' + mid
           + ' L ' + (x2 - 12) + ' ' + (mid + 4),
          stroke: 'rgba(255,255,255,.35)', 'stroke-width': 1.4, fill: 'none'}));
      }
    });

    // 置信度徽标放在链路末端
    const badgeX = PAD + (nodes.length - 1) * (BOX_W + GAP) + BOX_W - 52;
    const tone = FLOW_TONE[flow.confidence] || '#94a3b8';
    svg.appendChild(svgEl('rect', {x: badgeX, y: y + BOX_H + 6, width: 52, height: 16,
      rx: 8, fill: 'rgba(255,255,255,.06)', stroke: tone, 'stroke-opacity': .5}));
    svg.appendChild(svgText(badgeX + 26, y + BOX_H + 17, flow.confidence,
      {'font-size': 10, fill: tone, 'text-anchor': 'middle'}));
  });

  foot.textContent = data.note || '';
}

function shortId(value, keep) {
  const text = String(value || '');
  const limit = keep || 16;
  return text.length > limit + 4 ? text.slice(0, limit) + '…' : text;
}

async function correlateCurrent() {
  const id=byId('runtimeExecution').value;if(!id)return;
  const result=await request(`/api/v1/executions/${encodeURIComponent(id)}/correlate`,{method:'POST',headers:JSON_HEADERS,body:'{}'});
  const edges=await request(`/api/v1/executions/${encodeURIComponent(id)}/attributions`);
  await renderEffectDiff(id);
  await renderAttributionLane(id);
  await renderDataFlow(id);
  const box=byId('attributionCandidates');box.replaceChildren();
  const summary=document.createElement('p');summary.textContent=`受评事件 ${result.subject_count} · 候选 ${result.candidate_count} · 强候选选择 ${result.selected_count} · 无候选 ${result.no_candidate_count} · 有候选但未选定 ${result.ambiguous_count}（同主机事件可能属于其他会话）`;box.append(summary);
  for(const edge of edges.attributions){const line=document.createElement('p');line.textContent=`${edge.event_id} → ${edge.intent_id} · ${edge.method} · ${edge.confidence} · ${edge.selected ? '当前选择，仍须核验证据' : '未选择候选'}`;box.append(line);}
}

/* ---------- 资产中心 ---------- */

async function refreshAssets() {
  const [catalog, executions, ledger, publishers] = await Promise.all([
    request('/api/v1/products'), request('/api/v1/executions?limit=200'),
    request(assetLedgerQuery()), request('/api/v1/publishers'),
  ]);
  state.products = catalog.products;
  state.executions = executions.executions;
  state.ledger = ledger;
  state.publishers = publishers.items || [];
  renderAssetProducts();
  renderAssetHosts();
  renderAssetLedger();
  renderPublishers();
  renderExecutionChoices();
}

function renderPublishers() {
  const tbody = byId('publisherRows');
  if (!tbody) return;
  tbody.replaceChildren();
  const rows = state.publishers || [];
  byId('publisherCount').textContent = `${rows.length} 个发布方`;
  if (!rows.length) {
    addEmptyRow(tbody, 6, '暂未登记发布方公钥。');
    return;
  }
  const govern = canGovern();
  for (const pub of rows) {
    const tr = document.createElement('tr');
    const name = addCell(tr, pub.name);
    const idSmall = document.createElement('small');
    idSmall.textContent = pub.publisher_id;
    name.append(idSmall);
    addCell(tr, pub.algorithm);
    addCell(tr, `${pub.public_key.slice(0, 16)}…`, 'monoId');
    addCell(tr, pub.status === 'active' ? '有效' : '已吊销');
    addCell(tr, formatTime(pub.created_at));
    const op = addCell(tr, '');
    if (pub.status === 'active') {
      const btn = document.createElement('button');
      btn.type = 'button'; btn.className = 'secondaryButton'; btn.textContent = '吊销';
      btn.disabled = !govern;
      btn.addEventListener('click', guarded(async () => {
        btn.disabled = true;
        await request(`/api/v1/publishers/${encodeURIComponent(pub.publisher_id)}/revoke`,
          { method: 'POST', headers: JSON_HEADERS, body: '{}' });
        showNotice(`发布方 ${pub.name} 已吊销`, 'success');
        await refreshAssets();
      }));
      op.append(btn);
    } else {
      op.textContent = formatTime(pub.revoked_at);
    }
    tbody.append(tr);
  }
}

// 筛选串在 URL 上，刷新和分享视图都保留同一批条件。
function assetLedgerQuery() {
  const params = new URLSearchParams();
  const query = byId('assetFilterQuery').value.trim();
  const type = byId('assetFilterType').value;
  const install = byId('assetFilterInstall').value;
  const runtime = byId('assetFilterRuntime').value;
  if (query) params.set('query', query);
  if (type) params.set('asset_type', type);
  if (install) params.set('installation_state', install);
  if (runtime) params.set('runtime_state', runtime);
  params.set('limit', '200');
  return `/api/v1/assets?${params.toString()}`;
}

function renderAssetLedger() {
  const tbody = byId('assetLedgerRows');
  tbody.replaceChildren();
  for (const item of state.ledger.items) {
    const row = document.createElement('tr');
    const name = addCell(row, item.asset.canonical_name);
    const id = document.createElement('small');
    id.textContent = `${item.asset.asset_id}${item.asset.publisher ? ` · ${item.asset.publisher}` : ''}${item.asset.provenance ? ` · ${item.asset.provenance}` : ''}`;
    name.append(id);
    addCell(row, assetTypeLabels[item.asset.asset_type] || item.asset.asset_type);
    addCell(row, item.asset.product || '未指定');
    const copies = addCell(row, item.instances.length ? '' : '未登记副本');
    for (const instance of item.instances) {
      const line = document.createElement('small');
      line.textContent = `${instance.host_id} / ${instance.product_scope}${instance.install_path ? ` · ${instance.install_path}` : ''}`;
      copies.append(line);
    }
    const states = item.instances.length
      ? [['installation_state', installationStateLabels], ['activation_state', activationStateLabels],
         ['runtime_state', runtimeStateLabels]]
      : [];
    for (const [field, labels] of states) {
      // 多个副本可能处于不同状态：一个 pill 会撒谎，直接把不同取值都列出来。
      const values = [...new Set(item.instances.map((instance) => instance[field]))];
      if (values.length === 1) addPillCell(row, values[0], labels);
      else addCell(row, values.map((value) => labels[value] || value).join(' / '));
    }
    if (!states.length) {
      for (let index = 0; index < 3; index += 1) addCell(row, '—');
    }
    const counts = addCell(row, '');
    counts.textContent = item.instances.length
      ? `${item.instances.reduce((sum, i) => sum + i.admission_count, 0)} / ${item.instances.reduce((sum, i) => sum + i.execution_count, 0)}`
      : '—';
    const actions = document.createElement('td');
    actions.className = 'actionCell';
    const trace = document.createElement('button');
    trace.type = 'button';
    trace.className = 'secondaryButton';
    trace.textContent = '追踪';
    trace.addEventListener('click', () => showAssetTrace(item.asset.asset_id));
    actions.append(trace);
    row.append(actions);
    tbody.append(row);
  }
  if (!state.ledger.items.length) {
    addEmptyRow(tbody, 9, '没有符合条件的资产。登记后这里会出现逻辑资产与副本。');
  }
  byId('assetLedgerCount').textContent = `${state.ledger.items.length} 个逻辑资产`;
  const links = byId('assetLedgerLinks');
  links.replaceChildren();
  const intro = document.createElement('span');
  intro.textContent = '关联方式：';
  links.append(intro);
  for (const [key, text] of Object.entries(state.ledger.links || {})) {
    const line = document.createElement('small');
    line.textContent = `${timelineSectionLabels[key] || key}：${text}`;
    links.append(line);
  }
}

async function showAssetTrace(assetId) {
  const trace = await request(`/api/v1/assets/${encodeURIComponent(assetId)}`);
  const box = byId('assetTrace');
  box.replaceChildren();
  const head = document.createElement('article');
  head.className = 'recordItem';
  const title = document.createElement('strong');
  title.textContent = `${trace.asset.canonical_name} · ${trace.asset.asset_id}`;
  const meta = document.createElement('p');
  meta.textContent = `${assetTypeLabels[trace.asset.asset_type] || trace.asset.asset_type} · 产品 ${trace.asset.product || '未指定'} · 发布方 ${trace.asset.publisher || '未登记'}`;
  head.append(title, meta);
  box.append(head);

  const sections = [
    ['内容版本', trace.releases, (row) => `${row.version} · ${row.content_hash.slice(0, 16)}… · 签名${row.signature_verified ? `已验证（Ed25519${row.publisher_id ? ` · ${row.publisher_id}` : ''}）` : '未验证'}`],
    ['副本与三态', trace.instances, (row) => `${row.host_id} / ${row.product_scope} · 安装 ${installationStateLabels[row.installation_state] || row.installation_state} · 启用 ${activationStateLabels[row.activation_state] || row.activation_state} · 运行 ${runtimeStateLabels[row.runtime_state] || row.runtime_state} · 准入 ${row.admission_count} 次 · 执行 ${row.execution_count} 次`],
    ['准入事务', trace.admissions, (row) => `${row.transaction_id} · ${admissionStateLabels[row.state] || row.state} · 声明 ${row.content_hash.slice(0, 16)}… · 实测 ${row.observed_content_hash ? `${row.observed_content_hash.slice(0, 16)}…` : '未测量'}`],
    ['执行记录', trace.executions, (row) => `${row.execution_id} · ${row.product} ${row.product_version} · ${row.host_id} · ${row.outcome}`],
    ['发现项', trace.findings, (row) => `${row.finding_id} · ${row.title} · 严重级别 ${severityLabels[row.severity] || row.severity} · 关联人 ${row.linked_by || '未显式关联'}${row.link_note ? ` · ${row.link_note}` : ''}`],
    ['策略决定', trace.policy_decisions, (row) => `${row.decision_id} · ${row.subject_kind || ''} ${row.subject_id} · 动作 ${actionLabels[row.action] || row.action} · 策略 ${row.policy_version}`],
    ['Incident', trace.incidents, (row) => `${row.incident_id} · ${row.title} · ${incidentStatusLabels[row.status] || row.status} · 证据 ${row.evidence || '无'}`],
  ];
  for (const [name, rows, describe] of sections) {
    const article = document.createElement('article');
    article.className = 'recordItem';
    const label = document.createElement('strong');
    label.textContent = `${name}（${rows.length}）`;
    article.append(label);
    if (!rows.length) {
      const empty = document.createElement('p');
      empty.textContent = '暂无记录。';
      article.append(empty);
    }
    for (const row of rows.slice(0, 20)) {
      const line = document.createElement('p');
      line.textContent = describe(row);
      article.append(line);
    }
    box.append(article);
  }
  const links = document.createElement('article');
  links.className = 'recordItem';
  const linksTitle = document.createElement('strong');
  linksTitle.textContent = '关联方式';
  links.append(linksTitle);
  for (const [key, text] of Object.entries(trace.links || {})) {
    const line = document.createElement('p');
    line.textContent = `${timelineSectionLabels[key] || key}：${text}`;
    links.append(line);
  }
  box.append(links);
  byId('assetTrace').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

byId('assetFilterForm').addEventListener('submit', guarded(async (event) => {
  event.preventDefault();
  await refreshAssets();
}));

byId('assetRegisterForm').addEventListener('submit', guarded(async (event) => {
  event.preventDefault();
  const button = byId('assetRegisterSubmit');
  button.disabled = true;
  try {
    const asset = await request('/api/v1/assets', {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({
        asset_type: byId('assetType').value,
        canonical_name: byId('assetName').value.trim(),
        product: byId('assetProduct').value.trim() || undefined,
        publisher: byId('assetPublisher').value.trim() || undefined,
      }),
    });
    const instance = await request('/api/v1/asset-instances', {
      method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({
        asset_id: asset.asset.asset_id,
        host_id: byId('assetHost').value.trim(),
        product_scope: byId('assetScope').value.trim(),
        install_path: byId('assetInstallPath').value.trim() || undefined,
      }),
    });
    const version = byId('assetVersion').value.trim();
    const hash = byId('assetHash').value.trim();
    const publisherId = byId('assetPublisherId') ? byId('assetPublisherId').value.trim() : '';
    const signature = byId('assetSignature') ? byId('assetSignature').value.trim() : '';
    if (version && hash) {
      const releaseBody = { asset_id: asset.asset.asset_id, version, content_hash: hash };
      if (publisherId) releaseBody.publisher_id = publisherId;
      if (signature) releaseBody.signature = signature;
      await request('/api/v1/asset-releases', {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(releaseBody),
      });
    }
    const notes = [`资产 ${asset.asset.asset_id}${asset.duplicate ? '（已存在，返回原记录）' : ''}`,
      `副本 ${instance.instance.instance_id}${instance.duplicate ? '（已存在）' : ''}`];
    if (version && hash) notes.push(`内容版本 ${version}`);
    showNotice(`登记完成：${notes.join(' · ')}`, 'success');
    await refreshAssets();
  } catch (error) {
    showNotice(error.message, 'error');
  } finally {
    button.disabled = !canGovern();
  }
}));

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
    // 原来每个事件一行，一格能堆 6 行，整张表读起来像文档。压成一行能力摘要，
    // 逐事件的明细放 title——需要的人 hover 就有，不需要的人不必被它淹没。
    const uniqueCapabilities = Array.from(new Set(
      product.events.flatMap((event) => event.capabilities))).map(
      (name) => capabilityLabels[name] || name);
    const summary = document.createElement('small');
    summary.className = 'cellSummary';
    summary.textContent = uniqueCapabilities.length
      ? `能力 ${uniqueCapabilities.join(' / ')}` : '仅观测';
    summary.title = product.events.map((event) => {
      const capabilities = event.capabilities.map((name) => capabilityLabels[name] || name).join('/');
      return `${hookEventLabels[event.hook_event_type] || event.hook_event_type}: ${capabilities}${event.pre_execution ? '（执行前）' : ''}`;
    }).join('\n');
    observation.append(summary);
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
    head.textContent = `${assessment.assessment_id} · 固有 ${assessment.intrinsic_risk} / 运行 ${assessment.runtime_risk} / 暴露 ${assessment.exposure_risk} · 置信度 ${confidenceLabels[assessment.confidence] || assessment.confidence}`;
    const meta = document.createElement('p');
    meta.textContent = `资产 ${assessment.asset_id || '未关联'} · 执行 ${assessment.execution_id || '未关联'} · 证据 ${assessment.evidence_refs.length} 条 · 规则 ${assessment.rule_version} · ${formatTime(assessment.created_at)}`;
    item.append(head, meta);
    // 逐维度依据：总分只说明"是多少"，这一层才说明"凭什么是这个值和这个置信度"。
    // 置信度 unknown 的维度必须显式标注"未测量"，否则 0 分会被读成"没有风险"。
    for (const dimension of assessment.dimensions || []) {
      const name = riskDimensionLabels[dimension.dimension] || dimension.dimension;
      const line = document.createElement('p');
      line.className = 'fieldHint';
      line.textContent = `${name} ${dimension.score} 分 · 置信度 ${confidenceLabels[dimension.confidence] || dimension.confidence} · 规则 ${dimension.rule_version}`
        + (dimension.confidence === 'unknown' ? ' · 该维度未测量，0 分表示没有数据，不等于没有风险' : '');
      const basis = document.createElement('p');
      basis.textContent = dimension.basis;
      item.append(line, basis);
    }
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
    showNotice(`已创建风险评估 ${result.assessment_id}：固有 ${result.intrinsic_risk} / 运行 ${result.runtime_risk} / 暴露 ${result.exposure_risk} · 总体置信度 ${confidenceLabels[result.confidence] || result.confidence}（等于最弱的已测量维度）`, 'success');
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
    summary.textContent = `${shortId(incident.incident_id)}${incident.summary ? ` · ${incident.summary}` : ''}`;
    summary.title = incident.incident_id;
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
if (byId('runtimeCorrelateBtn')) {
  byId('runtimeCorrelateBtn').addEventListener('click', guarded(correlateCurrent));
}
if (byId('publisherForm')) {
  byId('publisherForm').addEventListener('submit', guarded(async (event) => {
    event.preventDefault();
    const btn = byId('publisherSubmit');
    btn.disabled = true;
    try {
      const res = await request('/api/v1/publishers', {
        method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({
          name: byId('publisherName').value.trim(),
          public_key: byId('publisherKey').value.trim(),
        }),
      });
      showNotice(`发布方 ${res.publisher.name} (${res.publisher.publisher_id}) 已登记`, 'success');
      byId('publisherName').value = '';
      byId('publisherKey').value = '';
      await refreshAssets();
    } finally {
      btn.disabled = !canGovern();
    }
  }));
}

let approvalRefreshBusy = false;
setInterval(async () => {
  if (!state.user || document.hidden || location.hash !== '#approvals' || approvalRefreshBusy) return;
  approvalRefreshBusy = true;
  try { await refreshApprovals(); }
  catch (error) { if (!(error instanceof UnauthenticatedError)) showNotice(error.message, 'error'); }
  finally { approvalRefreshBusy = false; }
}, 2000);


/* ---- 视图路由 ----------------------------------------------------------
   之前 15 个 section 全部常驻显示，11 个导航项只是锚点，整页是一张长条，
   用户要一直滚才能看完，视觉上也没有"在某个功能里"的感觉。这里按 hash
   切换，一次只显示当前视图。
   ---------------------------------------------------------------------- */
const DECISION_TONE = {block: '--state-block', confirm: '--state-confirm',
                      audit: '--state-audit', allow: '--state-allow'};
const DECISION_LABEL = {block: '阻断', confirm: '待确认', audit: '仅记录', allow: '放行'};

async function renderOverview() {
  let data;
  try { data = await request('/api/v1/overview'); }
  catch (error) { if (error instanceof UnauthenticatedError) return; throw error; }

  const total = data.runtime_events || 0;
  const attributed = data.attributed_edges || 0;
  const pct = total ? (attributed / total) * 100 : 0;
  // 0.72% 画成条形只剩 2px，肉眼等于没有；给一个最小可见刻度并在旁边标明
  // "刻度已放大"，避免读者把视觉比例当成真实比例。
  byId('attrBar').style.width = Math.max(pct, 2.2) + '%';
  byId('attrBig').textContent = attributed.toLocaleString();
  byId('attrPct').textContent = '条边 / ' + total.toLocaleString() + ' 事件 · ' + pct.toFixed(2)
    + '%（条长已放大到可辨识）';
  byId('attrHint').textContent = (data.executions || 0) + ' 次执行';
  byId('attrFoot').textContent = attributed.toLocaleString() + ' / ' + total.toLocaleString()
    + ' 条事件已归因（' + pct.toFixed(2) + '%）。未归因不等于有风险——没有证据时留空是设计选择，不是漏。';

  const bar = byId('decBar'), legend = byId('decLegend');
  const counts = data.policy_decisions || {};
  const order = ['block', 'confirm', 'audit', 'allow'];
  const sum = order.reduce(function (acc, key) { return acc + (counts[key] || 0); }, 0);
  bar.innerHTML = ''; legend.innerHTML = '';
  if (!sum) {
    bar.innerHTML = '<i style="width:100%;background:rgba(255,255,255,.06)"></i>';
    legend.innerHTML = '<span class="hint">还没有策略决策记录</span>';
  } else {
    order.forEach(function (key) {
      const n = counts[key] || 0;
      if (!n) return;
      const seg = document.createElement('i');
      seg.style.width = (n / sum * 100) + '%';
      seg.style.background = 'var(' + DECISION_TONE[key] + ')';
      seg.title = DECISION_LABEL[key] + ' ' + n;
      bar.appendChild(seg);
      const item = document.createElement('span');
      item.innerHTML = '<b style="background:var(' + DECISION_TONE[key] + ')"></b>'
        + DECISION_LABEL[key] + ' ' + n;
      legend.appendChild(item);
    });
  }
  byId('decHint').textContent = sum + ' 条决策';

  const gov = [
    ['资产', String(data.assets || 0)],
    ['准入通过', String((data.admissions || {}).verified || 0)],
    ['未关闭工单', String(data.incidents_open || 0)],
    ['执行记录', String(data.executions || 0)],
  ];
  byId('govRows').innerHTML = gov.map(function (row) {
    const tone = row[0] === '未关闭工单' && Number(row[1]) > 0 ? 'warn' : '';
    return '<div class="evalRow"><span>' + row[0] + '</span><strong class="' + tone + '">'
      + row[1] + '</strong></div>';
  }).join('');

  const ev = data.evaluation || {};
  const pctText = (v) => (v == null ? '未测量' : Math.round(v * 100) + '%');
  const ratioText = (a, b) => (a == null || b == null ? '未测量' : a + ' / ' + b);
  const rows = [
    ['副作用差分捕获 (A/B)', ratioText(ev.effect_diff_undeclared_tp, ev.effect_diff_scenarios ? Math.round(ev.effect_diff_scenarios / 2) : null), ev.effect_diff_undeclared_tp != null ? 'ok' : 'warn'],
    ['差分对比（规则基线 → ASGP）', ev.effect_diff_asgp_capture_rate == null ? '未测量' : pctText(ev.effect_diff_baseline_capture_rate) + ' → ' + pctText(ev.effect_diff_asgp_capture_rate), 'ok'],
    ['数据流链检出 / 误报', ratioText(ev.dataflow_detected, ev.dataflow_sequences) + ' · FP ' + (ev.dataflow_false_positive ?? '未测量'), 'ok'],
    ['归因精度 / 召回', pctText(ev.attribution_precision) + ' / ' + pctText(ev.attribution_recall), 'warn'],
  ];
  byId('evalRows').innerHTML = rows.map(function (row) {
    return '<div class="evalRow"><span>' + row[0] + '</span><strong class="' + row[2] + '">'
      + row[1] + '</strong></div>';
  }).join('');
}

const VIEW_ROUTES = ['overview','assets','detections','scan','engines','runtime',
                     'hostRuntime','approvals','policy','admissions','incidents'];

function applyRoute() {
  const requested = (location.hash || '#overview').replace('#', '');
  const key = VIEW_ROUTES.includes(requested) ? requested : 'overview';
  document.querySelectorAll('section[data-view]').forEach(function (node) {
    node.hidden = node.dataset.view !== key;
  });
  document.querySelectorAll('.navItem').forEach(function (link) {
    link.classList.toggle('active', link.getAttribute('href') === '#' + key);
  });
  if (!location.hash) location.replace('#overview');
  window.scrollTo(0, 0);
  if (key === 'overview') { renderOverview().catch(function () {}); }
}

window.addEventListener('hashchange', applyRoute);
applyRoute();
