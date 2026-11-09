// Pure view logic for the four agent-security pages (asset ledger, session
// list, behavior timeline, policy management). No React, no fetch: every
// function takes API payloads and returns render-ready rows so the logic can
// be covered by node:test (see agentSecurityModel.test.mjs).

const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
const RISK_SEVERITIES = new Set(["medium", "high", "critical"]);
const SENSITIVE_PATH_RULES = new Set(["S08", "R001", "R002"]);

export function formatClock(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return [date.getHours(), date.getMinutes(), date.getSeconds()]
    .map((part) => String(part).padStart(2, "0"))
    .join(":");
}

export function formatDateTime(value) {
  if (!value) {
    return "-";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  const day = [date.getFullYear(), date.getMonth() + 1, date.getDate()]
    .map((part) => String(part).padStart(2, "0"))
    .join("-");
  return `${day} ${formatClock(value)}`;
}

export function formatDuration(from, to) {
  if (!from) {
    return "-";
  }
  const start = new Date(from).getTime();
  const end = to ? new Date(to).getTime() : Date.now();
  if (Number.isNaN(start) || Number.isNaN(end) || end < start) {
    return "-";
  }
  const seconds = Math.floor((end - start) / 1000);
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes}m ${String(seconds % 60).padStart(2, "0")}s`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${String(minutes % 60).padStart(2, "0")}m`;
}

export function severityTone(severity) {
  if (severity === "critical" || severity === "high") {
    return "danger";
  }
  if (severity === "medium") {
    return "warning";
  }
  return "info";
}

export function actionTone(action) {
  if (action === "block") {
    return "danger";
  }
  if (action === "ask" || action === "alert") {
    return "warning";
  }
  if (action === "allow") {
    return "success";
  }
  return "info";
}

export function isRiskSeverity(severity) {
  return RISK_SEVERITIES.has(severity);
}

function shortPath(path) {
  const text = String(path ?? "");
  if (!text) {
    return "-";
  }
  const home = text.replace(/^\/home\/[^/]+/, "~").replace(/^\/Users\/[^/]+/, "~")
    .replace(/^\/root/, "~");
  return home.length > 48 ? `…${home.slice(-47)}` : home;
}

function latestBy(items, key) {
  return items.reduce((best, item) => {
    if (!best || String(item[key] ?? "") > String(best[key] ?? "")) {
      return item;
    }
    return best;
  }, null);
}

function normalizeAgentName(value) {
  return String(value ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function buildAgentAssetRows({ assets = [], sessions = [], scans = [] } = {}) {
  const kindOrder = { agent: 0, mcp: 1, skill: 2, hook: 3, deps: 4 };
  const rows = assets.map((asset) => {
    const matchingSessions = sessions.filter((item) =>
      normalizeAgentName(item.agent_name) === normalizeAgentName(asset.name)
        && (!asset.host || !item.host || item.host === asset.host));
    const session = latestBy(matchingSessions, "started_at");
    const latestScan = latestBy(
      scans.filter((scan) => (asset.instance_id && scan.instance_id
        ? scan.instance_id === asset.instance_id
        : scan.target_path === asset.path)),
      "ts",
    );
    let policyStatus = asset.kind === "agent"
      && asset.source === "managed-inventory" ? "discovered" : "unregistered";
    if (asset.registered && policyStatus !== "discovered") {
      policyStatus = "enforcing";
      if (latestScan?.verdict === "block") {
        policyStatus = "violation";
      } else if (latestScan?.verdict === "alert") {
        policyStatus = "warning";
      }
    }
    return {
      assetId: asset.asset_id,
      name: asset.name,
      kind: asset.kind,
      version: asset.version || "-",
      host: asset.host || "-",
      user: asset.owner || session?.user || "-",
      installedAt: asset.first_seen || "",
      lastRunAt: latestBy(
        matchingSessions,
        "started_at",
      )?.last_ts || asset.last_seen || "",
      registered: Boolean(asset.registered),
      logicalId: asset.logical_id || "",
      instanceId: asset.instance_id || asset.asset_id || "",
      contentHash: asset.content_hash || asset.sha256 || "",
      carrier: asset.carrier || "unknown",
      state: asset.state || "discovered",
      policyStatus,
      provenance: asset.provenance || "unknown",
      riskAssessment: latestScan?.risk_assessment
        || asset.risk_assessment || "unassessed",
      riskScore: Number(latestScan?.risk_score ?? asset.risk_score ?? 0),
      riskBreakdown: Array.isArray(latestScan?.risk_breakdown)
        ? latestScan.risk_breakdown : (Array.isArray(asset.risk_breakdown)
          ? asset.risk_breakdown : []),
      findingRuleIds: Array.isArray(latestScan?.findings)
        ? [...new Set(latestScan.findings.map((finding) => finding.rule_id).filter(Boolean))]
        : (Array.isArray(asset.finding_rule_ids) ? asset.finding_rule_ids : []),
      assessmentReason: latestScan?.assessment_reason || "",
      sha256: asset.sha256 || "",
      path: asset.path || "",
    };
  });
  return rows.sort((left, right) => {
    const kindDelta = (kindOrder[left.kind] ?? 9) - (kindOrder[right.kind] ?? 9);
    if (kindDelta !== 0) {
      return kindDelta;
    }
    return String(right.lastRunAt).localeCompare(String(left.lastRunAt));
  });
}

export function buildSessionRows(sessions = []) {
  return sessions.map((session) => ({
    sessionId: session.session_id,
    host: session.host || "-",
    agentName: session.agent_name || "-",
    agentVersion: session.agent_version || "-",
    user: session.user || "-",
    cwd: session.cwd || "-",
    startedAt: session.started_at || session.first_ts || "",
    endedAt: session.ended_at || "",
    duration: formatDuration(session.started_at || session.first_ts,
                             session.ended_at || null),
    toolCalls: Number(session.tool_calls ?? 0),
    riskEvents: Number(session.risk_events ?? 0),
    eventCount: Number(session.event_count ?? 0),
    maxSeverity: session.max_severity || "info",
    status: session.ended_at ? "ended" : "running",
    tone: session.ended_at ? "info" : "success",
  }));
}

function mapEvent(event, index) {
  const kind = event.event_type;
  const action = event.action;
  let labelKey = "agentsec.timeline.event";
  const params = {};
  if (kind === "process_exec") {
    labelKey = "agentsec.timeline.processStart";
    params.tool = event.tool_name || "-";
  } else if (kind === "file_access") {
    const sensitive = Array.isArray(event.rule_ids)
      && event.rule_ids.some((ruleId) => SENSITIVE_PATH_RULES.has(ruleId));
    labelKey = (action === "block" || sensitive)
      ? "agentsec.timeline.fileBlocked" : "agentsec.timeline.fileRead";
    params.path = shortPath(event.target_path);
  } else if (kind === "net_connect") {
    labelKey = "agentsec.timeline.netConnect";
    params.domain = event.dst_domain || "-";
    if (event.dst_port) {
      params.port = String(event.dst_port);
    }
  } else if (kind === "tool_call") {
    if (action === "block") {
      labelKey = "agentsec.timeline.blocked";
      params.tool = event.tool_name || "-";
    } else if (action === "ask") {
      labelKey = "agentsec.timeline.ask";
      params.tool = event.tool_name || "-";
    } else if (event.tool_server) {
      labelKey = "agentsec.timeline.mcpCall";
      params.server = event.tool_server;
    } else {
      labelKey = "agentsec.timeline.toolCall";
      params.tool = event.tool_name || "-";
    }
  } else if (kind === "config_change") {
    labelKey = "agentsec.timeline.configChange";
  } else if (kind === "scan_finding") {
    labelKey = "agentsec.timeline.scanFinding";
  } else if (kind === "heartbeat") {
    labelKey = "agentsec.timeline.heartbeat";
  }
  return {
    id: `${event.ts}-${index}`,
    ts: event.ts,
    clock: formatClock(event.ts),
    kind,
    action,
    labelKey,
    labelParams: params,
    severity: event.severity || "info",
    ruleIds: Array.isArray(event.rule_ids) ? event.rule_ids : [],
    tiVerdict: event.ti_verdict || "unknown",
    tiProvider: event.ti_provider || "",
    tiConfidence: Number(event.ti_confidence ?? 0),
    tone: severityTone(event.severity),
    actionTone: actionTone(action),
    isRisk: isRiskSeverity(event.severity) || action === "block" || action === "ask",
    toolName: event.tool_name || "",
    toolServer: event.tool_server || "",
    target: event.target_path || "",
    domain: event.dst_domain || "",
    port: event.dst_port ?? null,
    pid: event.agent_pid ?? null,
    detail: event.evidence?.reason || "",
  };
}

export function buildTimeline({ session = null, timeline = [] } = {}) {
  const entries = [];
  if (session?.started_at) {
    entries.push({
      id: `session-start-${session.session_id}`,
      ts: session.started_at,
      clock: formatClock(session.started_at),
      kind: "session_start",
      action: "allow",
      labelKey: "agentsec.timeline.agentStart",
      labelParams: { agent: session.agent_name || "Agent" },
      severity: "info",
      ruleIds: [],
      tone: "success",
      actionTone: "success",
      isRisk: false,
      toolName: "",
      toolServer: "",
      target: "",
      domain: "",
      port: null,
      pid: null,
      detail: session.cwd || "",
    });
  }
  timeline.forEach((event, index) => entries.push(mapEvent(event, index)));
  if (session?.ended_at) {
    entries.push({
      id: `session-end-${session.session_id}`,
      ts: session.ended_at,
      clock: formatClock(session.ended_at),
      kind: "session_end",
      action: "allow",
      labelKey: "agentsec.timeline.agentEnd",
      labelParams: { agent: session.agent_name || "Agent" },
      severity: "info",
      ruleIds: [],
      tone: "info",
      actionTone: "info",
      isRisk: false,
      toolName: "",
      toolServer: "",
      target: "",
      domain: "",
      port: null,
      pid: null,
      detail: "",
    });
  }
  return entries.sort((left, right) => String(left.ts).localeCompare(String(right.ts)));
}

export function buildTimelineFromEvents(events = []) {
  return [...events]
    .sort((left, right) => String(left.ts).localeCompare(String(right.ts)))
    .map((event, index) => mapEvent(event, index));
}

export function filterTimeline(entries, { severity = "all", kind = "all" } = {}) {
  return entries.filter((entry) => {
    if (kind !== "all" && entry.kind !== kind) {
      return false;
    }
    if (severity === "all") {
      return true;
    }
    if (severity === "risk") {
      return entry.isRisk;
    }
    return entry.severity === severity;
  });
}

const POLICY_GROUPS = [
  { id: "file", titleKey: "agentsec.policy.fileAccess", kinds: ["path"] },
  { id: "network", titleKey: "agentsec.policy.networkAccess", kinds: ["network", "host"] },
  { id: "mcp", titleKey: "agentsec.policy.mcpWhitelist", kinds: ["mcp"] },
  { id: "tool", titleKey: "agentsec.policy.toolPermissions", kinds: ["tool"] },
  { id: "command", titleKey: "agentsec.policy.dangerousCommands", kinds: ["command"] },
];

export function buildPolicyGroups(policies = []) {
  return POLICY_GROUPS.map((group) => ({
    id: group.id,
    titleKey: group.titleKey,
    rows: policies
      .filter((policy) => group.kinds.includes(policy.kind))
      .map((policy) => ({
        policyId: policy.policy_id,
        kind: policy.kind,
        name: policy.name || policy.policy_id,
        pattern: policy.pattern || "",
        severity: policy.severity,
        action: policy.action,
        enabled: Boolean(policy.enabled),
        updatedAt: policy.updated_at || "",
        note: policy.note || "",
      })),
  }));
}

export function buildApprovalRows({ pending = [], history = [] } = {}) {
  return {
    pending: pending.map((event) => ({
      eventId: event.event_id,
      ts: event.ts,
      clock: formatClock(event.ts),
      host: event.host || "-",
      sessionId: event.session_id || "-",
      toolName: event.tool_name || "-",
      target: event.target_path || event.dst_domain || "-",
      ruleIds: Array.isArray(event.rule_ids) ? event.rule_ids : [],
      severity: event.severity || "medium",
      tone: severityTone(event.severity),
    })),
    history: history.map((event) => {
      const decision = event.evidence?.decision || "";
      return {
        eventId: event.event_id,
        ts: event.ts,
        clock: formatClock(event.ts),
        decision,
        decisionKey: decision === "approve" ? "agentsec.policy.approvals.approved"
          : decision === "reject" ? "agentsec.policy.approvals.rejected"
            : "agentsec.policy.approvals.changed",
        target: event.evidence?.policy_id || event.target_path || "-",
        note: event.evidence?.note || "",
        tone: decision === "approve" ? "success" : decision === "reject" ? "danger" : "info",
      };
    }),
  };
}

export function summarizeAgentSecurity({ stats = null, sessions = [] } = {}) {
  const byAction = stats?.by_action ?? {};
  return {
    eventsTotal: Number(stats?.events_total ?? 0),
    sessions: Number(stats?.sessions ?? sessions.length ?? 0),
    runningSessions: sessions.filter((session) => !session.ended_at).length,
    riskEvents: sessions.reduce((sum, session) => sum + Number(session.risk_events ?? 0), 0),
    blocked: Number(byAction.block ?? 0),
    asked: Number(byAction.ask ?? 0),
    pendingApprovals: Number(stats?.pending_approvals ?? 0),
    assets: Number(stats?.assets ?? 0),
    rulesTotal: Number(stats?.rules_total ?? 0),
    runtimeRules: Number(stats?.runtime_rules ?? 0),
  };
}
