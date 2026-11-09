import assert from "node:assert/strict";
import test from "node:test";

import {
  actionTone,
  buildAgentAssetRows,
  buildApprovalRows,
  buildPolicyGroups,
  buildSessionRows,
  buildTimeline,
  buildTimelineFromEvents,
  filterTimeline,
  formatClock,
  formatDateTime,
  formatDuration,
  severityTone,
  summarizeAgentSecurity,
} from "./agentSecurityModel.js";

const assets = [
  {
    asset_id: "asset-aaa", kind: "agent", name: "claude-code", version: "1.2.3",
    path: "/usr/local/bin/claude", sha256: "a".repeat(64), host: "d2-dev",
    registered: true, first_seen: "2026-11-01T09:00:00+00:00",
    last_seen: "2026-11-06T20:00:00+00:00",
  },
  {
    asset_id: "asset-bbb", kind: "mcp", name: "evil-skill", version: "",
    path: "/tmp/evil", sha256: "b".repeat(64), host: "d2-dev",
    registered: false, first_seen: "2026-11-06T19:00:00+00:00",
    last_seen: "2026-11-06T19:00:00+00:00",
  },
];

const sessions = [
  {
    session_id: "s-1", host: "d2-dev", agent_name: "claude-code",
    agent_version: "1.2.3", user: "alice", cwd: "/home/alice/project",
    started_at: "2026-11-06T20:00:01+00:00", ended_at: "",
    event_count: 5, tool_calls: 3, risk_events: 2, max_severity: "high",
  },
  {
    session_id: "s-2", host: "d1-win", agent_name: "codex",
    agent_version: "0.9", user: "bob", cwd: "C:\\work",
    started_at: "2026-11-06T18:00:00+00:00",
    ended_at: "2026-11-06T18:30:00+00:00",
    event_count: 2, tool_calls: 1, risk_events: 0, max_severity: "info",
  },
];

test("formats clock, datetime and durations", () => {
  assert.equal(formatClock("2026-11-06T20:00:01+00:00").length, 8);
  assert.equal(formatClock(""), "-");
  assert.equal(formatDateTime("").length, 1);
  assert.match(formatDuration("2026-11-06T20:00:00+00:00",
                              "2026-11-06T20:00:45+00:00"), /^45s$/);
  assert.match(formatDuration("2026-11-06T20:00:00+00:00",
                              "2026-11-06T20:12:05+00:00"), /^12m 05s$/);
  assert.match(formatDuration("2026-11-06T20:00:00+00:00",
                              "2026-11-06T21:03:00+00:00"), /^1h 03m$/);
  assert.equal(formatDuration("", null), "-");
});

test("maps severities and actions to display tones", () => {
  assert.equal(severityTone("critical"), "danger");
  assert.equal(severityTone("high"), "danger");
  assert.equal(severityTone("medium"), "warning");
  assert.equal(severityTone("info"), "info");
  assert.equal(actionTone("block"), "danger");
  assert.equal(actionTone("ask"), "warning");
  assert.equal(actionTone("allow"), "success");
  assert.equal(actionTone("audit"), "info");
});

test("builds agent asset rows with employee, device and policy status", () => {
  const rows = buildAgentAssetRows({ assets, sessions, scans: [] });
  const agent = rows.find((row) => row.kind === "agent");
  assert.equal(agent.name, "claude-code");
  assert.equal(agent.user, "alice");
  assert.equal(agent.host, "d2-dev");
  assert.equal(agent.version, "1.2.3");
  assert.equal(agent.policyStatus, "enforcing");
  const unregistered = rows.find((row) => row.name === "evil-skill");
  assert.equal(unregistered.policyStatus, "unregistered");
  // agents sort before other kinds
  assert.equal(rows[0].kind, "agent");
});

test("asset policy status escalates from scan verdicts", () => {
  const rows = buildAgentAssetRows({
    assets: [assets[0]],
    sessions: [],
    scans: [{ target_path: "/usr/local/bin/claude", target_name: "claude-code",
              verdict: "block", ts: "2026-11-06T21:00:00+00:00" }],
  });
  assert.equal(rows[0].policyStatus, "violation");
});

test("managed remote inventory keeps owner and does not claim enforcement", () => {
  const [row] = buildAgentAssetRows({
    assets: [{ ...assets[0], owner: "agentsec-lab", host: "agentsec-test-01",
               source: "managed-inventory", registered: false }],
    sessions: [],
    scans: [],
  });
  assert.equal(row.host, "agentsec-test-01");
  assert.equal(row.user, "agentsec-lab");
  assert.equal(row.policyStatus, "discovered");
});

test("builds session rows with counts and duration", () => {
  const rows = buildSessionRows(sessions);
  assert.equal(rows.length, 2);
  const running = rows.find((row) => row.sessionId === "s-1");
  assert.equal(running.status, "running");
  assert.equal(running.toolCalls, 3);
  assert.equal(running.riskEvents, 2);
  assert.equal(running.maxSeverity, "high");
  const ended = rows.find((row) => row.sessionId === "s-2");
  assert.equal(ended.status, "ended");
  assert.match(ended.duration, /^30m 00s$/);
});

test("builds a session timeline with a synthetic start entry", () => {
  const entries = buildTimeline({
    session: sessions[0],
    timeline: [
      { ts: "2026-11-06T20:00:03+00:00", event_type: "file_access",
        action: "audit", severity: "info", rule_ids: [],
        target_path: "/home/alice/project/config.yaml" },
      { ts: "2026-11-06T20:00:05+00:00", event_type: "tool_call",
        action: "allow", severity: "info", rule_ids: [],
        tool_name: "read_file", tool_server: "filesystem" },
      { ts: "2026-11-06T20:00:10+00:00", event_type: "tool_call",
        action: "block", severity: "high", rule_ids: ["R001"],
        tool_name: "Read", evidence: { reason: "sensitive path" } },
      { ts: "2026-11-06T20:00:12+00:00", event_type: "net_connect",
        action: "audit", severity: "info", rule_ids: [],
        dst_domain: "198.51.100.7", dst_port: 443 },
    ],
  });
  assert.equal(entries[0].labelKey, "agentsec.timeline.agentStart");
  assert.equal(entries[0].clock.length, 8);
  assert.equal(entries[1].labelKey, "agentsec.timeline.fileRead");
  assert.equal(entries[1].labelParams.path, "~/project/config.yaml");

  const sensitive = buildTimelineFromEvents([
    { ts: "2026-11-06T20:00:10+00:00", event_type: "file_access",
      action: "alert", severity: "critical", rule_ids: ["S08", "R001"],
      target_path: "/root/.ssh/id_rsa" },
  ]);
  assert.equal(sensitive[0].labelKey, "agentsec.timeline.fileBlocked");
  assert.equal(sensitive[0].labelParams.path, "~/.ssh/id_rsa");
  assert.equal(entries[2].labelKey, "agentsec.timeline.mcpCall");
  assert.equal(entries[2].labelParams.server, "filesystem");
  const blocked = entries[3];
  assert.equal(blocked.labelKey, "agentsec.timeline.blocked");
  assert.equal(blocked.tone, "danger");
  assert.ok(blocked.isRisk);
  assert.deepEqual(blocked.ruleIds, ["R001"]);
  assert.equal(entries[4].labelKey, "agentsec.timeline.netConnect");
  assert.equal(entries[4].labelParams.domain, "198.51.100.7");
});

test("timeline sorts by timestamp and appends session end", () => {
  const entries = buildTimeline({
    session: { session_id: "s-3", started_at: "2026-11-06T20:00:01+00:00",
               ended_at: "2026-11-06T20:05:00+00:00", agent_name: "claude" },
    timeline: [
      { ts: "2026-11-06T20:00:04+00:00", event_type: "process_exec",
        action: "alert", severity: "medium", rule_ids: ["R003"],
        tool_name: "ssh" },
      { ts: "2026-11-06T20:00:02+00:00", event_type: "file_access",
        action: "audit", severity: "info", rule_ids: [], target_path: "/tmp/x" },
    ],
  });
  assert.equal(entries.length, 4);
  assert.deepEqual(entries.map((entry) => entry.kind),
                   ["session_start", "file_access", "process_exec", "session_end"]);
  assert.equal(entries[2].labelKey, "agentsec.timeline.processStart");
  assert.equal(entries[2].labelParams.tool, "ssh");
});

test("builds a global timeline from events without session bookends", () => {
  const entries = buildTimelineFromEvents([
    { ts: "2026-11-06T20:00:02+00:00", event_type: "heartbeat", action: "audit",
      severity: "info", rule_ids: [] },
    { ts: "2026-11-06T20:00:01+00:00", event_type: "scan_finding",
      action: "alert", severity: "high", rule_ids: ["S01"] },
  ]);
  assert.equal(entries.length, 2);
  assert.equal(entries[0].kind, "scan_finding");
  assert.equal(entries[1].labelKey, "agentsec.timeline.heartbeat");
});

test("filters timeline by severity and kind", () => {
  const entries = buildTimelineFromEvents([
    { ts: "2026-11-06T20:00:01+00:00", event_type: "file_access",
      action: "block", severity: "high", rule_ids: ["R001"], target_path: "/root/.ssh/id_rsa" },
    { ts: "2026-11-06T20:00:02+00:00", event_type: "net_connect",
      action: "audit", severity: "info", rule_ids: [], dst_domain: "8.8.8.8" },
  ]);
  assert.equal(filterTimeline(entries, {}).length, 2);
  assert.equal(filterTimeline(entries, { severity: "risk" }).length, 1);
  assert.equal(filterTimeline(entries, { severity: "high" }).length, 1);
  assert.equal(filterTimeline(entries, { kind: "net_connect" }).length, 1);
  assert.equal(filterTimeline(entries, { kind: "process_exec" }).length, 0);
});

test("groups policies into the four management sections", () => {
  const groups = buildPolicyGroups([
    { policy_id: "P-PATH-B01", name: "阻止访问 ~/.ssh", kind: "path",
      pattern: "~/.ssh", severity: "high", action: "block", enabled: true },
    { policy_id: "P-CMD-B01", name: "阻止命令", kind: "command",
      pattern: "rm -rf", severity: "high", action: "block", enabled: true },
    { policy_id: "P-MCP-A01", name: "批准 filesystem", kind: "mcp",
      pattern: "filesystem", severity: "high", action: "allow", enabled: true },
    { policy_id: "P-NET-A01", name: "批准 curl", kind: "network",
      pattern: "curl", severity: "medium", action: "allow", enabled: true },
  ]);
  assert.deepEqual(groups.map((group) => group.id),
                   ["file", "network", "mcp", "tool", "command"]);
  assert.equal(groups[0].rows.length, 1);
  assert.equal(groups[1].rows.length, 1);
  assert.equal(groups[1].rows[0].kind, "network");
  assert.equal(groups[2].rows.length, 1);
  assert.equal(groups[3].rows.length, 0);
  assert.equal(groups[4].rows.length, 1);
});

test("host-kind policies keep their kind inside the network group", () => {
  const groups = buildPolicyGroups([
    { policy_id: "P-HOST-P01", name: "生产主机", kind: "host", pattern: "prod-*",
      severity: "critical", action: "ask", enabled: true },
  ]);
  assert.equal(groups[1].id, "network");
  assert.equal(groups[1].rows[0].kind, "host");
});

test("builds approval pending and history rows", () => {
  const rows = buildApprovalRows({
    pending: [
      { event_id: "evt-ask", ts: "2026-11-06T20:00:10+00:00", host: "d2-dev",
        session_id: "s-1", tool_name: "Bash", target_path: "", rule_ids: ["R003"],
        severity: "medium" },
    ],
    history: [
      { event_id: "evt-apr-1", ts: "2026-11-06T20:01:00+00:00",
        evidence: { decision: "approve", policy_id: "P-CMD-B01", note: "poc" } },
      { event_id: "evt-apr-2", ts: "2026-11-06T20:02:00+00:00",
        evidence: { decision: "reject", policy_id: "", note: "" } },
    ],
  });
  assert.equal(rows.pending[0].eventId, "evt-ask");
  assert.equal(rows.pending[0].tone, "warning");
  assert.equal(rows.history[0].decisionKey, "agentsec.policy.approvals.approved");
  assert.equal(rows.history[0].tone, "success");
  assert.equal(rows.history[1].decisionKey, "agentsec.policy.approvals.rejected");
  assert.equal(rows.history[1].tone, "danger");
});

test("summarizes agent security KPIs", () => {
  const summary = summarizeAgentSecurity({
    stats: { events_total: 42, sessions: 5, assets: 9, by_action: { block: 7, ask: 3 },
             pending_approvals: 2, rules_total: 33, runtime_rules: 5 },
    sessions,
  });
  assert.equal(summary.eventsTotal, 42);
  assert.equal(summary.runningSessions, 1);
  assert.equal(summary.riskEvents, 2);
  assert.equal(summary.blocked, 7);
  assert.equal(summary.pendingApprovals, 2);
  assert.equal(summary.rulesTotal, 33);
  const empty = summarizeAgentSecurity();
  assert.equal(empty.eventsTotal, 0);
  assert.equal(empty.sessions, 0);
});
