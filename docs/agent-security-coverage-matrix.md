# Agent Security Runtime Coverage and Risk Triage

_Operational design for the two-host StepFun trial and future managed endpoints · 2026-11-08_

## Asset counts are inventory, not threat counts

> **Historical metric warning:** all `542 / 599 / 125 / 459` figures below are
> **v1 path-count metrics and obsolete**. They are retained only to explain the
> first measurement and must not be presented as installed assets, current
> alerts, or detection effectiveness.

Read-only path provenance showed that the test host's 542 Skills and 31 plugin MCP definitions are predominantly under the Codex plugin cache. Five additional Skills are Codex built-ins; two Skills and two MCP definitions are explicit synthetic lab fixtures. These were not individually installed at random. The four Agent CLIs installed for the trial are Codex, Qwen Code, OpenClaw, and Step Code.

The asset ledger previously counted 542 Skills, 33 MCP assets (31 plugin cache definitions and two synthetic definitions), 23 dependency manifests, one Hook config, and four CLIs. A definition in an MCP JSON file is not evidence that its server is running; a Skill in cache is not evidence it was activated. Plugin-cache provenance must remain distinct from user-installed and synthetic assets.

The first 599 unique path targets had 125 `block` policy verdicts, 459 `alert` verdicts, and 15 with no findings. The dominant findings were S16 unregistered source, S08 sensitive-path text, and S13 unregistered MCP definitions. These v1 counts include marketplace-cache definitions and are not current risk denominators. They describe rule matches and policy actions, **not confirmed malware**. The latest known results for the synthetic samples are S01/S02/S08 on the pseudo-malicious Skill and S03 on the poisoned MCP description. Finding evidence was stripped before upload.

The corrected inventory reports logical assets separately from physical instances and normalized content. Marketplace cache, vendor dependencies, and synthetic samples remain visible in inventory but are separated from installed/enabled/active assets and enforcement alerts. Current counts must come from `/api/agent-security/assets/summary`; do not derive them from the historical values above.

## Separate verdict, assessment, and provenance

| Field | Example values | Meaning |
|---|---|---|
| Provenance | `codex_plugin_cache`, `codex_builtin`, `user_installed_cli_content`, `synthetic_test`, `unknown` | Where the asset was discovered or how it arrived |
| Scanner verdict | `clean`, `alert`, `block` | Scanner/policy action for the current scan |
| Risk assessment | `unassessed`, `no_findings`, `suspicious`, `high_risk_candidate`, `confirmed_malicious`, `false_positive` | Current interpretation of all available evidence |
| ThreatBook IOC verdict | `malicious`, `suspicious`, `clean`, `unknown` | Reputation of the queried public IOC at query time only |
| Review state | `pending`, `confirmed_malicious`, `false_positive`, `accepted_exception` | Human adjudication with reviewer/reason/time |

Static `block`, unregistered S16, a hash change, or ThreatBook `clean` alone never confirms or clears asset maliciousness. TI is shadow enrichment; runtime `connect` after sensitive read remains a critical behavior correlation but is not automatically proof of exfiltration.

## End-to-end developer scenario coverage

| Scenario | Intent evidence | Near-execution Hook | Runtime observation | On-path enforcement | Required correlation |
|---|---|---|---|---|---|
| Install/update CLI/plugin/Skill/MCP | Source, version, digest, installer | Product lifecycle event if supported | Inventory delta and scan | Admission gate before activation (implementation in progress) | Provenance + scan + approval |
| Read/edit project source | Tool and normalized target | PreToolUse allow/ask/block | File event | Hook for supported products | Host/session/target match |
| Read credential path | Requested target | Deny before tool execution | auditd open/read attempt | Hook; OS ACL/LSM for bypass routes | Hook decision + observed attempt |
| Run shell/process | Command parameters | Command policy | `execve` chain | Hook plus constrained shell/sandbox (future) | Parent/session/PID/executable |
| MCP read/write/admin call | Server, tool name, arguments, capability | MCP matcher and capability policy | Server process/file/network activity | MCP gateway or server authorization (future) | Server identity + declared capability + effect |
| Install package/lifecycle script | Package source and lockfile | Install command policy | Child processes, writes, network | Package gate/sandbox (future) | Manifest digest + runtime effects |
| Model/API connection | Intended provider/tool route | Usually not a tool Hook event | `connect` by Agent process/session | Egress proxy/allowlist (future) | Distinguish expected model traffic from data egress |
| Sensitive read followed by connection | Read intent and following action | Hook may prevent read | R005 cross-poll correlation | Egress gateway (future) | Critical candidate; inspect destination and data-flow context |
| Approval/denial | Ask request and approver | Adapter ask protocol | Resulting execution/no-execution | Product approval UI | Decision binds to exact request and precedes execution |
| Hook tampering/trust bypass | Config/package digest and product trust | Managed trust gate | S21/S22 monitor | Managed settings/hooks | Trust state is separate from config presence |
| Session/subagent start | Product/session identity | Session hooks if supported | Process tree/backfill | Agent supervisor (future) | Host-namespaced session ID; orphan state explicit |
| Offline endpoint/outage | Local policy decision | Local Hook remains active | SQLite outbox/heartbeat | Local enforcement | Queue depth, oldest age, retry, last successful upload |
| Collector tampering/stoppage | Expected collector state | N/A | service/audit heartbeat | OS service manager | Heartbeat deadline and local audit health |

## Multi-Agent capability matrix

| Product | Current tier | Current verified coverage |
|---|---|---|
| Claude Code | Hook | Callback allow/block, product text response, and package/settings baseline verified |
| Codex CLI | Hook adapter exists | Adapter protocol verified; development host Hook deliberately not installed; isolated test account used for runtime behavior |
| Qwen Code | Discovery | Inventory/config scan; without shell tool it declined execution rather than fabricate evidence |
| OpenClaw | Discovery | StepFun provider configured; Agent turn timed out in this trial, so no execution pass claimed |
| Step Code | Discovery | Real tool-enabled call and auditd process/file telemetry verified |
| Hermes/OpenCode/Aider | Candidate | Not installed in this trial |
| WorkBuddy/Qcode/other | Discovery candidate | No verified Hook contract; only asset/config scan until validated |

Every adapter must declare version, event names, input fields, allow/ask/deny protocol, product trust gate, sandbox/approval posture, bypasses, and tested capabilities. Similar configuration shape is not evidence of Hook support.

## Operations: device lifecycle, heartbeat, and minute-level response

1. Each device has a random token, centrally stored only as SHA-256. Re-enrollment rotates it; revoke invalidates it. Upload only over TLS/mTLS or the current SSH loopback tunnel.
2. Collector polls every 5 seconds, has a durable SQLite outbox, retries uploads with exponential backoff/jitter, and sends a heartbeat every 60 seconds containing total pending events, oldest queued timestamp, upload failures, audit offset, and lost-record count.
3. Device health is derived from the collector heartbeat: online <=120 seconds, degraded <=300 seconds or backlog/retry present, offline >300 seconds, never-seen if none. Inventory arrival alone does not imply online.
4. Endpoint collector is a persistent systemd unit with start-on-boot and restart-on-failure. Audit rules remain scoped to the test UID and dedicated lab path. Host-wide `execve` capture is explicitly not the default on multi-user production hosts.
5. UI polls device health and Agent Security data every 30 seconds while visible. Healthy-path target is p95 <=60 seconds from audited event to central timeline; outages are represented as stale/offline plus backlog, not silently hidden.

## ThreatBook shadow enrichment

- A local mode-600 ignored file contains `THREATBOOK_API_KEY`; never put it in Agent config, logs, reports, or edge events.
- Shadow mode only in this trial. Query deduplicated public IP/domain indicators from runtime events, cache 7 days, soft budget 250/day, hard stop 300/day, 2-second timeout; errors/unsupported indicator types become unknown.
- Never send private/reserved IPs, internal hostnames, source text, prompt text, usernames, arguments, or file paths. The public destination IP observed in a runtime connection may be submitted; the target's sensitive-read path is never submitted.
- ThreatBook `clean` is reputation of that IOC, not proof the Agent/Skill is safe. Do not enable TI `enforce` in a detective-only monitor; blocking an already observed connection is not possible without an in-path gateway.
- Confirmed-malicious requires high-confidence IOC evidence corroborated with local behavior or analyst adjudication. Static findings alone remain suspicious/high-risk candidates.
