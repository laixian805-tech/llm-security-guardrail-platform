from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from pathlib import Path

from .adapters import ADAPTERS, capability_matrix
from .admission import evaluate_path
from .guard import guard_status, install_guard, uninstall_guard
from .models import ScanVerdict
from .inventory import (discover_agent_assets, sanitize_scan_report,
                        upload_agent_assets)
from .threat_intel import extract_iocs
from .policy import CallerContext, decide, load_policies
from .paths import agentsec_dir
from .scanner import Registry, scan_path, sha256_path
from .collector import (CollectorConfig, collect_once, collector_status,
                     load_config, run_daemon)
from .poc import run_acceptance_poc
from .store import AgentSecStore


def _print_json(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _cmd_scan(args: argparse.Namespace) -> int:
    registry = Registry.load(args.registry) if args.registry else Registry.load()
    store = AgentSecStore()
    reports = scan_path(args.path, host=args.host or "", registry=registry)
    if not reports:
        print(f"no scannable target found at {args.path}", file=sys.stderr)
        return 3
    exit_code = 0
    for report in reports:
        store.record_scan(report)
        if args.json:
            _print_json(report.model_dump())
            continue
        print(f"[{report.verdict.value.upper():5s}] {report.target_kind.value}/{report.target_name} "
              f"-> {report.target_path}")
        for finding in report.findings:
            location = f"{finding.file}:{finding.line}" if finding.line else finding.file
            decoded = " (decoded)" if finding.decoded else ""
            print(f"    {finding.rule_id} {finding.severity.value:8s} {finding.action.value:5s} "
                  f"{location}{decoded} {finding.evidence[:80]}")
        print(f"    sha256={report.sha256[:16]} registered={report.registered} drift={report.drift}")
        if report.verdict == ScanVerdict.BLOCK:
            exit_code = max(exit_code, 2)
        elif report.verdict == ScanVerdict.ALERT:
            exit_code = max(exit_code, 1)
    return exit_code


def _cmd_registry_add(args: argparse.Namespace) -> int:
    registry = Registry.load(args.registry) if args.registry else Registry.load()
    digest = sha256_path(Path(args.path).expanduser()) if args.path else ""
    asset = registry.add(args.kind, args.name, digest, source=args.source,
                         approved_by=args.approved_by, note=args.note)
    print(f"registered {args.kind}/{args.name} sha256={digest[:16]} source={args.source}")
    _ = asset
    return 0


def _cmd_registry_remove(args: argparse.Namespace) -> int:
    registry = Registry.load(args.registry) if args.registry else Registry.load()
    removed = registry.remove(args.kind, args.name)
    print("removed" if removed else "not found")
    return 0 if removed else 1


def _cmd_registry_list(args: argparse.Namespace) -> int:
    registry = Registry.load(args.registry) if args.registry else Registry.load()
    if args.json:
        _print_json(registry.assets)
        return 0
    if not registry.assets:
        print("registry is empty")
        return 0
    for asset in registry.assets:
        print(f"{asset.get('kind', '?'):6s} {asset.get('name', '?'):30s} "
              f"sha256={str(asset.get('sha256', ''))[:16]} source={asset.get('source', '')}")
    return 0


def _cmd_admission_check(args: argparse.Namespace) -> int:
    """Evaluate one asset before an install or enable operation."""
    registry = Registry.load(args.registry) if args.registry else Registry.load()
    decision = evaluate_path(
        args.path,
        kind=args.kind,
        name=args.name,
        registry=registry,
        allow_cached=args.allow_cached,
        allow_synthetic=args.allow_synthetic,
    )
    if args.json:
        _print_json(decision.as_dict())
    else:
        print(f"[{decision.action.upper()}] {decision.kind}/{decision.name} -> {decision.path}")
        print(f"    {decision.reason}")
        for check in decision.checks:
            print(f"    {'PASS' if check.passed else 'FAIL':4s} {check.name}: {check.reason}")
    return 0 if decision.allowed else 2


def _cmd_assets(args: argparse.Namespace) -> int:
    store = AgentSecStore()
    assets = store.list_assets(kind=args.kind, host=args.host)
    if args.json:
        _print_json([a.model_dump() for a in assets])
        return 0
    if not assets:
        print("no assets recorded")
        return 0
    for asset in assets:
        print(f"{asset.kind.value:6s} {asset.name:30s} host={asset.host or '-':12s} "
              f"registered={asset.registered} sha256={asset.sha256[:16]}")
    return 0


def _cmd_inventory(args: argparse.Namespace) -> int:
    host = args.host or os.environ.get("AGENTSEC_HOST") or socket.gethostname()
    assets = discover_agent_assets(host=host)
    store = AgentSecStore()
    cache_path = agentsec_dir() / "inventory-target-hashes.json"
    cache: dict[str, str] = {}
    if not args.full_scan:
        try:
            loaded = json.loads(cache_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cache = {str(key): str(value) for key, value in loaded.items()}
        except (OSError, json.JSONDecodeError):
            pass
    for asset in assets:
        store.upsert_asset(asset)
    scans = []
    ti_candidates: list[tuple[str, str, str]] = []
    for target in args.scan:
        reports = scan_path(target, host=host,
                            unchanged_hashes=None if args.full_scan else cache)
        if not reports:
            print(f"agentsec inventory: no scannable target at {target}",
                  file=sys.stderr)
            return 3
        for report in reports:
            ti_candidates.extend(
                (report.target_kind.value, report.target_path, ioc)
                for finding in report.findings
                for ioc, _ioc_type in extract_iocs(finding.evidence)
            )
            safe_report = sanitize_scan_report(report)
            store.record_scan(safe_report)
            scans.append(safe_report)
    if getattr(args, "refresh_ti", False):
        from .ti import check_ioc
        remaining = getattr(args, "ti_limit", 50)
        for kind, target_path, ioc in sorted(set(ti_candidates)):
            if remaining <= 0:
                break
            ti = check_ioc(store, ioc, mode="shadow")
            remaining -= 1
            if not ti["ioc"]:
                continue
            for index, report in enumerate(scans):
                if report.target_kind.value == kind and report.target_path == target_path:
                    scans[index] = report.model_copy(update={
                        "ti_provider": ti["provider"],
                        "ti_verdict": ti["verdict"],
                        "ti_confidence": ti["confidence"],
                    })
                    store.update_scan_ti(report.scan_id, provider=ti["provider"],
                                         verdict=ti["verdict"],
                                         confidence=ti["confidence"])
                    break
    upload_result = None
    if args.upload:
        url = args.url or os.environ.get("AGENTSEC_ASSET_UPLOAD_URL", "")
        token = os.environ.get("AGENTSEC_DEVICE_KEY", "")
        try:
            upload_result = upload_agent_assets(url=url, device_key=token,
                                                assets=assets, scans=scans)
        except (ValueError, RuntimeError) as exc:
            print(f"agentsec inventory: {exc}", file=sys.stderr)
            if args.best_effort:
                return 0
            return 5
    if not args.dry_run:
        cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=2) + "\n",
                              encoding="utf-8")
        if os.name != "nt":
            cache_path.chmod(0o600)
    if args.json:
        payload = {"assets": [asset.model_dump(mode="json") for asset in assets]}
        payload["scans"] = [report.model_dump(mode="json") for report in scans]
        if upload_result is not None:
            payload["upload"] = upload_result
        _print_json(payload)
        return 0
    print(f"discovered {len(assets)} Agent CLI asset(s)")
    for asset in assets:
        print(f"{asset.name:16s} version={asset.version or '-':20s} host={asset.host}")
    if scans:
        print(f"scanned {len(scans)} Skill/MCP/Hook target(s)")
    if upload_result is not None:
        print(f"uploaded {upload_result.get('accepted', 0)} asset(s)"
              f" for device {upload_result.get('device_id', '')}")
    return 0


def _cmd_events(args: argparse.Namespace) -> int:
    store = AgentSecStore()
    events = store.list_events(severity=args.severity, rule_id=args.rule,
                               session_id=args.session, limit=args.limit)
    if args.json:
        _print_json([e.model_dump() for e in events])
        return 0
    if not events:
        print("no events")
        return 0
    for event in events:
        rules = ",".join(event.rule_ids) or "-"
        print(f"{event.ts} {event.severity.value:8s} {event.action.value:5s} {event.source.value:8s} "
              f"{event.event_type.value:13s} host={event.host or '-'} rules={rules} "
              f"{event.target_path or event.dst_domain}")
    return 0


def _cmd_stats(args: argparse.Namespace) -> int:
    store = AgentSecStore()
    stats = store.stats()
    if args.json:
        _print_json(stats)
        return 0
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


def _cmd_policy_check(args: argparse.Namespace) -> int:
    tool_input = json.loads(args.input) if args.input else {}
    decision = decide(args.tool, tool_input,
                      CallerContext(host=args.host, host_role=args.role),
                      load_policies(args.policies))
    if args.json:
        _print_json(decision.model_dump())
    else:
        print(f"{decision.action.value}: {decision.reason}")
        if decision.rule_ids:
            print(f"rules: {','.join(decision.rule_ids)}")
    return {"block": 2, "ask": 1}.get(decision.action.value, 0)


def _cmd_guard_install(args: argparse.Namespace) -> int:
    try:
        result = install_guard(args.agent, settings_path=args.settings or None,
                               module=args.module)
    except ValueError as exc:
        print(f"agentsec: {exc}", file=sys.stderr)
        return 4
    print(f"settings: {result.settings_path}")
    if result.backup_path:
        print(f"backup:   {result.backup_path}")
    print(f"installed hook events: {', '.join(result.installed) or '(none)'}")
    if result.already_present:
        print(f"already present:       {', '.join(result.already_present)}")
    print(f"policies:  {result.policies_path}")
    print(f"baseline:  {result.baseline_path}")
    for line in ADAPTERS[args.agent].trust:
        print(f"trust:     {line}")
    return 0


def _cmd_guard_uninstall(args: argparse.Namespace) -> int:
    try:
        result = uninstall_guard(args.agent, settings_path=args.settings or None,
                                 module=args.module)
    except ValueError as exc:
        print(f"agentsec: {exc}", file=sys.stderr)
        return 4
    print(f"removed hook events: {', '.join(result.removed) or '(none)'}")
    if result.backup_path:
        print(f"backup: {result.backup_path}")
    return 0


def _cmd_guard_status(args: argparse.Namespace) -> int:
    status = guard_status(args.agent, settings_path=args.settings or None, module=args.module)
    if args.json:
        _print_json(status)
        return 0
    print(f"agent:     {status['agent']} (tier={status['tier']})")
    print(f"settings:  {status['settings_path']}")
    print(f"events:    {', '.join(status['installed_events']) or '(not installed)'}")
    print(f"baseline:  {'match' if status['baseline_match'] else 'mismatch or missing'}"
          f" (settings={'ok' if status['settings_match'] else 'drift'},"
          f" package={'ok' if status['package_match'] else 'drift'})")
    for identity, record in (status.get("callbacks") or {}).items():
        print(f"callback:  {'ok  ' if record['match'] else 'DRIFT'} {identity} -> {record['path']}")
    print(f"callbacks: {'match' if status['callbacks_match'] else 'mismatch or missing'}")
    if status.get("discovery_only"):
        print("coverage:  discovery-only (process discovery + config scan; no hooks)")
    if status["trust"]:
        print("trust:     entries present != trusted; product-side review still required")
        for line in status["trust"]:
            print(f"           - {line}")
    governance = status.get("governance") or {}
    for risk in governance.get("risks", []):
        print(f"GOVERNANCE RISK: {risk['key']}={risk['value']} — {risk['risk']}")
    for entry in governance.get("managed_settings", []):
        print(f"managed:   {'present' if entry['present'] else 'absent '} {entry['path']}")
    print(f"policies:  {status['policies_path']}")
    print(f"audit failures: {status['audit_failures']}")
    return 0


def _cmd_hook(args: argparse.Namespace) -> int:
    from . import hook as hook_module

    return hook_module.main([args.event, "--agent", args.agent])


def _cmd_guard_capabilities(args: argparse.Namespace) -> int:
    rows = capability_matrix()
    if args.json:
        _print_json(rows)
        return 0
    for row in rows:
        print(f"[{row['tier']:9s}] {row['key']:12s} {row['display_name']}")
        print(f"            agent_name={row['agent_name']} "
              f"settings={row['settings_path'] or '-'}")
        if row["events"]:
            for event, matcher in row["matchers"].items():
                print(f"            {event:14s} matcher={matcher}")
            print(f"            deny_via={row['deny_via']} "
                  f"trust_hash_pinned={row['trust_hash_pinned']}")
        for line in row["trust"]:
            print(f"            trust: {line}")
        if row["scan_paths"]:
            print(f"            scan: {', '.join(row['scan_paths'])}")
        for risk in row["governance"].get("risks", []):
            print(f"            GOVERNANCE RISK: {risk['key']}={risk['value']} — {risk['risk']}")
        if row["notes"]:
            print(f"            note: {row['notes']}")
    return 0


def _cmd_monitor_once(args: argparse.Namespace) -> int:
    config = load_config()
    if args.no_upload:
        config.upload_url = ""
    stats = collect_once(config, upload=not args.no_upload)
    if args.json:
        _print_json(stats)
    else:
        print(f"records={stats['records']} events={stats['events']} "
              f"inserted={stats['inserted']} offset={stats['audit_offset']} "
              f"uploaded={stats['uploaded']} heartbeat={stats['heartbeat']}")
    return 0


def _cmd_monitor_daemon(args: argparse.Namespace) -> int:
    config = load_config()
    if args.interval:
        config.poll_seconds = args.interval
    print(f"agentsec collector started (audit={config.audit_log}, "
          f"upload={config.upload_url or 'local only'})", flush=True)
    run_daemon(config)
    return 0


def _cmd_monitor_status(args: argparse.Namespace) -> int:
    status = collector_status(load_config())
    if args.json:
        _print_json(status)
        return 0
    print(f"audit log: {status['audit_log']} (size={status['audit_size']}, "
          f"offset={status['audit_offset']}, lag={status['audit_lag_bytes']}B)")
    print(f"pending events: {status['pending_events']}  upload: {status['upload_url']}"
          f"  upload failures: {status['upload_fail_count']}")
    age = status['heartbeat_age_seconds']
    print(f"heartbeat age: {age if age is not None else 'never'}s "
          f"({'OVERDUE (S23)' if status['heartbeat_overdue'] else 'ok'})")
    print(f"registered sessions: {status['registered_sessions']}")
    print(f"agent processes: {len(status['agent_processes'])}")
    for proc in status["agent_processes"]:
        print(f"  pid={proc['pid']} ppid={proc['ppid']} comm={proc['comm']} "
              f"session={proc['session_id'] or '(unregistered)'}")
    return 0


def _cmd_poc_run(args: argparse.Namespace) -> int:
    report = run_acceptance_poc()
    rendered = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        target = Path(args.output).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(rendered + "\n", encoding="utf-8")
    if args.json or args.output:
        print(rendered)
    else:
        print(f"Agent Security POC: {report['status']} "
              f"({report['summary']['passed']}/{report['summary']['total']} checks)")
        for check in report["checks"]:
            print(f"[{check['status'].upper():6s}] {check['name']}: {check['actual']}")
    return 0 if report["status"] == "passed" else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="agentsec", description="Agent security gateway CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--registry", default="", help="path to registry.json")

    scan = sub.add_parser("scan", parents=[common], help="scan a skill/mcp/deps/hook target")
    scan.add_argument("path")
    scan.add_argument("--host", default="")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_cmd_scan)

    registry = sub.add_parser("registry", help="manage the local trusted registry")
    registry_sub = registry.add_subparsers(dest="registry_command", required=True)
    reg_add = registry_sub.add_parser("add", parents=[common])
    reg_add.add_argument("--kind", required=True, choices=["agent", "mcp", "skill", "deps", "hook"])
    reg_add.add_argument("--name", required=True)
    reg_add.add_argument("--path", default="")
    reg_add.add_argument("--source", default="local")
    reg_add.add_argument("--approved-by", default="")
    reg_add.add_argument("--note", default="")
    reg_add.set_defaults(func=_cmd_registry_add)
    reg_remove = registry_sub.add_parser("remove", parents=[common])
    reg_remove.add_argument("--kind", required=True)
    reg_remove.add_argument("--name", required=True)
    reg_remove.set_defaults(func=_cmd_registry_remove)
    reg_list = registry_sub.add_parser("list", parents=[common])
    reg_list.add_argument("--json", action="store_true")
    reg_list.set_defaults(func=_cmd_registry_list)

    admission = sub.add_parser("admission", help="check an asset before install or enable")
    admission_sub = admission.add_subparsers(dest="admission_command", required=True)
    admission_check = admission_sub.add_parser("check", help="run the fail-closed admission gate")
    admission_check.add_argument("--kind", required=True,
                                 choices=["agent", "mcp", "skill", "deps", "hook"])
    admission_check.add_argument("--name", required=True)
    admission_check.add_argument("--path", required=True)
    admission_check.add_argument("--registry", default="",
                                 help="path to registry.json")
    admission_check.add_argument("--allow-cached", action="store_true",
                                 help="allow an explicitly selected cache for inventory checks")
    admission_check.add_argument("--allow-synthetic", action="store_true",
                                 help="allow synthetic lab content")
    admission_check.add_argument("--json", action="store_true")
    admission_check.set_defaults(func=_cmd_admission_check)

    assets = sub.add_parser("assets", help="list recorded assets")
    assets.add_argument("--kind", default="")
    assets.add_argument("--host", default="")
    assets.add_argument("--json", action="store_true")
    assets.set_defaults(func=_cmd_assets)

    inventory = sub.add_parser("inventory", help="discover installed Agent CLIs")
    inventory.add_argument("--host", default="",
                           help="friendly host name; defaults to AGENTSEC_HOST or hostname")
    inventory.add_argument("--upload", action="store_true",
                            help="upload metadata using AGENTSEC_DEVICE_KEY")
    inventory.add_argument("--full-scan", action="store_true",
                            help="rescan all targets even when the local digest is unchanged")
    inventory.add_argument("--dry-run", action="store_true",
                            help="discover and scan without changing the local digest cache")
    inventory.add_argument("--best-effort", action="store_true",
                            help="keep local inventory/cache and exit 0 when central upload is unavailable")
    inventory.add_argument("--refresh-ti", action="store_true",
                            help="perform bounded ThreatBook shadow lookups for eligible findings")
    inventory.add_argument("--ti-limit", type=int, default=50,
                            help="maximum ThreatBook lookups for this run")
    inventory.add_argument("--scan", action="append", default=[], metavar="PATH",
                            help="scan a local Skill/MCP/Hook target and include its summary")
    inventory.add_argument("--url", default="",
                            help="inventory endpoint; defaults to AGENTSEC_ASSET_UPLOAD_URL")
    inventory.add_argument("--json", action="store_true")
    inventory.set_defaults(func=_cmd_inventory)

    events = sub.add_parser("events", help="query security events")
    events.add_argument("--severity", default="")
    events.add_argument("--rule", default="")
    events.add_argument("--session", default="")
    events.add_argument("--limit", type=int, default=50)
    events.add_argument("--json", action="store_true")
    events.set_defaults(func=_cmd_events)

    stats = sub.add_parser("stats", help="show event statistics")
    stats.add_argument("--json", action="store_true")
    stats.set_defaults(func=_cmd_stats)

    policy = sub.add_parser("policy", help="policy decision utilities")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)
    policy_check = policy_sub.add_parser("check", help="evaluate one tool call")
    policy_check.add_argument("--tool", required=True)
    policy_check.add_argument("--input", default="", help="tool input as JSON")
    policy_check.add_argument("--host", default="")
    policy_check.add_argument("--role", default="")
    policy_check.add_argument("--policies", default="")
    policy_check.add_argument("--json", action="store_true")
    policy_check.set_defaults(func=_cmd_policy_check)

    guard = sub.add_parser("guard", help="install or inspect agent hooks")
    guard_sub = guard.add_subparsers(dest="guard_command", required=True)
    guard_install = guard_sub.add_parser("install")
    guard_install.add_argument("--agent", default="claude-code",
                               choices=sorted(ADAPTERS))
    guard_install.add_argument("--settings", default="")
    guard_install.add_argument("--module", default="app.agent_security")
    guard_install.set_defaults(func=_cmd_guard_install)
    guard_uninstall = guard_sub.add_parser("uninstall")
    guard_uninstall.add_argument("--agent", default="claude-code",
                                 choices=sorted(ADAPTERS))
    guard_uninstall.add_argument("--settings", default="")
    guard_uninstall.add_argument("--module", default="app.agent_security")
    guard_uninstall.set_defaults(func=_cmd_guard_uninstall)
    guard_status_parser = guard_sub.add_parser("status")
    guard_status_parser.add_argument("--agent", default="claude-code",
                                     choices=sorted(ADAPTERS))
    guard_status_parser.add_argument("--settings", default="")
    guard_status_parser.add_argument("--module", default="app.agent_security")
    guard_status_parser.add_argument("--json", action="store_true")
    guard_status_parser.set_defaults(func=_cmd_guard_status)
    guard_capabilities = guard_sub.add_parser(
        "capabilities", help="print the per-product hook capability matrix")
    guard_capabilities.add_argument("--json", action="store_true")
    guard_capabilities.set_defaults(func=_cmd_guard_capabilities)

    monitor = sub.add_parser("monitor", help="behavior monitor (auditd collector, D2 Linux)")
    monitor_sub = monitor.add_subparsers(dest="monitor_command", required=True)
    monitor_once = monitor_sub.add_parser("once", help="run a single collection cycle")
    monitor_once.add_argument("--no-upload", action="store_true")
    monitor_once.add_argument("--json", action="store_true")
    monitor_once.set_defaults(func=_cmd_monitor_once)
    monitor_daemon = monitor_sub.add_parser("daemon", help="run the collector loop")
    monitor_daemon.add_argument("--interval", type=float, default=0.0,
                                help="poll interval seconds (overrides env)")
    monitor_daemon.set_defaults(func=_cmd_monitor_daemon)
    monitor_status = monitor_sub.add_parser("status", help="collector and audit pipeline status")
    monitor_status.add_argument("--json", action="store_true")
    monitor_status.set_defaults(func=_cmd_monitor_status)

    poc = sub.add_parser("poc", help="run isolated local acceptance checks")
    poc_sub = poc.add_subparsers(dest="poc_command", required=True)
    poc_run = poc_sub.add_parser("run", help="scan and verify the local vertical slice")
    poc_run.add_argument("--json", action="store_true")
    poc_run.add_argument("--output", default="",
                         help="write a machine-readable report to this path")
    poc_run.set_defaults(func=_cmd_poc_run)

    hook = sub.add_parser("hook", help="agent hook entry point (called by the agent)")
    hook.add_argument("event", choices=["pre-tool-use", "post-tool-use",
                                        "session-start", "session-end"])
    hook.add_argument("--agent", default="claude-code", choices=sorted(ADAPTERS))
    hook.set_defaults(func=_cmd_hook)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
