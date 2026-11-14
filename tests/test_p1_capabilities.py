"""P1 能力单测：MCP 端侧配置与会话列表枚举、内核 audit 丢包对账、audit backlog 标志与超时执行收敛。"""

from __future__ import annotations

import json
import stat
from datetime import datetime, timedelta, timezone
import sys
from pathlib import Path

from endpoint import audit as audit_mod
from endpoint import coverage as coverage_mod
from endpoint import probe_product as probe_mod
from endpoint.outbox import Outbox
from test_console_auth import api, admin_token, call
from test_v1_ingest import setup_device


def test_verify_mcp_qwen_and_codex_enumeration(tmp_path: Path, monkeypatch):
    home = tmp_path / "home"
    qwen_cfg = home / ".qwen" / "settings.json"
    qwen_cfg.parent.mkdir(parents=True)
    qwen_cfg.write_text(
        json.dumps({"mcpServers": {"helper-mcp": {"command": "node", "args": ["/opt/mcp.js"]}}}),
        encoding="utf-8",
    )

    codex_cfg = home / ".codex" / "config.toml"
    codex_cfg.parent.mkdir(parents=True)
    codex_cfg.write_text('[mcp_servers.docs-mcp]\ncommand = "node"\nargs = ["/opt/docs.js"]\n', encoding="utf-8")

    # 未安装 CLI 时，降级为 filesystem + loaded=None（不伪造加载成功）
    monkeypatch.setenv("PATH", str(tmp_path / "empty-bin"))
    r_qwen = probe_mod.verify_mcp("qwen-code", "helper-mcp", home=home)
    assert r_qwen["level"] == "filesystem" and r_qwen["loaded"] is None and r_qwen["probe"] == "cli_not_found"
    r_codex = probe_mod.verify_mcp("codex", "docs-mcp", home=home)
    assert r_codex["level"] == "filesystem" and r_codex["loaded"] is None

    # 安装模拟 qwen mcp list CLI，验证 listed / not_listed 二态
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    qwen_bin = bin_dir / "qwen"
    qwen_bin.write_text(f"#!{sys.executable}\nprint('helper-mcp: connected')\n", encoding="utf-8")
    qwen_bin.chmod(qwen_bin.stat().st_mode | stat.S_IEXEC)
    monkeypatch.setenv("PATH", str(bin_dir))

    listed = probe_mod.verify_mcp("qwen-code", "helper-mcp", home=home)
    assert listed["level"] == "product_session" and listed["loaded"] is True
    assert listed["probe"]["outcome"] == "listed"

    missing = probe_mod.verify_mcp("qwen-code", "absent-mcp", home=home)
    assert missing["loaded"] is False and missing["probe"] == "not_registered"


def test_kernel_audit_drops_delta_and_backlog_alert(tmp_path: Path):
    box = Outbox(tmp_path / "endpoint")
    coverage_mod.record_kernel_audit_drops(box, status={"enabled": 1, "lost": 100, "backlog": 10, "backlog_limit": 8192})
    assert box.unreported_drops() == []

    coverage_mod.record_kernel_audit_drops(box, status={"enabled": 1, "lost": 107, "backlog": 7000, "backlog_limit": 8192})
    drops = {d["kind"]: d for d in box.unreported_drops()}
    assert drops["kernel_audit_lost"]["count"] == 7
    assert drops["kernel_audit_backlog"]["count"] == 0
    box.close()


def test_audit_collect_once_sets_more_when_log_exceeds_chunk(tmp_path: Path):
    log = tmp_path / "audit.log"
    state = tmp_path / "state"
    # 写入超过 1 MiB 的记录块以触发分片排空标志 more=True。
    line = 'type=SYSCALL msg=audit(1700000000.000:1): arch=c000003e syscall=59 success=yes pid=10 ppid=1 uid=1000 key="asgp"\n'
    repeats = (1024 * 1024) // len(line) + 20
    log.write_text(line * repeats, encoding="utf-8")
    cfg = {"audit_log": str(log), "state_dir": str(state), "audit_uid": 1000, "audit_keys": ["asgp"], "max_records": 50000}
    res = audit_mod.collect_once(cfg, settled=True)
    assert res["more"] is True and res["bytes"] > 0


def test_reap_stale_executions_closes_old_running_and_preserves_recent(api, admin_token):
    dev = setup_device(api, admin_token, "reaper")
    now = datetime.now(timezone.utc)
    old_start = (now - timedelta(hours=3)).isoformat()
    recent_start = (now - timedelta(minutes=2)).isoformat()

    for ex_id, started in [("exec_stale_qwen", old_start), ("exec_fresh_qwen", recent_start)]:
        r = call(
            api.base,
            "POST",
            "/api/v1/executions",
            token=dev["token"],
            body={
                "execution_id": ex_id,
                "product": "qwen-code",
                "product_version": "0.26.8",
                "session_id": f"sess_{ex_id}",
                "started_at": started,
                "outcome": "running",
            },
        )
        assert r.status_code == 200, r.text

    # 设备令牌不得触发控制面全局清理。
    assert call(api.base, "POST", "/api/v1/executions:reap-stale", token=dev["token"], body={}).status_code in (401, 403)

    reap = call(
        api.base,
        "POST",
        "/api/v1/executions:reap-stale",
        token=admin_token,
        body={"stale_after_seconds": 1800, "product": "qwen-code"},
    )
    assert reap.status_code == 200, reap.text
    payload = reap.json()
    assert payload["closed_count"] == 1
    assert payload["execution_ids"] == ["exec_stale_qwen"]

    rows = {r["execution_id"]: r for r in call(api.base, "GET", "/api/v1/executions", token=admin_token).json()["executions"]}
    assert rows["exec_stale_qwen"]["outcome"] == "aborted"
    assert rows["exec_stale_qwen"]["ended_at"] is not None
    assert rows["exec_fresh_qwen"]["outcome"] == "running"
