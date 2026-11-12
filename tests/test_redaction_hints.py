"""端侧资源提示：只取路径，不取内容；归一化规则与控制面一致。

来历：归因服务的 TEMPORAL_FEATURE(0.35) 读 summary 里的资源提示，但端侧从来没
产过这个字段——生产环境里那 0.35 分的弱关联永远不会触发，是死代码。补上这个
字段的同时，必须确认它不会把参数内容带出去。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "endpoint"))

from redaction import resource_hints, summarize  # noqa: E402


def test_extracts_absolute_paths():
    hints = resource_hints({"command": "cat /etc/passwd && ls /var/log"})
    assert "/etc/passwd" in hints
    assert "/var/log" in hints


def test_normalises_home_prefix():
    hints = resource_hints({"path": "/home/alice/.ssh/id_rsa"})
    assert hints == ["~/.ssh/id_rsa"], "家目录必须归一成 ~，否则与控制面比对不上"


def test_ignores_plain_words():
    hints = resource_hints({"command": "echo hello world", "description": "say hi"})
    assert hints == []


def test_truncates_overlong_paths():
    long_path = "/" + "/".join(["segment"] * 40)
    hints = resource_hints({"path": long_path})
    assert hints and len(hints[0]) <= 161
    assert hints[0].endswith("…")


def test_caps_number_of_hints():
    command = " ".join(f"/tmp/file-{i}" for i in range(10))
    hints = resource_hints({"command": command})
    assert len(hints) == 4


def test_does_not_leak_values_into_summary():
    """路径可以出去，密钥值绝对不行。"""
    secret = "sk-ant-abcdefghijklmnopqrstuvwxyz0123"
    params = {"command": f"curl -H 'Authorization: Bearer {secret}' /tmp/out"}
    summary, _ = summarize(params)
    assert secret not in summary
    assert "/tmp/out" in summary
    assert json.loads(summary)["values_omitted"] is True


def test_summary_omits_hints_when_absent():
    summary, digest = summarize({"description": "nothing here"})
    payload = json.loads(summary)
    assert "resource_hints" not in payload
    assert len(digest) == 64


def test_control_plane_uses_the_same_normalisation():
    """端侧与归因服务必须用同一套归一化，否则弱关联匹配不上。"""
    sys.path.insert(0, str(ROOT / "backend"))
    from services.attribution_service import _hint_form

    cases = ["/home/bob/.aws/credentials", "/Users/bob/.aws/credentials"]
    assert resource_hints({"path": cases[0]}) == [_hint_form(cases[0])]
    assert resource_hints({"path": cases[1]}) == [_hint_form(cases[1])]


@pytest.mark.parametrize("params", [
    {"command": "grep -r token /srv/app/.env"},
    {"path": "~/.ssh/id_ed25519", "mode": "read"},
])
def test_hint_shape_is_json_serialisable(params):
    summary, _ = summarize(params)
    payload = json.loads(summary)
    assert isinstance(payload.get("resource_hints", []), list)
    assert all(isinstance(item, str) for item in payload.get("resource_hints", []))
