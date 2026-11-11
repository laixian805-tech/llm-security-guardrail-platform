#!/usr/bin/env python3
"""协议尖峰录制器：把 Claude Code hook 的 stdin 原样落盘。

只做一件事：把收到的 JSON 原样 append 到 `~/.asgp/spike/recorded-<event>.jsonl`，
恒 exit 0。不触网、不写库、不解析、不改配置——尖峰要的是"产品实际送了
什么"，任何加工都会让证据变成猜的。

用法（由 ~/.claude/settings.json 的 hooks 条目调用，也可手工喂 JSON）：
    echo '{"hook_event_name":"SessionStart","session_id":"s"}' | python3 scripts/record-claude-hooks.py

产物按事件名分文件，一次会话的四个事件各自成流，方便逐字段与适配器比对。
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SPIKE_DIR = Path(os.environ.get("ASGP_SPIKE_DIR", Path.home() / ".asgp" / "spike"))
MAX_BODY_BYTES = 8 * 1024 * 1024


def event_name(payload: object) -> str:
    if isinstance(payload, dict):
        name = payload.get("hook_event_name")
        if isinstance(name, str) and name:
            return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
    return "unknown"


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_BODY_BYTES)
    except Exception as exc:  # noqa: BLE001 - 录制器绝不能打断用户的工具调用
        print(f"[record-claude-hooks] 读取 stdin 失败：{exc}", file=sys.stderr)
        return 0

    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        payload = {"_unparsed": raw[:4096].decode("utf-8", "replace")}

    record = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "argv": sys.argv[1:],
        "payload": payload,
    }
    target = SPIKE_DIR / f"recorded-{event_name(payload)}.jsonl"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:  # noqa: BLE001 - 同上：恒 exit 0
        print(f"[record-claude-hooks] 写入 {target} 失败：{exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
