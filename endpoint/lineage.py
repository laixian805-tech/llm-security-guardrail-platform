"""端侧只读 Transcript 谱系推导（无第三方依赖、无网络、不外传对话原文）。

依据控制面 SourceKind 契约：
  user_task | workspace_config | installed_skill | mcp_server | tool_output | unknown
优先尊重显式实验室标签环境变量 ASGP_SOURCE_KIND / ASGP_SOURCE_REF；否则只读解析
Claude Code / Qwen Code / Codex 的本地 transcript_path（有界读取尾部内容），根据
最近真实用户指令之后是否经过外部工具输出、工作区规则文件、已安装 Skill 或 MCP 工具
调用链路推导当前工具调用的指令来源类别，并输出脱敏后的结构化 source_ref。
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

VALID_SOURCE_KINDS = frozenset({
    "user_task",
    "workspace_config",
    "installed_skill",
    "mcp_server",
    "tool_output",
    "unknown",
})

_SAFE_TOKEN = re.compile(r"[^A-Za-z0-9_.:-]+")
_SKILL_CMD_RE = re.compile(r"<(?:command-name|skill-name)>/?([A-Za-z0-9_.:-]+)</(?:command-name|skill-name)>")
_SKILL_PATH_RE = re.compile(r"(?:^|/)skills/([^/]+)/SKILL\.md$", re.IGNORECASE)
_WORKSPACE_CONFIG_NAMES = frozenset({
    "claude.md", "agents.md", "qwen.md", ".mcp.json",
    "mcp.json", "settings.json", "settings.local.json", "config.toml",
})


def _sanitize_token(value: Any, fallback: str = "unknown") -> str:
    text = _SAFE_TOKEN.sub("_", str(value or "").strip()).strip("_")
    return text[:64] or fallback


def _extract_path_hint(params: Any) -> str | None:
    if not isinstance(params, dict):
        return None
    for key in ("file_path", "path", "target_file", "filename", "file"):
        val = params.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip().replace("\\", "/")
    return None


def _classify_tool_artifact(tool_name: str, params: Any = None) -> tuple[str, str] | None:
    """判定工具或参数路径本身是否属于高风险供给链来源（MCP / Skill / 工作区配置）。"""
    name = (tool_name or "").strip()
    lowered = name.lower()
    if lowered.startswith("mcp__"):
        parts = name.split("__")
        server = _sanitize_token(parts[1] if len(parts) > 1 else "server")
        return "mcp_server", f"mcp:{server}"
    if lowered in ("skill", "invoke_skill", "use_skill", "activate_skill"):
        skill_name = ""
        if isinstance(params, dict):
            skill_name = params.get("skill") or params.get("name") or params.get("command") or ""
        return "installed_skill", f"skill:{_sanitize_token(skill_name, 'skill')}"
    path_hint = _extract_path_hint(params)
    if path_hint:
        skill_match = _SKILL_PATH_RE.search(path_hint)
        if skill_match:
            return "installed_skill", f"skill:{_sanitize_token(skill_match.group(1), 'skill')}"
        base = Path(path_hint).name.lower()
        if base in _WORKSPACE_CONFIG_NAMES or "/.claude/rules/" in path_hint.lower():
            return "workspace_config", f"config:{_sanitize_token(Path(path_hint).name, 'config')}"
    return None


def _read_bounded_lines(path_str: str, max_bytes: int) -> list[str]:
    path = Path(path_str)
    try:
        st = path.stat()
    except OSError:
        return []
    if not path.is_file() or st.st_size <= 0:
        return []
    try:
        with path.open("rb") as fh:
            if st.st_size > max_bytes:
                fh.seek(st.st_size - max_bytes)
                raw = fh.read(max_bytes)
                nl = raw.find(b"\n")
                if nl != -1:
                    raw = raw[nl + 1:]
            else:
                raw = fh.read(max_bytes)
        return raw.decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _parse_json_dict(raw: Any) -> Any:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else None
        except ValueError:
            return None
    return None


def _extract_claude_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        chunks = [
            c.get("text", "")
            for c in content
            if isinstance(c, dict) and c.get("type") == "text" and isinstance(c.get("text"), str)
        ]
        return "\n".join(chunks)
    return ""


def _iter_transcript_steps(product: str, lines: list[str], target_call_id: str | None):
    """把三款产品的 JSONL 记录统一归约成按时间顺序的事件步骤流。

    若遇到 target_call_id 对应的 tool_use，立即停止，确保同一调用的 Pre/Post 共享一致前置语境。
    """
    seen_calls: dict[str, tuple[str, Any]] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if not isinstance(obj, dict):
            continue

        # 1) Claude Code JSONL（优先排除含 provenance 的 Qwen 记录）
        if "provenance" not in obj and obj.get("type") != "response_item" and (product == "claude-code" or ("message" in obj and obj.get("type") in ("user", "assistant"))):
            rec_type = obj.get("type")
            msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
            content = msg.get("content")
            if rec_type == "user":
                if isinstance(content, list) and any(isinstance(b, dict) and b.get("type") == "tool_result" for b in content):
                    for block in content:
                        if isinstance(block, dict) and block.get("type") == "tool_result":
                            cid = str(block.get("tool_use_id") or "")
                            tname, _ = seen_calls.get(cid, ("tool", {}))
                            yield ("tool_result", cid, tname)
                else:
                    text = _extract_claude_text(content)
                    m = _SKILL_CMD_RE.search(text)
                    if m:
                        yield ("skill", f"skill:{_sanitize_token(m.group(1))}")
                    elif text.strip():
                        yield ("user", f"transcript:{product}:user_turn")
            elif rec_type == "assistant" and isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        cid = str(block.get("id") or "")
                        if target_call_id and cid == target_call_id:
                            return
                        tname = str(block.get("name") or "tool")
                        tinput = block.get("input") if isinstance(block.get("input"), dict) else {}
                        seen_calls[cid] = (tname, tinput)
                        yield ("tool_use", cid, tname, tinput)
            continue

        # 2) Qwen Code JSONL
        if product == "qwen-code" or "provenance" in obj:
            prov = obj.get("provenance")
            rec_type = obj.get("type")
            msg = obj.get("message") if isinstance(obj.get("message"), dict) else {}
            parts = msg.get("parts") if isinstance(msg.get("parts"), list) else []
            if rec_type == "user" or prov == "real_user":
                text = "".join(str(p.get("text") or "") for p in parts if isinstance(p, dict))
                m = _SKILL_CMD_RE.search(text)
                if m:
                    yield ("skill", f"skill:{_sanitize_token(m.group(1))}")
                else:
                    yield ("user", f"transcript:{product}:user_turn")
            elif prov == "assistant_output" or rec_type == "assistant":
                for part in parts:
                    if isinstance(part, dict) and isinstance(part.get("functionCall"), dict):
                        fc = part["functionCall"]
                        cid = str(fc.get("id") or "")
                        if target_call_id and cid == target_call_id:
                            return
                        tname = str(fc.get("name") or "tool")
                        targs = _parse_json_dict(fc.get("args")) or {}
                        seen_calls[cid] = (tname, targs)
                        yield ("tool_use", cid, tname, targs)
            elif rec_type == "tool_result" or prov == "tool_result":
                tcr = obj.get("toolCallResult") if isinstance(obj.get("toolCallResult"), dict) else {}
                cid = str(tcr.get("callId") or "")
                tname = None
                if not cid:
                    for part in parts:
                        if isinstance(part, dict) and isinstance(part.get("functionResponse"), dict):
                            fr = part["functionResponse"]
                            cid = str(fr.get("id") or "")
                            tname = fr.get("name")
                            break
                resolved_name = str(tname or seen_calls.get(cid, ("tool", {}))[0])
                yield ("tool_result", cid, resolved_name)
            continue

        # 3) Codex JSONL
        if obj.get("type") == "response_item":
            pl = obj.get("payload") if isinstance(obj.get("payload"), dict) else {}
            pt = pl.get("type")
            if pt == "message" and pl.get("role") == "user":
                content = pl.get("content")
                text = ""
                if isinstance(content, list):
                    text = "\n".join(str(b.get("text") or "") for b in content if isinstance(b, dict))
                elif isinstance(content, str):
                    text = content
                stripped = text.strip()
                if stripped and not stripped.startswith("<environment_context>"):
                    m = _SKILL_CMD_RE.search(stripped)
                    if m:
                        yield ("skill", f"skill:{_sanitize_token(m.group(1))}")
                    else:
                        yield ("user", f"transcript:{product}:user_turn")
            elif pt in ("function_call", "custom_tool_call", "mcp_tool_call"):
                cid = str(pl.get("call_id") or "")
                if target_call_id and cid == target_call_id:
                    return
                tname = str(pl.get("name") or (f"mcp__{pl.get('server') or 'server'}__tool" if pt == "mcp_tool_call" else "tool"))
                targs = _parse_json_dict(pl.get("arguments")) or {}
                seen_calls[cid] = (tname, targs)
                yield ("tool_use", cid, tname, targs)
            elif pt in ("function_call_output", "custom_tool_call_output"):
                cid = str(pl.get("call_id") or "")
                tname, _ = seen_calls.get(cid, ("tool", {}))
                yield ("tool_result", cid, tname)


def infer_lineage(
    product: str,
    payload: dict[str, Any],
    *,
    tool_call_id: str | None = None,
    max_bytes: int = 262144,
) -> tuple[str | None, str | None]:
    """推导工具调用的来源谱系 (source_kind, source_ref)，绝不返回原始文本或凭据。"""
    env_kind = (os.environ.get("ASGP_SOURCE_KIND") or "").strip()
    env_ref = (os.environ.get("ASGP_SOURCE_REF") or "").strip() or None
    if env_kind:
        if env_kind in VALID_SOURCE_KINDS:
            return env_kind, env_ref
        return "unknown", env_ref

    tool_name = str(payload.get("tool_name") or "")
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}

    # 若当前工具调用本身直指 MCP 工具或 Skill/工作区敏感规则，优先标明供给链来源。
    direct = _classify_tool_artifact(tool_name, tool_input)
    if direct is not None:
        return direct

    transcript_path = payload.get("transcript_path")
    if isinstance(transcript_path, str) and transcript_path.strip():
        lines = _read_bounded_lines(transcript_path.strip(), max_bytes=max_bytes)
        if lines:
            current: tuple[str, str] | None = None
            calls: dict[str, tuple[str, Any]] = {}
            resolved_call_id = tool_call_id or payload.get("tool_call_id") or payload.get("tool_use_id")
            try:
                for step in _iter_transcript_steps(product, lines, resolved_call_id):
                    kind = step[0]
                    if kind == "user":
                        current = ("user_task", step[1])
                    elif kind == "skill":
                        current = ("installed_skill", step[1])
                    elif kind == "tool_use":
                        _, cid, tname, targs = step
                        calls[cid] = (tname, targs)
                    elif kind == "tool_result":
                        _, cid, tname = step
                        targs = calls.get(cid, (tname, {}))[1]
                        artifact = _classify_tool_artifact(tname, targs)
                        if artifact is not None:
                            current = artifact
                        else:
                            current = ("tool_output", f"tool_output:{_sanitize_token(tname, 'tool')}")
            except Exception:
                return None, None
            if current is not None:
                return current

    return None, None
