"""数据外发链重建：在单次执行内找「读敏感文件 → 中转 → 外连」这条路径。

**这是路径级启发式，不是内容追踪。** 它证明的是"同一会话里先读了敏感文件、
后有到外部地址的连接"，不证明"这些字节被发出去了"。要做内容级需要端侧拦读写
内容，量级完全不同，这里明确不做——宁可把边界写清楚，也不给一个看起来更强的
错误结论。

为什么值得做：现有归因只回答"这个事件属于哪次调用"，回答不了"这次会话有没有
把东西送出去"。后者才是 Agent 安全真正要回答的问题。
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath

from services.ingestion_service import IngestError

VERSION = "dataflow-v1"

# 命中即视为"值得关注的数据源"。顺序无关，命中任意一个就算。
SENSITIVE_MARKERS = (
    # 目录级路径（~/.ssh）也要算：列一遍目录同样能看出有哪些密钥。
    ".ssh", "id_rsa", "id_ed25519", "id_ecdsa",
    ".aws/credentials", ".git-credentials", ".npmrc", ".pypirc",
    ".kube/config", ".docker/config.json", "keychain", "login data",
    ".env", "credentials", "cookies", "cookie.sqlite", "wallet.dat",
)

# 这些主机的连接不视为外发：包管理器、代码托管、以及内网/回环。
TRUSTED_HOSTS = (
    # 代码托管与包管理：日常构建必经，纳入白名单否则每次 push/install 都误报。
    "github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
    # 云厂商 API 与模型端点。
    "aws.amazon.com", "sts.amazonaws.com", "s3.amazonaws.com",
    "api.anthropic.com", "api.openai.com", "api.stepfun.com",
)
# 说明：白名单是"常见合法端点"的折中，不是安全边界。攻击者完全可以把数据推到
# 自己的 github 仓库或 S3 桶——这一点路径级判据无法区分，写进文档而不是假装解决。

TRUSTED_SUFFIXES = (".internal", ".local", ".localdomain", ".cluster.local")

# 这些工具是"往外发东西"的典型形态，用来给链路提高置信度。
EXFIL_COMMANDS = ("curl", "wget", "nc", "ncat", "scp", "sftp", "rsync", "httpie", "http ", "socat")

# 写类工具：路径级追踪无法知道内容流向哪个新文件，但"读了敏感文件之后又写出
# 新文件、随后外连"这一形态明显比"只读+外连"更可疑，用它来区分中/低置信度。
WRITE_TOOLS = ("write", "edit", "create", "save", "append", "modify", "compress", "zip", "tar")


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_sensitive(path: str) -> bool:
    lowered = str(path).lower()
    # 公钥（.pub）是公开材料，读它并联网是正常行为，不能算敏感源。
    if lowered.endswith(".pub"):
        return False
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def _is_external(host: str | None) -> bool:
    """判断连接目标是否在"外部"。宁可把内网判成外部也不要反过来。"""
    if not host:
        return False
    value = str(host).strip().lower()
    if value in ("localhost", "::1") or value.startswith("127."):
        return False
    if any(value.endswith(suffix) for suffix in TRUSTED_SUFFIXES):
        return False
    if value in TRUSTED_HOSTS:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        # 域名：不在信任名单里就算外部（企业域名应显式加入 TRUSTED_HOSTS）。
        return True
    # is_global 而不是 not is_private：文档保留段（192.0.2/198.51.100/203.0.113）
    # 在 Python 里算 private，但它们根本不可路由，不该当成外发终点。
    return address.is_global


def _basename(path: str) -> str:
    return PurePosixPath(str(path)).name


def _evidence(kind: str, uri: str) -> dict:
    return {"kind": kind, "uri": uri}


class DataFlowService:
    """按会话重建数据外发候选链；同一会话可产出多条。"""

    def __init__(self, storage) -> None:
        self.storage = storage

    def trace(self, execution_id: str) -> dict:
        with self.storage.connection() as conn:
            execution = conn.execute(
                "SELECT * FROM executions WHERE execution_id=?", (execution_id,)).fetchone()
            if not execution:
                raise IngestError("unknown_execution", 404)
            intents = [dict(row) for row in conn.execute(
                "SELECT intent_id,tool_name,occurred_at,params_summary FROM intents"
                " WHERE execution_id=? ORDER BY occurred_at", (execution_id,))]
            events = [dict(row) for row in conn.execute(
                "SELECT event_id,event_type,occurred_at,resource_host,resource_port,resource_path,pid"
                " FROM runtime_events WHERE execution_id=? AND event_type IN"
                " ('network_connect','file_access') ORDER BY occurred_at", (execution_id,))]
            # 真实采集里审计事件几乎都不带 execution_id（全库 18820 条只有 17 条有），
            # 按执行查会永远为空。退回"同主机 + 时间窗"，并如实标注依据——
            # 时间窗匹配的 sink 有可能属于同期别的进程，置信度要降级。
            sink_basis = "execution_id"
            if not events:
                started = str(execution["started_at"])
                # 事件带毫秒、intent 时间不带，直接用字符串当上界会把同一秒里
                # 毫秒更大的事件排除掉（13:02:46 < 13:02:46.357）。统一按时间戳
                # 计算并留 90 秒缓冲：进程退出、连接收尾通常晚于最后一次工具调用。
                last = max((datetime.fromisoformat(str(i["occurred_at"])) for i in intents),
                           default=datetime.fromisoformat(started))
                if execution["ended_at"]:
                    end_dt = datetime.fromisoformat(str(execution["ended_at"]))
                else:
                    end_dt = last + timedelta(seconds=90)
                ended = end_dt.isoformat()
                events = [dict(row) for row in conn.execute(
                    "SELECT event_id,event_type,occurred_at,resource_host,resource_port,resource_path,pid"
                    " FROM runtime_events WHERE host_id=? AND device_id=? AND occurred_at>=?"
                    " AND occurred_at<=? AND event_type IN ('network_connect','file_access')"
                    " ORDER BY occurred_at",
                    (execution["host_id"], execution["device_id"], started, ended))]
                sink_basis = "time_window"
            anchors = [dict(row) for row in conn.execute(
                "SELECT intent_id,occurred_at FROM intents WHERE execution_id=?", (execution_id,))]
        _ = anchors  # 保留查询以便后续做时间对齐扩展

        flows: list[dict] = []
        for index, intent in enumerate(intents):
            hints = self._hints(intent)
            sensitive = [hint for hint in hints if _is_sensitive(hint)]
            if not sensitive:
                continue
            for source_path in sensitive:
                flow = self._build(intent, source_path, intents[index + 1:], events, sink_basis)
                if flow:
                    flows.append(flow)
        return {"execution_id": execution_id, "version": VERSION,
                "sink_basis": sink_basis, "flows": flows, "note": self._note()}

    # --- 内部 ----------------------------------------------------------

    @staticmethod
    def _hints(intent: dict) -> list[str]:
        try:
            summary = json.loads(intent.get("params_summary") or "{}")
        except (ValueError, TypeError):
            return []
        if not isinstance(summary, dict):
            return []
        hints = summary.get("resource_hints")
        if not hints and summary.get("resource_hint"):
            hints = [summary["resource_hint"]]
        return [str(hint) for hint in (hints or [])]

    def _build(self, source_intent: dict, source_path: str,
               later_intents: list[dict], events: list[dict], sink_basis: str) -> dict | None:
        """从一次敏感读取出发，找中转跳与外部 sink。没有 sink 就不产链。"""
        source_time = str(source_intent["occurred_at"])
        name = _basename(source_path)

        hops = []
        for intent in later_intents:
            if str(intent["occurred_at"]) < source_time:
                continue
            hints = self._hints(intent)
            tool = str(intent.get("tool_name") or "")
            # 强中转：后续调用碰了同一个文件（同路径或同文件名）。
            same_file = bool(name) and any(
                hint == source_path or _basename(hint) == name for hint in hints)
            # 弱中转（staging）：读了敏感文件之后又写出新文件，内容可能被搬走。
            staging = (not same_file) and any(token in tool.lower() for token in WRITE_TOOLS) and bool(hints)
            if same_file or staging:
                hops.append({
                    "intent_id": intent["intent_id"],
                    "tool_name": intent["tool_name"],
                    "role": "same_file" if same_file else "staging",
                    "occurred_at": intent["occurred_at"],
                    "paths": hints[:4],
                    "evidence_refs": [_evidence("intent", intent["intent_id"])],
                })

        sinks = []
        for event in events:
            if event["event_type"] != "network_connect":
                continue
            if str(event["occurred_at"]) < source_time:
                continue
            if not _is_external(event.get("resource_host")):
                continue
            sinks.append(event)

        if not sinks:
            # 读了私钥但没有外部连接：不是外发链。宁可漏报也不误报。
            return None

        # 置信度：有中转跳、或读取动作本身是外发类命令，才升到 medium。
        tool = str(source_intent.get("tool_name") or "")
        command_like = any(token in tool for token in EXFIL_COMMANDS)
        confidence = "medium" if (hops or command_like) else "low"
        if sink_basis == "time_window" and confidence == "medium":
            # sink 只是"同一时间窗内这台机器的某个连接"，可能不属于本次执行，
            # 那么强结论就站不住——降一级，而不是继续按 medium 报。
            confidence = "low"

        sink = sinks[0]
        evidence = [_evidence("intent", source_intent["intent_id"]),
                    _evidence("file_access", source_path)]
        evidence.extend(item["evidence_refs"][0] for item in hops)
        evidence.append(_evidence("network_connect", sink["event_id"]))

        return {
            "flow_id": "flow_" + uuid.uuid4().hex,
            "execution_id": source_intent.get("execution_id"),
            "source": {"intent_id": source_intent["intent_id"], "path": source_path,
                       "tool_name": source_intent["tool_name"],
                       "occurred_at": source_intent["occurred_at"]},
            "hops": hops,
            "sink": {"host": sink.get("resource_host"), "port": sink.get("resource_port"),
                     "event_id": sink["event_id"], "occurred_at": sink["occurred_at"]},
            "sink_count": len(sinks),
            "sink_basis": sink_basis,
            "confidence": confidence,
            "evidence_refs": evidence,
            "detected_at": now(),
        }

    @staticmethod
    def _note() -> str:
        return ("路径级启发式：同一会话内先读敏感文件、后连外部地址；"
                "不证明内容被发送。内网与已知可信域名不计入外发。")
