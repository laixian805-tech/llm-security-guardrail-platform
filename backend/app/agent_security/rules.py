from __future__ import annotations

from dataclasses import dataclass

from .models import SecurityAction, Severity


@dataclass(frozen=True)
class DetectionRule:
    """One entry of the detection catalog.

    ``layer=static`` rules are applied by the extension scanner before
    anything executes; ``layer=runtime`` rules are applied by the runtime
    guard (hook) and the behavior monitor. Two series live in this module:

    - ``S01``-``S28``: the 28-rule / 8-category static catalog
      (``RULES``), auditable as one coverage matrix.
    - ``R001``-``R005``: the first-version runtime rules (``RUNTIME_RULES``,
      landing doc 11.2) that the Linux/WSL2 V1 demo is built around.
    """

    rule_id: str
    name: str
    category: str
    layer: str            # static | runtime
    kind: str             # regex | structural
    severity: Severity
    action: SecurityAction
    targets: tuple[str, ...]
    pattern: str = ""
    message: str = ""


CATEGORY_LABELS: dict[str, str] = {
    "A": "指令投毒与隐藏指令",
    "B": "危险命令执行",
    "C": "敏感文件与凭证访问",
    "D": "数据外发与隐蔽外联",
    "E": "MCP 越权与恶意工具",
    "F": "供应链与依赖风险",
    "G": "Hook 与配置篡改",
    "H": "进程与环境异常",
}

_R = DetectionRule

RULES: tuple[DetectionRule, ...] = (
    # A 指令投毒与隐藏指令
    _R("S01", "hidden_instruction", "A", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp"),
       r"(<!--[\s\S]{0,300}?(ignore|instruction|system|assistant|tool)[\s\S]{0,300}-->)|([\u200b\u200c\u200d\u2060\ufeff])",
       "HTML 注释或零宽字符中隐藏指令"),
    _R("S02", "instruction_override", "A", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp", "hook"),
       r"(?i)(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?)",
       "指令覆盖模式"),
    _R("S03", "mcp_tool_description_poisoning", "A", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("mcp",),
       r"(?i)(you\s+(must|should|shall)\s|always\s+call\s|do\s+not\s+tell\s+the\s+user|without\s+(asking|telling|informing)\s+the\s+user)",
       "MCP 工具描述中含诱导模型执行的语句"),
    # B 危险命令执行
    _R("S04", "destructive_command", "B", "static", "regex", Severity.CRITICAL, SecurityAction.BLOCK,
       ("skill", "mcp", "hook"),
       r"(?i)(\brm\s+(-[a-z]+\s+)*-[a-z]*[rf][a-z]*\s+(/|~|\*|\$home))|(\b(mkfs|shred|wipefs)\b[^\n]{0,60}/dev/)"
       r"|(\bdd\s+[^\n]{0,60}of=/dev/)",
       "破坏性命令"),
    _R("S05", "remote_script_exec", "B", "static", "regex", Severity.CRITICAL, SecurityAction.BLOCK,
       ("skill", "mcp", "hook"),
       r"(?i)(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh)\b",
       "下载远程脚本并直接执行"),
    _R("S06", "privilege_escalation", "B", "static", "regex", Severity.HIGH, SecurityAction.ASK,
       ("skill", "mcp", "hook"),
       r"(?i)(\bsudo\b)|(chmod\s+[0-7]*[4567][0-7]{3})|(\bsetcap\b)",
       "权限提升行为"),
    _R("S07", "reverse_shell", "B", "static", "regex", Severity.CRITICAL, SecurityAction.BLOCK,
       ("skill", "mcp", "hook"),
       r"(/dev/tcp/)|(\bnc(at)?\s+(-[a-z]+\s+)*-e\b)|(\bsocat\b[^\n]{0,80}exec)|(bash\s+-i\s*>&)|(python[0-9.]*\s+-c[^\n]{0,80}socket)",
       "反弹 shell 特征"),
    # C 敏感文件与凭证访问
    _R("S08", "sensitive_file_read", "C", "static", "regex", Severity.CRITICAL, SecurityAction.BLOCK,
       ("skill", "mcp", "hook"),
       r"(~/\.ssh/|\.ssh/id_|\.env\b|\.aws/credentials|\.kube/config|id_rsa|id_ed25519|\.netrc\b|\.pgpass\b"
       r"|secrets?\.(ya?ml|json|env)\b|/etc/shadow\b)",
       "敏感文件或凭证路径"),
    _R("S09", "sensitive_archive", "C", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp", "hook"),
       r"(?i)\b(tar|zip|7z|gzip|bzip2)\b[^\n]{0,120}(\.ssh|\.aws|\.env|secrets?|src/|sources?/|repo)",
       "打包敏感目录"),
    _R("S10", "credential_exfil", "C", "static", "regex", Severity.CRITICAL, SecurityAction.BLOCK,
       ("skill", "mcp", "hook"),
       r"(?i)(cat|type|less|head|tail|cp)\s+[^\n|]{0,80}(\.env|\.ssh|credentials|id_rsa|secret)[^\n|]{0,80}"
       r"\|\s*(curl|wget|nc|ncat)\b",
       "读取凭证并管道外传"),
    # D 数据外发与隐蔽外联
    _R("S11", "risky_domain", "D", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp", "hook"),
       r"(?i)\b(pastebin\.com|transfer\.sh|ngrok\.io|webhook\.site|requestbin|interact\.sh"
       r"|discord(app)?\.com/api/webhooks)\b",
       "高风险外联域名"),
    _R("S12", "encoded_exfil", "D", "static", "regex", Severity.MEDIUM, SecurityAction.ALERT,
       ("skill", "mcp", "hook"),
       r"(?i)(base64\s+(-d|--decode)|base64\.b64decode)[^\n]{0,100}(\||curl|wget|bash|sh|nc)\b",
       "编码后外传"),
    # E MCP 越权与恶意工具（结构检查在 scanner 实现）
    _R("S13", "unregistered_mcp_server", "E", "static", "structural", Severity.HIGH, SecurityAction.ALERT,
       ("mcp",), "", "MCP Server 不在可信 Registry"),
    _R("S14", "mcp_fs_scope", "E", "static", "structural", Severity.HIGH, SecurityAction.BLOCK,
       ("mcp",), "", "filesystem MCP 授予过宽根目录"),
    _R("S15", "mcp_tool_arg_anomaly", "E", "static", "structural", Severity.HIGH, SecurityAction.BLOCK,
       ("mcp",), "", "MCP 参数异常：路径穿越或内联密钥"),
    # F 供应链与依赖风险
    _R("S16", "untrusted_source", "F", "static", "structural", Severity.MEDIUM, SecurityAction.ALERT,
       ("skill", "mcp", "deps"), "", "来源不在可信 Registry"),
    _R("S17", "hash_drift", "F", "static", "structural", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp", "deps", "hook"), "", "已登记资产 Hash 漂移"),
    _R("S18", "unpinned_dependency", "F", "static", "structural", Severity.MEDIUM, SecurityAction.ALERT,
       ("deps",), "", "依赖未固定版本或疑似 typosquat 包名"),
    _R("S19", "postinstall_script", "F", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("deps",),
       r"(?i)\"(pre|post)?install\"\s*:\s*\"[^\"]*(curl|wget|bash|sh\b|python|node|powershell)",
       "安装期脚本执行外部命令"),
    _R("S20", "runtime_download", "F", "static", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("skill", "mcp"),
       r"(?i)(curl|wget|invoke-webrequest|iwr|urllib\.request\.urlopen|requests\.get)[^\n]{0,140}"
       r"(\.sh\b|\.py\b|\.ps1\b|\.exe\b|payload|/tmp/|/var/tmp/)",
       "运行时二次下载载荷"),
    # G Hook 与配置篡改
    _R("S21", "hook_config_tamper", "G", "static", "structural", Severity.CRITICAL, SecurityAction.ALERT,
       ("hook",), "", "Hook 配置引用未登记回调或回调命令可疑"),
    _R("S22", "hook_script_change", "G", "static", "structural", Severity.CRITICAL, SecurityAction.ALERT,
       ("hook",), "", "Hook 回调脚本与基线 Hash 不一致"),
    _R("S23", "guard_offline", "G", "runtime", "structural", Severity.HIGH, SecurityAction.ALERT,
       ("guard",), "", "Guard 心跳超时或失联"),
    # H 进程与环境异常
    _R("S24", "unknown_subprocess", "H", "runtime", "structural", Severity.MEDIUM, SecurityAction.AUDIT,
       ("process",), "", "Agent 派生未知子进程"),
    _R("S25", "prod_host_session", "H", "runtime", "structural", Severity.CRITICAL, SecurityAction.ASK,
       ("session",), "", "生产标记主机上出现 Agent 会话"),
    _R("S26", "db_cli_direct", "H", "runtime", "regex", Severity.HIGH, SecurityAction.ALERT,
       ("process",),
       r"(?i)\b(psql|mysql|mongo|mongosh|redis-cli|sqlite3)\b",
       "数据库 CLI 直连"),
    _R("S27", "cloud_destructive_op", "H", "runtime", "regex", Severity.CRITICAL, SecurityAction.ASK,
       ("process",),
       r"(?i)\b(kubectl\s+delete|terraform\s+destroy|helm\s+uninstall|aws\s+s3\s+rm|gcloud\b[^\n]{0,60}delete"
       r"|aliyun\b[^\n]{0,60}delete)\b",
       "云平台高危操作"),
    _R("S28", "orphan_session", "H", "runtime", "structural", Severity.MEDIUM, SecurityAction.AUDIT,
       ("session",), "", "进程无法关联到 Agent 会话"),
)

RULES_BY_ID: dict[str, DetectionRule] = {rule.rule_id: rule for rule in RULES}


# ---------------------------------------------------------------------------
# V1 runtime detection rules (landing doc 11.2, first Linux/WSL2 release)
# ---------------------------------------------------------------------------

RUNTIME_RULES: tuple[DetectionRule, ...] = (
    _R("R001", "ssh_private_key_access", "C", "runtime", "regex",
       Severity.HIGH, SecurityAction.BLOCK, ("path",),
       r"(\.ssh/|\.ssh$|id_rsa|id_ed25519|id_ecdsa|id_dsa)",
       "Agent 访问 SSH 私钥"),
    _R("R002", "cloud_credential_access", "C", "runtime", "regex",
       Severity.HIGH, SecurityAction.BLOCK, ("path",),
       r"(\.aws/credentials|\.aws/config|\.kube/config|\.gnupg/|\.azure/"
       r"|gcloud/credentials|\.docker/config\.json|\.netrc|\.pgpass|\.config/gcloud)",
       "Agent 读取云凭据"),
    _R("R003", "unapproved_network_tool", "D", "runtime", "regex",
       Severity.MEDIUM, SecurityAction.ASK, ("process",),
       r"\b(curl|wget|nc|ncat|netcat|socat|telnet|ftp|sftp|scp|ssh|rsync)\b",
       "Agent 启动未批准的网络工具"),
    _R("R004", "unapproved_mcp_tool", "E", "runtime", "structural",
       Severity.HIGH, SecurityAction.BLOCK, ("tool",), "",
       "Agent 调用未批准 MCP 工具"),
    _R("R005", "sensitive_read_then_exfil", "D", "runtime", "structural",
       Severity.CRITICAL, SecurityAction.ALERT, ("session",), "",
       "敏感文件读取后出现异常外联"),
)

RUNTIME_RULES_BY_ID: dict[str, DetectionRule] = {
    rule.rule_id: rule for rule in RUNTIME_RULES
}


def runtime_rule_ids() -> list[str]:
    return [rule.rule_id for rule in RUNTIME_RULES]


def rule_ids() -> list[str]:
    return [rule.rule_id for rule in RULES]


def static_rules(target: str) -> list[DetectionRule]:
    """Static scanner rules applicable to a target kind."""
    return [rule for rule in RULES if rule.layer == "static" and target in rule.targets]


def structural_rule_ids(target: str) -> set[str]:
    return {rule.rule_id for rule in static_rules(target) if rule.kind == "structural"}


def rule_by_id(rule_id: str) -> DetectionRule | None:
    return RULES_BY_ID.get(rule_id) or RUNTIME_RULES_BY_ID.get(rule_id)
