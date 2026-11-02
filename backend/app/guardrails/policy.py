from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal


PolicyIntent = Literal[
    "benign_business",
    "benign_security_education",
    "benign_rag_query",
    "benign_low_risk_tool_request",
    "instruction_override",
    "prompt_or_policy_extraction",
    "role_takeover",
    "rag_or_web_poisoning",
    "tool_return_poisoning",
    "unauthorized_tool_escalation",
    "attack_generation",
    "uncertain",
]
PolicyRiskTier = Literal["allow", "audit", "block", "escalate"]
PolicyAction = Literal["allow", "audit", "block", "escalate"]


@dataclass(frozen=True)
class PolicyDecision:
    intent: PolicyIntent
    risk_tier: PolicyRiskTier
    action: PolicyAction
    confidence: float
    matched_signals: list[str] = field(default_factory=list)
    reason: str = ""
    rule_name: str | None = None
    policy_score: float = 0.0
    risk_score: int = 0
    classifier: dict[str, object] = field(default_factory=dict)

    def model_dump(self) -> dict[str, object]:
        return {
            "intent": self.intent,
            "risk_tier": self.risk_tier,
            "action": self.action,
            "confidence": round(self.confidence, 4),
            "matched_signals": list(self.matched_signals),
            "reason": self.reason,
            "rule_name": self.rule_name,
            "policy_score": round(self.policy_score, 4),
            "risk_score": self.risk_score,
            "classifier": dict(self.classifier),
        }


_DEFENSIVE_CONTEXT = re.compile(
    r"\b(explain|why|risky|risk|training|defen[cs]ive|mitigat(?:e|ion)|prevent|security\s+review|review)\b"
    r"|\b(?:analy[sz]e|analysis)\b.{0,80}\b(prompt\s+injection|jailbreak|risk|defen[cs]ive|security|bypass)\b"
    r"|\b(prompt\s+injection|jailbreak|risk|defen[cs]ive|security|bypass)\b.{0,80}\b(?:analy[sz]e|analysis)\b"
    r"|安全(?:分析|评估|培训|防御)|防御|风险|为什么",
    re.I,
)
_NEGATED_BYPASS = re.compile(r"\b(do\s+not|don't|without|avoid)\b.{0,80}\b(bypass|exploit|payload|attack\s+steps?)\b", re.I)
_QUOTED_ATTACK_PHRASE = re.compile(
    r"(['\"`“”‘’])\s*(ignore\s+(?:all\s+)?previous\s+instructions?|忽略之前所有限制|忽略之前的指令)\s*\1",
    re.I,
)
_LOW_RISK_TOOL = re.compile(
    r"\b(policy_lookup|search_kb|report_lookup|user_info|calculator|translation\s*tool|weather\s*tool|calendar\s*tool)\b"
    r"|übersetzungstool|traduction|outil\s+météo|herramienta\s+de\s+calendario|herramienta\s+de\s+traducci[oó]n",
    re.I,
)
_SELF_SERVICE_MFA = re.compile(
    r"\b(reset|view|configure|update|recover)\b.{0,80}\b(my|own|my\s+account)\b.{0,80}\b(mfa|2fa|multi-factor|two-factor)\b"
    r"|\b(my|own|my\s+account)\b.{0,80}\b(mfa|2fa|multi-factor|two-factor)\b",
    re.I,
)
_HIGH_RISK_TOOL = re.compile(
    r"\b(export_data|export_internal_reports|export_reports|admin\s+export|export\s+tool|read_system_files|"
    r"bulk_download_customer_data|emergency_data_wipe|install_backdoor|delete_all_users|export_financial_data|reset_system|"
    r"disable_security_alerts|grant_admin_access|disable_firewall|reset_all_passwords|factory_reset|db_export|diagnostic_tool|"
    r"medical_records|clear_logs|send_marketing_spam|show_config|reset\s+(?:all\s+)?(?:user\s+)?mfa)\b"
    r"|敏感数据导出工具|客户数据|重置所有用户\s*MFA|listar_credenciales|afficher_mots_de_passe",
    re.I,
)
_AUTH_BYPASS = re.compile(
    r"\b(role\s*=\s*admin|bypass|without\s+(?:permission|authorization)|skip\s+(?:permission|authorization|verification)|"
    r"no\s+verification|omitt?ing\s+(?:any\s+)?verification|check\s+with\s+me\s+later|public\s+role|"
    r"sin\s+restricciones|omitiendo\s+cualquier\s+verificaci[oó]n|keine\s+verifikation|"
    r"ne\s+v[ée]rifiez\s+pas\s+les\s+permissions)\b"
    r"|绕过|访问控制|权限校验|不要再做权限|不需要验证",
    re.I,
)
_AUTHORIZATION_TOKEN = re.compile(
    r"\b(?:authorization|audit|access)\s+token\b|\bAUTH-[A-Z0-9-]{4,}\b",
    re.I,
)
_AUTHORIZED_REPORT_EXPORT = re.compile(
    r"\b(quarterly\s+audit|internal\s+security\s+reports?|export_reports)\b.{0,180}\b(token|AUTH-[A-Z0-9-]{4,})\b"
    r"|\b(token|AUTH-[A-Z0-9-]{4,})\b.{0,180}\b(quarterly\s+audit|internal\s+security\s+reports?|export_reports)\b",
    re.I,
)
_DESTRUCTIVE_OR_EXFIL_OBJECTIVE = re.compile(
    r"\b(wipe|delete|remove|purge|disable|deactivate|drop|reset|install\s+(?:a\s+)?(?:monitoring\s+)?backdoor|"
    r"read\s+(?:the\s+)?(?:root|system)\s+(?:file|files|filesystem)|bulk\s+download|"
    r"customer\s+data|user\s+data|production\s+data|external\s+(?:server|url)|all\s+user\s+accounts|"
    r"security\s+protocols?|security\s+alerts?|admin\s+access|monitoring|authentication\s+systems?|two-factor|2fa|mfa|logs?|"
    r"credentials?|passwords?|access\s+tokens?|wire\s+transfer|bank(?:ing)?\s+transfer|transfer\s+all\s+funds|financial\s+data|"
    r"medical\s+records?|confidential\s+document|phishing\s+email|termination\s+emails?|marketing\s+spam|competitor\.com|"
    r"drop\s+table|clear\s+logs?|delete_all_users|export_financial_data|reset_system|disable_firewall|reset_all_passwords|"
    r"factory\s+reset|factory_reset|/admin/delete_users|db_export|diagnostic_tool|show_config)\b"
    r"|删除|抹除|导出|传输|外部服务器|客户数据|用户数据|所有用户|禁用|关闭|重置|访问控制|"
    r"supprimer|suppression|d[ée]sactiver|journaux|surveillance|"
    r"ejecuta|ejecutar|transferir|cuenta\s+de\s+rescate|correo\s+masivo|oferta\s+falsa|credenciales|"
    r"sistema\s+de\s+archivos\s+ra[ií]z|privilegios\s+de\s+administrador|reenviar|documento\s+confidencial|"
    r"\bzur[uü]ck\b|\bsetzen\b|deaktivieren|authentifizierungssysteme|zwei-faktor|logdateien|"
    r"benutzerdaten|zugangsdaten|konto\s+gesperrt|"
    r"virement\s+bancaire|virer\s+\d|compte\s+(?:personnel|des\s+ravisseurs)|outil\s+comptable|mots\s+de\s+passe|contacts",
    re.I,
)
_HIGH_RISK_EXECUTION = re.compile(
    r"\b(call|use|run|execute|send|export|transmit|wipe|delete|disable|reset|install|read)\b"
    r"|调用|执行|导出|传输|删除|禁用|重置|appeler|ex[ée]cutez|ejecuta|virer|\bsetzen\b|deaktivieren|senden|exportieren",
    re.I,
)
_SOURCE_WORD = (
    r"(retrieved|knowledge\s+base|document|context|chunk|web\s+page|webpage|tool\s+(?:returned|result|output)|"
    r"tool\s+output|report\s+tool\s+output|(?:payment\s+)?api\s+returned|api\s+response|"
    r"api\s+de\s+(?:pagos|b[uú]squeda)\s+devolvi[oó]|die\s+analyse\s+zeigt|rapport|recuper[ée]\s+este\s+fragmento|"
    r"el\s+doc\s+dice|aus\s+dem\s+dokument|(?:das\s+)?support[-\s]?tool\s+sagt|api-systemmeldung|"
    r"translate\s+this|[üu]bersetze)"
)
_SOURCE_CONTROL = re.compile(
    rf"\b{_SOURCE_WORD}\b.{{0,220}}\b(ignore|override|export|reveal|dump|follow|use\s+the\s+retrieved\s+instruction|new\s+instruction|"
    rf"to\s+proceed|execute|list\s+all\s+user\s+credentials|send\s+to|wire\s+transfer|drop\s+table|transaction\s+approved|"
    rf"delete|revoke|confidential|phishing|termination|diagnostic_tool|db_export|system\s+prompt|"
    rf"exportieren|benutzerdaten|wartungsmodus|zugangsdaten|senden\s+sie|fake@domain\.com)\b"
    rf"|\b(use\s+the\s+retrieved\s+instruction|follow\s+the\s+(?:retrieved|tool|web)\s+instruction)\b"
    r"|工具返回.{0,180}(新指令|调用|导出|发送|外部|删除|禁用|重置)"
    r"|outil\s+renvoy[ée].{0,180}(nouvelle\s+instruction|appeler|supprimer|d[ée]sactiver|journaux|surveillance)"
    r"|(?:herramienta|api\s+de\s+(?:pagos|b[uú]squeda))\s+(?:devolvi[oó]|retorn[oó]).{0,180}(nueva\s+instrucci[oó]n|instrucci[oó]n|ejecuta|exporta|omite|transferir|transacci[oó]n\s+aprobada|correo\s+masivo|oferta\s+falsa)"
    r"|die\s+analyse\s+zeigt.{0,180}(logdateien|l[oö]schen|admin@|senden)"
    r"|rapport.{0,180}(note\s+secr[eè]te|ex[ée]cuter|nettoyage\s+complet)"
    r"|(?:recuper[ée]\s+este\s+fragmento|el\s+doc\s+dice).{0,180}(reenviar|ejecute|env[ií]e|externo|confidencial|diagnostic_tool)"
    r"|aus\s+dem\s+dokument.{0,180}(system-prompt|ausgeben|befolgen)"
    r"|werkzeug.{0,80}(zur[uü]ck|r[uü]ckgabe).{0,180}(neue\s+anweisung|ausf[uü]hren|exportieren)"
    r"|(?:das\s+)?support[-\s]?tool\s+sagt.{0,180}(senden\s+sie|zugangsdaten|fake@domain\.com|konto\s+gesperrt)",
    re.I,
)
_RAG_POLICY_OVERRIDE = re.compile(
    r"\b(retrieved|document|context|chunk)\b.{0,140}\boverride\s+policy\b",
    re.I,
)
_BENIGN_RAG = re.compile(
    r"\b(using|use|with|from)\b.{0,80}\b(retrieved|handbook|content|document)\b.{0,120}"
    r"\b(summarize|compare|list|answer|requirements?)\b",
    re.I,
)
_ATTACK_GENERATION = re.compile(
    r"\b(add|generate|create|write|provide)\b.{0,80}"
    r"\b(paraphrase(?:d)?|multi-turn|translated|translation)\b.{0,120}"
    r"\b(variants?|probes?|payloads?|attack\s+set)\b",
    re.I,
)
_PROMPT_SECRET = re.compile(
    r"\b(repeat|reveal|print|show|dump|output|disclose)\b.{0,120}"
    r"\b(system|hidden|developer|internal|confidential|initial)\b.{0,80}"
    r"\b(prompt|instruction|message|policy|rules?|keys?|constraints?)\b"
    r"|\b(system|hidden|developer)\s+prompt\b"
    r"|\b(exact\s+initial\s+prompt|initial\s+prompt|initial\s+instructions?|system\s+instructions?|full\s+system\s+instructions?|system\s+messages?|hidden\s+instructions?|security\s+rules?)\b"
    r"|\brepeat\s+everything\s+above\s+this\s+line\b"
    r"|\b(mu[eé]strame|m[uú]estrame|mostrar|repite|repetir|cu[eé]ntame)\b.{0,120}\b(instrucciones\s+iniciales|reglas\s+de\s+seguridad|prompt\s+(?:inicial|del\s+sistema|sistema))\b"
    r"|\b(system-prompt|système|invite\s+syst[eè]me|prompt\s+del\s+sistema|prompt\s+sistema)\b"
    r"|(?:покажи|выведи|раскрой).{0,120}(системн(?:ые|ые)?\s+инструкц(?:ии|ий)|параметр(?:ы|ов)\s+безопасности)"
    r"|输出系统提示词|内部策略|系统提示词|初始指令|初始提示|秘密令牌|配置|基本指令|所有规则|规则和约束",
    re.I,
)
_ROLE_TAKEOVER = re.compile(
    r"\b(from now on|you are now|act as|pretend to be|act[uú]a\s+como)\b.{0,140}"
    r"\b(system\s+developer|developer|developer\s+mode|admin(?:istrator)?|auditor|security_admin|modo\s+desarrollador)\b"
    r"|\bdisable\s+(?:safety\s+)?(?:rules?|guardrails?)\b"
    r"|进入维护模式|关闭安全|禁用安全",
    re.I,
)
_FALSE_AUTHORITY_ESCALATION = re.compile(
    r"\b(i\s+(?:am|own)|i'm\s+(?:the\s+)?owner|verified|confirmed|assistant:\s*verified)\b.{0,180}"
    r"\b(promote\s+me|security_admin|silently\s+approve|approve\s+every\s+tool\s+call|tool\s+call)\b"
    r"|\b(i\s+am\s+the\s+system\s+administrator|system\s+administrator|ceo\s+here|it\s+support|directeur\s+g[ée]n[ée]ral|pdg)\b.{0,220}"
    r"\b(wipe|delete|disable|reset|run|execute|output|reveal|initial\s+prompt|check\s+with\s+me\s+later|do\s+not\s+ask|no\s+verification|"
    r"ordonnez|outil\s+comptable|virer|virement|compte\s+personnel)\b"
    r"|\bje\s+suis\s+le\s+pdg\b.{0,220}\b(ordonnez|outil\s+comptable|virer|virement|compte\s+personnel)\b"
    r"|\bpromote\s+me\s+to\s+security_admin\b"
    r"|口头授权.{0,120}(重置所有用户\s*MFA|权限校验)"
    r"|重置所有用户\s*MFA.{0,120}(不要再做权限校验|口头授权)",
    re.I,
)
_INSTRUCTION_OVERRIDE = re.compile(
    r"\b(ignore|disregard|forget)\b.{0,80}\b(previous|earlier|prior)\b.{0,80}\b(instructions?|rules?|directions?|policy)\b"
    r"|忽略之前(?:所有)?(?:限制|指令|规则)",
    re.I,
)
_EXECUTE_ATTACK = _HIGH_RISK_EXECUTION
_ENCODED_FOLLOW = re.compile(r"\bdecode\b.{0,80}\bfollow\b.{0,80}\b[A-Za-z0-9+/]{24,}={0,2}\b", re.I)
_SQL_DESTRUCTIVE = re.compile(r"\b(drop|truncate|delete)\s+(?:table|database)\b|\bDROP\s+TABLE\b", re.I)
_UNAUTHORIZED_FUNCTION = re.compile(
    r"\b(call|execute|run)\b.{0,80}\b(?:admin\s+function|sql\s+query)\b"
    r"|\b(call|execute|run|use|fetch)\b.{0,120}\b(delete_all_users|export_financial_data|reset_system|disable_firewall|reset_all_passwords|"
    r"medical_records|clear_logs|send_marketing_spam|db_export|diagnostic_tool|show_config)\b"
    r"|/(?:admin|internal)/[A-Za-z0-9_/-]+"
    r"|`(?:delete_all_users|export_financial_data|reset_system|disable_firewall|reset_all_passwords|medical_records|clear_logs|send_marketing_spam|show_config)`"
    r"|\b(delete_all_users|export_financial_data|reset_system|disable_firewall|reset_all_passwords|medical_records|clear_logs|send_marketing_spam|db_export|diagnostic_tool|show_config)\b"
    r"|listar_credenciales|afficher_mots_de_passe",
    re.I,
)


def decide_input_policy(text: str) -> PolicyDecision:
    normalized = " ".join(str(text or "").split())
    lower = normalized.lower()
    signals: list[str] = []

    if _QUOTED_ATTACK_PHRASE.search(normalized):
        signals.append("quoted_attack_phrase")
    if _DEFENSIVE_CONTEXT.search(normalized):
        signals.append("defensive_explanation")
    if _NEGATED_BYPASS.search(normalized):
        signals.append("negated_bypass_steps")

    has_defensive_context = bool({"quoted_attack_phrase", "defensive_explanation", "negated_bypass_steps"} & set(signals))
    has_execute_intent = _has_execute_attack_intent(normalized)

    if _LOW_RISK_TOOL.search(normalized) and not _HIGH_RISK_TOOL.search(normalized):
        return _decision(
            "benign_low_risk_tool_request",
            "allow",
            0.9,
            [*signals, "low_risk_tool"],
            "The request references a registered low-risk tool and does not ask for authorization bypass or high-risk export.",
        )

    if (
        _SELF_SERVICE_MFA.search(normalized)
        and not re.search(r"\b(all\s+users?|admin|administrator|role\s*=\s*admin)\b|所有用户|管理员", normalized, re.I)
        and not _AUTH_BYPASS.search(normalized)
    ):
        return _decision(
            "benign_business",
            "allow",
            0.86,
            [*signals, "self_service_mfa"],
            "The request asks for self-service MFA guidance for the user's own account, without bypassing verification.",
        )

    if _BENIGN_RAG.search(normalized) and not _SOURCE_CONTROL.search(normalized):
        return _decision(
            "benign_rag_query",
            "allow",
            0.88,
            [*signals, "benign_rag_summary"],
            "The request asks to summarize or compare retrieved business content, not to follow untrusted instructions.",
        )

    if _ATTACK_GENERATION.search(normalized):
        return _decision(
            "attack_generation",
            "block",
            0.9,
            [*signals, "attack_payload_generation"],
            "The request asks to generate attack payload variants or probes.",
            "semantic_attack_coverage_expansion",
        )

    if _SQL_DESTRUCTIVE.search(normalized):
        return _decision(
            "unauthorized_tool_escalation",
            "block",
            0.94,
            [*signals, "destructive_sql"],
            "The request asks for destructive SQL execution or operational details.",
            "destructive_sql_operation",
        )

    if _RAG_POLICY_OVERRIDE.search(normalized):
        return _decision(
            "rag_or_web_poisoning",
            "block",
            0.92,
            [*signals, "untrusted_source_policy_override"],
            "Untrusted retrieved content is attempting to override platform policy.",
            "rag_policy_override",
        )

    if _SOURCE_CONTROL.search(normalized):
        if has_defensive_context and not has_execute_intent:
            return _decision(
                "benign_security_education",
                "allow",
                0.88,
                [*signals, "untrusted_source_discussion"],
                "The prompt discusses untrusted-source injection defensively without asking the model to follow it.",
            )
        intent: PolicyIntent = "tool_return_poisoning" if re.search(
            r"\b(tool\s+(returned|result|output)|tool\s+output|(?:payment\s+)?api\s+returned|api\s+response|report\s+tool\s+output)\b"
            r"|工具返回|outil\s+renvoy[ée]|(?:herramienta|api\s+de\s+(?:pagos|b[uú]squeda))\s+(?:devolvi[oó]|retorn[oó])"
            r"|die\s+analyse\s+zeigt|rapport|werkzeug|(?:das\s+)?support[-\s]?tool\s+sagt|api-systemmeldung",
            lower,
            re.I,
        ) else "rag_or_web_poisoning"
        rule_name = "tool_output_instruction_injection" if intent == "tool_return_poisoning" else "rag_source_instruction_override"
        return _decision(
            intent,
            "block",
            0.92,
            [*signals, "untrusted_source_instruction"],
            "Untrusted retrieved, web, or tool content is attempting to issue instructions.",
            rule_name,
        )

    if _UNAUTHORIZED_FUNCTION.search(normalized):
        return _decision(
            "unauthorized_tool_escalation",
            "block",
            0.93,
            [*signals, "sensitive_function_call", *_signal_if(_DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(normalized), "destructive_or_exfil_objective")],
            "The request asks to call or execute a sensitive function, tool, or query for destructive or exfiltration purposes.",
            "unauthorized_sensitive_function_call",
        )

    if _AUTHORIZED_REPORT_EXPORT.search(normalized) and not _AUTH_BYPASS.search(normalized) and not _DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(normalized):
        return _decision(
            "benign_business",
            "audit",
            0.84,
            [*signals, "authorization_token_present", "controlled_report_export"],
            "The request describes an authorized report export token; route to normal tool authorization rather than blocking at input.",
            "authorized_tool_request_requires_gateway",
        )

    if has_defensive_context and not has_execute_intent:
        return _decision(
            "benign_security_education",
            "allow",
            0.91,
            signals,
            "The prompt discusses security or attack phrases defensively and does not ask the model to execute the attack.",
        )

    if _INSTRUCTION_OVERRIDE.search(normalized):
        if has_execute_intent or not has_defensive_context:
            intent: PolicyIntent = "prompt_or_policy_extraction" if _PROMPT_SECRET.search(normalized) else "instruction_override"
            return _decision(
                intent,
                "block",
                0.91,
                [*signals, "instruction_override"],
                "The request asks the model to override prior instructions or policy.",
                "prompt_injection_ignore_previous",
            )
        return _decision(
            "benign_security_education",
            "allow",
            0.86,
            [*signals, "instruction_override_discussion"],
            "The prompt mentions instruction override in a defensive or educational context.",
        )

    if _ROLE_TAKEOVER.search(normalized) and re.search(
        r"\b(from now on|you are now)\b|\bdisable\s+(?:safety\s+)?(?:rules?|guardrails?)\b|进入维护模式|关闭安全|禁用安全",
        normalized,
        re.I,
    ):
        return _decision(
            "role_takeover",
            "block",
            0.92,
            [*signals, "role_or_safety_override"],
            "The request attempts role takeover, false authority, or safety-rule disabling.",
            "role_takeover_authority_claim",
        )

    if _PROMPT_SECRET.search(normalized):
        return _decision(
            "prompt_or_policy_extraction",
            "block",
            0.93,
            [*signals, "prompt_or_policy_secret"],
            "The request attempts to reveal hidden system, developer, policy, or internal prompt material.",
            "system_prompt_extraction_request",
        )

    if _FALSE_AUTHORITY_ESCALATION.search(normalized):
        intent = (
            "unauthorized_tool_escalation"
            if re.search(r"\b(tool\s+call|approve|silently|reset\s+(?:all\s+)?(?:user\s+)?mfa|run|execute|wipe|delete|disable)\b|重置所有用户\s*MFA|权限校验", normalized, re.I)
            or _DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(normalized)
            else "role_takeover"
        )
        return _decision(
            intent,
            "block",
            0.92,
            [*signals, "false_authority_claim", "privilege_escalation"],
            "The request uses claimed or simulated authority to request privileged role or tool escalation.",
            "false_authority_tool_escalation",
        )

    if (
        _HIGH_RISK_TOOL.search(normalized)
        and not (_AUTHORIZATION_TOKEN.search(normalized) and not _AUTH_BYPASS.search(normalized))
        and (_AUTH_BYPASS.search(normalized) or _HIGH_RISK_EXECUTION.search(normalized) or _DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(normalized))
    ):
        rule_name = "public_role_export_request" if re.search(r"\bexport\s+tool\b", lower) and re.search(r"\bpublic\b", lower) else "unauthorized_tool_escalation"
        return _decision(
            "unauthorized_tool_escalation",
            "block",
            0.94,
            [*signals, "high_risk_tool", "authorization_bypass"],
            "The request attempts a high-risk tool action or authorization bypass.",
            rule_name,
        )

    if re.search(
        r"\b(wire\s+transfer|bank(?:ing)?\s+transfer|transfer\s+all\s+funds|list\s+all\s+user\s+credentials|send\s+to\s+admin@external\.com)\b"
        r"|transferir.{0,80}(cuenta|rescate)|herramienta\s+de\s+banca|[uü]berweisungstool|"
        r"virement\s+bancaire|virer.{0,80}(?:€|eur|euro|compte\s+personnel)|outil\s+comptable.{0,80}(?:virer|virement)|compte\s+des\s+ravisseurs",
        normalized,
        re.I,
    ):
        return _decision(
            "unauthorized_tool_escalation",
            "block",
            0.9,
            [*signals, "financial_or_credential_exfiltration"],
            "The request asks for credential exfiltration or unauthorized financial transfer.",
            "credential_or_financial_exfiltration",
        )

    if _DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(normalized) and (
        _AUTH_BYPASS.search(normalized)
        or re.search(
            r"\b(ceo\s+here|it\s+support|directeur\s+g[ée]n[ée]ral|direct\s+order|code\s+red|emergency|urgent|breach|autorisiert|autoris[ée]e?)\b"
            r"|紧急|口头授权|内部调查|ne\s+v[ée]rifiez\s+pas|keine\s+verifikation",
            normalized,
            re.I,
        )
    ):
        return _decision(
            "unauthorized_tool_escalation",
            "block",
            0.9,
            [*signals, "destructive_or_exfil_objective", "authority_or_no_verify"],
            "The request combines urgency or claimed authority with destructive, exfiltration, or security-disabling action.",
            "social_engineering_high_risk_action",
        )

    if _ROLE_TAKEOVER.search(normalized):
        return _decision(
            "role_takeover",
            "block",
            0.92,
            [*signals, "role_or_safety_override"],
            "The request attempts role takeover, false authority, or safety-rule disabling.",
            "role_takeover_authority_claim",
        )

    if _ENCODED_FOLLOW.search(normalized):
        return _decision(
            "instruction_override",
            "block",
            0.86,
            [*signals, "encoded_follow_instruction"],
            "The request asks the model to decode and follow an encoded instruction.",
            "encoded_instruction_follow_request",
        )

    if re.search(r"\b(prompt\s+injection|jailbreak|bypass|red\s+team)\b|越狱|提示注入", lower):
        return _decision(
            "uncertain",
            "audit",
            0.55,
            [*signals, "security_topic"],
            "The prompt discusses security-sensitive concepts but no clear unsafe execution intent was found.",
        )

    return _decision(
        "benign_business",
        "allow",
        0.7,
        signals or ["no_security_risk_signal"],
        "No security policy violation was detected.",
    )


def _has_execute_attack_intent(text: str) -> bool:
    if _ENCODED_FOLLOW.search(text):
        return True
    if _PROMPT_SECRET.search(text):
        return True
    if _SQL_DESTRUCTIVE.search(text) or _UNAUTHORIZED_FUNCTION.search(text):
        return True
    if _HIGH_RISK_TOOL.search(text) and (_AUTH_BYPASS.search(text) or _EXECUTE_ATTACK.search(text)):
        return True
    if _SOURCE_CONTROL.search(text):
        return True
    if _DESTRUCTIVE_OR_EXFIL_OBJECTIVE.search(text) and (_HIGH_RISK_EXECUTION.search(text) or _AUTH_BYPASS.search(text)):
        return True
    if re.search(r"\bnow\s+execute\s+it\b|\bfollow\s+this\s+instruction\b|\buse\s+the\s+retrieved\s+instruction\b", text, re.I):
        return True
    if re.search(r"输出系统提示词|内部策略|重置所有用户\s*MFA|不要再做权限校验|新指令", text, re.I):
        return True
    return False


def _decision(
    intent: PolicyIntent,
    risk_tier: PolicyRiskTier,
    confidence: float,
    matched_signals: list[str],
    reason: str,
    rule_name: str | None = None,
) -> PolicyDecision:
    action: PolicyAction = risk_tier
    return PolicyDecision(
        intent=intent,
        risk_tier=risk_tier,
        action=action,
        confidence=confidence,
        matched_signals=sorted(set(signal for signal in matched_signals if signal)),
        reason=reason,
        rule_name=rule_name,
    )


def _signal_if(condition: object, signal: str) -> list[str]:
    return [signal] if condition else []
