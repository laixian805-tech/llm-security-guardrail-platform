from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Literal

from app.guardrails.policy import PolicyDecision


RiskDecision = Literal["allow", "audit", "block"]


@dataclass(frozen=True)
class RiskClassification:
    model: str
    policy_score: float
    risk_score: int
    decision: RiskDecision
    confidence: float
    features: list[str]
    reason: str

    def model_dump(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "policy_score": round(self.policy_score, 4),
            "risk_score": self.risk_score,
            "decision": self.decision,
            "confidence": round(self.confidence, 4),
            "features": list(self.features),
            "reason": self.reason,
        }


_EXPLICIT_ALLOW_INTENTS = {
    "benign_security_education",
    "benign_rag_query",
    "benign_low_risk_tool_request",
}
_EXPLICIT_BLOCK_INTENTS = {
    "instruction_override",
    "prompt_or_policy_extraction",
    "role_takeover",
    "rag_or_web_poisoning",
    "tool_return_poisoning",
    "unauthorized_tool_escalation",
    "attack_generation",
}
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
_AUTHORIZATION_TOKEN = re.compile(r"\b(?:authorization|audit|access)\s+token\b|\bAUTH-[A-Z0-9-]{4,}\b", re.I)
_FALSE_AUTHORITY = re.compile(
    r"\b(i\s+own|i'm\s+(?:the\s+)?owner|i\s+am\s+(?:the\s+)?(?:owner|admin(?:istrator)?|system\s+administrator)|system\s+administrator|"
    r"verified|confirmed|assistant:\s*verified|promote\s+me|security_admin|ceo\s+here|it\s+support|directeur\s+g[ée]n[ée]ral|pdg)\b"
    r"|\bje\s+suis\s+le\s+pdg\b"
    r"|口头授权|紧急演练|内部调查",
    re.I,
)
_UNTRUSTED_SOURCE = re.compile(
    r"\b(retrieved|document|context|chunk|web\s*page|tool\s+(?:returned|output|result)|tool\s+output|report\s+tool\s+output|"
    r"(?:payment\s+)?api\s+returned|api\s+response|api\s+de\s+(?:pagos|b[uú]squeda)\s+devolvi[oó]|"
    r"die\s+analyse\s+zeigt|rapport|recuper[ée]\s+este\s+fragmento|el\s+doc\s+dice|aus\s+dem\s+dokument|"
    r"(?:das\s+)?support[-\s]?tool\s+sagt|api-systemmeldung|translate\s+this|[üu]bersetze)\b"
    r".{0,220}\b(ignore|override|follow|export|new\s+instruction|dump|reveal|to\s+proceed|execute|"
    r"list\s+all\s+user\s+credentials|send\s+to|wire\s+transfer|drop\s+table|transaction\s+approved|delete|revoke|"
    r"confidential|phishing|termination|diagnostic_tool|db_export|system\s+prompt|"
    r"exportieren|benutzerdaten|wartungsmodus|zugangsdaten|senden\s+sie|fake@domain\.com)\b"
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
_PROMPT_SECRET = re.compile(
    r"\b(reveal|print|show|dump|output|disclose|repeat)\b.{0,120}\b(system|hidden|developer|internal|confidential|initial)\b"
    r".{0,80}\b(prompt|instruction|message|policy|rules?|constraints?)\b"
    r"|\b(exact\s+initial\s+prompt|initial\s+prompt|initial\s+instructions?|system\s+instructions?|full\s+system\s+instructions?|system\s+messages?|hidden\s+instructions?|security\s+rules?)\b"
    r"|\brepeat\s+everything\s+above\s+this\s+line\b"
    r"|\b(mu[eé]strame|m[uú]estrame|mostrar|repite|repetir|cu[eé]ntame)\b.{0,120}\b(instrucciones\s+iniciales|reglas\s+de\s+seguridad|prompt\s+(?:inicial|del\s+sistema|sistema))\b"
    r"|\b(system-prompt|système|invite\s+syst[eè]me|prompt\s+del\s+sistema|prompt\s+sistema)\b"
    r"|(?:покажи|выведи|раскрой).{0,120}(системн(?:ые|ые)?\s+инструкц(?:ии|ий)|параметр(?:ы|ов)\s+безопасности)"
    r"|输出系统提示词|内部策略|初始指令|初始提示|秘密令牌|配置|基本指令|所有规则|规则和约束",
    re.I,
)
_INSTRUCTION_OVERRIDE = re.compile(r"\b(ignore|disregard|forget|override)\b.{0,100}\b(instruction|policy|rule|guardrail)s?\b|忽略之前", re.I)
_EXECUTE_VERB = re.compile(
    r"\b(call|run|execute|approve|export|send|decode|follow|disable|promote|reset|wipe|delete|install|read)\b"
    r"|调用|执行|导出|重置|删除|禁用|传输|appeler|ex[ée]cutez|ejecuta|virer|setzen|deaktivieren|senden|exportieren",
    re.I,
)
_DEFENSIVE_CONTEXT = re.compile(
    r"\b(explain|why|training|defensive|review|mitigation|prevent|risky)\b"
    r"|\b(?:analy[sz]e|analysis)\b.{0,80}\b(prompt\s+injection|jailbreak|risk|defensive|security|bypass)\b"
    r"|防御|风险|培训",
    re.I,
)
_QUOTED_ATTACK = re.compile(r"(['\"`“”‘’])\s*(ignore\s+(?:all\s+)?previous\s+instructions?|忽略之前所有限制)\s*\1", re.I)
_LOW_RISK_TOOL = re.compile(
    r"\b(policy_lookup|search_kb|report_lookup|user_info|calculator|translation\s*tool|weather\s*tool|calendar\s*tool)\b"
    r"|übersetzungstool|traduction|outil\s+météo|herramienta\s+de\s+calendario|herramienta\s+de\s+traducci[oó]n",
    re.I,
)
_BENIGN_RAG = re.compile(r"\b(retrieved|handbook|content|document)\b.{0,100}\b(summarize|compare|list|requirements?)\b", re.I)
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
_SELF_SERVICE_MFA = re.compile(
    r"\b(reset|view|configure|update|recover)\b.{0,80}\b(my|own|my\s+account)\b.{0,80}\b(mfa|2fa|multi-factor|two-factor)\b"
    r"|\b(my|own|my\s+account)\b.{0,80}\b(mfa|2fa|multi-factor|two-factor)\b",
    re.I,
)
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


def enrich_policy_with_risk(
    policy: PolicyDecision,
    text: str,
    *,
    surface: str = "prompt",
    context: dict[str, Any] | None = None,
) -> PolicyDecision:
    classification = classify_policy_risk(policy, text, surface=surface, context=context)
    action = policy.action
    risk_tier = policy.risk_tier
    rule_name = policy.rule_name
    reason = policy.reason
    confidence = max(policy.confidence, classification.confidence)

    if policy.intent in _EXPLICIT_BLOCK_INTENTS:
        action = "block"
        risk_tier = "block"
    elif policy.intent in _EXPLICIT_ALLOW_INTENTS:
        action = policy.action
        risk_tier = policy.risk_tier
    elif policy.intent == "uncertain" or (policy.intent == "benign_business" and policy.confidence <= 0.75):
        if classification.decision == "block":
            action = "block"
            risk_tier = "block"
            rule_name = "local_risk_classifier_block"
            reason = classification.reason
        elif classification.decision == "audit":
            action = "audit"
            risk_tier = "audit"
            rule_name = "local_risk_classifier_audit"
            reason = classification.reason

    return replace(
        policy,
        action=action,  # type: ignore[arg-type]
        risk_tier=risk_tier,  # type: ignore[arg-type]
        confidence=min(1.0, confidence),
        rule_name=rule_name,
        reason=reason,
        policy_score=classification.policy_score,
        risk_score=classification.risk_score,
        classifier=classification.model_dump(),
    )


def classify_policy_risk(
    policy: PolicyDecision,
    text: str,
    *,
    surface: str = "prompt",
    context: dict[str, Any] | None = None,
) -> RiskClassification:
    normalized = " ".join(str(text or "").split())
    features: list[str] = []
    score = _base_score(policy)

    score += _feature(normalized, _HIGH_RISK_TOOL, 35, "high_risk_tool", features)
    score += _feature(normalized, _AUTH_BYPASS, 30, "auth_bypass", features)
    score += _feature(normalized, _FALSE_AUTHORITY, 30, "false_authority_claim", features)
    score += _feature(normalized, _UNTRUSTED_SOURCE, 35, "untrusted_source_instruction", features)
    score += _feature(normalized, _PROMPT_SECRET, 35, "prompt_or_policy_secret", features)
    score += _feature(normalized, _INSTRUCTION_OVERRIDE, 25, "instruction_override", features)
    score += _feature(normalized, _DESTRUCTIVE_OR_EXFIL_OBJECTIVE, 35, "destructive_or_exfil_objective", features)
    score += _feature(normalized, _SQL_DESTRUCTIVE, 35, "destructive_sql", features)
    score += _feature(normalized, _UNAUTHORIZED_FUNCTION, 60, "sensitive_function_call", features)
    score += _feature(normalized, _EXECUTE_VERB, 10, "execute_verb", features)
    score += _feature(normalized, _DEFENSIVE_CONTEXT, -20, "defensive_context", features)
    score += _feature(normalized, _QUOTED_ATTACK, -15, "quoted_attack_phrase", features)
    score += _feature(normalized, _LOW_RISK_TOOL, -20, "low_risk_tool", features)
    score += _feature(normalized, _BENIGN_RAG, -15, "benign_rag_summary", features)

    has_auth_bypass = _AUTH_BYPASS.search(normalized)
    if _AUTHORIZATION_TOKEN.search(normalized) and not has_auth_bypass and not _UNTRUSTED_SOURCE.search(normalized):
        score -= 35
        features.append("authorization_token_present")
    if (
        _SELF_SERVICE_MFA.search(normalized)
        and not has_auth_bypass
        and not re.search(r"\b(all\s+users?|admin|administrator|role\s*=\s*admin)\b|所有用户|管理员", normalized, re.I)
    ):
        score -= 55
        features.append("self_service_mfa")

    if surface in {"tool", "agent"}:
        score += 10
        features.append(f"surface_{surface}")
    elif surface == "rag":
        score += 8
        features.append("surface_rag")

    context = context or {}
    if str(context.get("source_trust") or "").lower() in {"low", "untrusted"}:
        score += 15
        features.append("low_trust_source")
    if str(context.get("tool_verdict") or "").lower() == "block":
        score += 35
        features.append("tool_gateway_block")

    if policy.intent in _EXPLICIT_ALLOW_INTENTS:
        score = min(score, 25)
    if policy.intent in _EXPLICIT_BLOCK_INTENTS:
        score = max(score, 82)

    risk_score = max(0, min(100, int(round(score))))
    decision = _decision_from_score(risk_score, surface=surface)
    confidence = _confidence_from_score(risk_score)
    policy_score = round(risk_score / 100, 4)
    reason = f"Local risk classifier assigned {risk_score}/100 risk for {surface} input."
    return RiskClassification(
        model="local-linear-policy-v1",
        policy_score=policy_score,
        risk_score=risk_score,
        decision=decision,
        confidence=confidence,
        features=sorted(set(features or [f"intent_{policy.intent}"])),
        reason=reason,
    )


def _base_score(policy: PolicyDecision) -> int:
    return {
        "benign_business": 20,
        "benign_security_education": 5,
        "benign_rag_query": 10,
        "benign_low_risk_tool_request": 8,
        "instruction_override": 82,
        "prompt_or_policy_extraction": 88,
        "role_takeover": 84,
        "rag_or_web_poisoning": 86,
        "tool_return_poisoning": 90,
        "unauthorized_tool_escalation": 92,
        "attack_generation": 82,
        "uncertain": 45,
    }.get(policy.intent, 30)


def _feature(text: str, pattern: re.Pattern[str], weight: int, name: str, features: list[str]) -> int:
    if not pattern.search(text):
        return 0
    features.append(name)
    return weight


def _decision_from_score(score: int, *, surface: str) -> RiskDecision:
    if score >= 80:
        return "block"
    if score >= 60 and surface in {"tool", "rag", "agent"}:
        return "block"
    if score >= 30:
        return "audit"
    return "allow"


def _confidence_from_score(score: int) -> float:
    if score >= 80:
        return 0.88
    if score >= 60:
        return 0.76
    if score >= 30:
        return 0.62
    return 0.72
