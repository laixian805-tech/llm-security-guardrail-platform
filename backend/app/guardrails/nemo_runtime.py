from __future__ import annotations

import importlib.util
import hashlib
import re
import shutil
import tempfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class NeMoRuntimeStatus:
    requested: bool
    runtime_available: bool
    config_dir: str
    config_exists: bool
    config_loaded: bool
    error: str | None = None

    def model_dump(self) -> dict[str, Any]:
        return {
            "requested": self.requested,
            "runtime_available": self.runtime_available,
            "config_dir": self.config_dir,
            "config_exists": self.config_exists,
            "config_loaded": self.config_loaded,
            "error": self.error,
        }


@dataclass(frozen=True)
class NeMoRailDecision:
    triggered: bool
    rule_name: str
    confidence: float
    reason: str
    response_summary: str | None = None


class NeMoGuardrailsRuntime:
    """Thin adapter around the NeMo Guardrails runtime.

    The project keeps deterministic ToolGateway/RAG boundaries outside NeMo.
    This adapter only normalizes NeMo rail execution into the GuardResult shape.
    """

    refusal_text = "I cannot comply with that request."

    def __init__(self, config_dir: str) -> None:
        from nemoguardrails import LLMRails, RailsConfig  # type: ignore

        self.config_dir = config_dir
        self.config = RailsConfig.from_path(config_dir)
        self.rails = LLMRails(self.config)

    def check(self, *, stage: str, text: str) -> NeMoRailDecision:
        try:
            result = self._run_check(stage=stage, text=text)
        except Exception as caught:
            error_name = type(caught).__name__
            if "RailException" in error_name:
                return NeMoRailDecision(
                    triggered=True,
                    rule_name=f"nemo_{stage}_rail_exception",
                    confidence=0.95,
                    reason=f"NeMo Guardrails runtime blocked the content with {error_name}.",
                    response_summary=summarize_text(str(caught)),
                )
            raise
        content = extract_response_content(result)
        summary = summarize_text(content)
        status = str(getattr(result, "status", "")).lower()
        rail = getattr(result, "rail", None)
        if status.endswith("blocked") or rail or self._looks_like_refusal(content):
            return NeMoRailDecision(
                triggered=True,
                rule_name=str(rail or f"nemo_{stage}_rail").replace(" ", "_"),
                confidence=0.92,
                reason="NeMo Guardrails runtime refused the content.",
                response_summary=summary,
            )
        return NeMoRailDecision(
            triggered=False,
            rule_name="nemo_no_match",
            confidence=0.0,
            reason="NeMo Guardrails runtime did not block the content.",
            response_summary=summary,
        )

    def _run_check(self, *, stage: str, text: str) -> Any:
        from nemoguardrails.rails.llm.options import RailType  # type: ignore

        if stage == "post_output":
            messages = [
                {
                    "role": "assistant",
                    "content": text,
                }
            ]
            rail_types = [RailType.OUTPUT]
        else:
            messages = [{"role": "user", "content": text}]
            rail_types = [RailType.INPUT]
        return self.rails.check(messages=messages, rail_types=rail_types)

    def _looks_like_refusal(self, text: str) -> bool:
        normalized = text.lower()
        refusal_markers = (
            self.refusal_text.lower(),
            "cannot comply",
            "can't comply",
            "can't respond",
            "cannot respond",
            "input not allowed",
            "output not allowed",
        )
        return any(marker in normalized for marker in refusal_markers)


@lru_cache(maxsize=16)
def get_nemo_runtime(
    config_dir: str | None = None,
    *,
    model_name: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> NeMoGuardrailsRuntime:
    resolved = effective_nemo_config_dir(
        config_dir,
        model_name=model_name,
        base_url=base_url,
        api_key=api_key,
    )
    return NeMoGuardrailsRuntime(resolved)


def extract_response_content(response: Any) -> str:
    if isinstance(response, str):
        return response
    response_attr = getattr(response, "response", None)
    if response_attr is not None:
        return extract_response_content(response_attr)
    result_content = getattr(response, "content", None)
    if isinstance(result_content, str):
        return result_content
    content_attr = getattr(response, "content", None)
    if isinstance(content_attr, str):
        return content_attr
    if isinstance(response, dict):
        content = response.get("content")
        if isinstance(content, str):
            return content
        message = response.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            return str(message["content"])
        messages = response.get("messages")
        if isinstance(messages, list) and messages:
            last = messages[-1]
            if isinstance(last, dict) and isinstance(last.get("content"), str):
                return str(last["content"])
    if isinstance(response, list) and response:
        return extract_response_content(response[-1])
    return str(response)


def summarize_text(text: str, *, limit: int = 240) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[: limit - 3]}..."


def default_nemo_config_dir() -> str:
    return str(Path(__file__).resolve().parent / "nemo_config")


def effective_nemo_config_dir(
    config_dir: str | None = None,
    *,
    model_name: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> str:
    resolved = Path(config_dir or default_nemo_config_dir()).resolve()
    if not any([model_name, base_url, api_key]):
        return str(resolved)
    return str(
        _materialize_runtime_config(
            resolved,
            model_name=model_name,
            base_url=base_url,
            api_key=api_key,
        )
    )


def _materialize_runtime_config(
    source_dir: Path,
    *,
    model_name: str | None,
    base_url: str | None,
    api_key: str | None,
) -> Path:
    fingerprint = hashlib.sha256(
        "|".join(
            [
                str(source_dir),
                model_name or "",
                base_url or "",
                api_key or "",
            ]
        ).encode("utf-8")
    ).hexdigest()[:16]
    target_dir = Path(tempfile.gettempdir()) / "llmsec-nemo-configs" / fingerprint
    config_path = target_dir / "config.yml"
    if config_path.exists():
        return target_dir
    target_dir.mkdir(parents=True, exist_ok=True)
    for child in source_dir.iterdir():
        target = target_dir / child.name
        if child.is_dir():
            if target.exists():
                shutil.rmtree(target)
            shutil.copytree(child, target)
        else:
            shutil.copy2(child, target)
    _rewrite_config_model(config_path, model_name=model_name, base_url=base_url, api_key=api_key)
    return target_dir


def _rewrite_config_model(
    config_path: Path,
    *,
    model_name: str | None,
    base_url: str | None,
    api_key: str | None,
) -> None:
    raw = config_path.read_text(encoding="utf-8")
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(raw)
        if not isinstance(payload, dict):
            return
        models = payload.get("models")
        if not isinstance(models, list):
            return
        for item in models:
            if not isinstance(item, dict) or item.get("type") != "main":
                continue
            if model_name:
                item["model"] = model_name
            parameters = item.setdefault("parameters", {})
            if isinstance(parameters, dict):
                if base_url:
                    parameters["base_url"] = base_url
                if api_key:
                    parameters["api_key"] = api_key
            break
        config_path.write_text(yaml.safe_dump(payload, sort_keys=False, allow_unicode=True), encoding="utf-8")
    except Exception:
        if model_name:
            raw = re.sub(r"(?m)^(\s*model:\s*).*$", rf"\1{model_name}", raw, count=1)
        if base_url:
            raw = re.sub(r"(?m)^(\s*base_url:\s*).*$", rf"\1{base_url}", raw, count=1)
        if api_key:
            raw = re.sub(r"(?m)^(\s*api_key:\s*).*$", rf"\1{api_key}", raw, count=1)
        config_path.write_text(raw, encoding="utf-8")


def explain_nemo_guard_pack(config_dir: str | None = None) -> dict[str, Any]:
    resolved = Path(config_dir or default_nemo_config_dir())
    config_path = resolved / "config.yml"
    status = nemo_runtime_status(str(resolved), requested=True)
    raw_config = config_path.read_text(encoding="utf-8") if config_path.exists() else ""
    parsed = _parse_nemo_config(raw_config)
    input_flows = _nested_get(parsed, ["rails", "input", "flows"], [])
    output_flows = _nested_get(parsed, ["rails", "output", "flows"], [])
    prompts = parsed.get("prompts") if isinstance(parsed.get("prompts"), list) else []
    instructions = parsed.get("instructions") if isinstance(parsed.get("instructions"), list) else []
    blocked_intents = _blocked_intents_from_prompts(prompts, raw_config)
    return {
        "schema_version": 1,
        "engine": "nemo",
        "config_dir": str(resolved),
        "config_file": str(config_path),
        "status": status.model_dump(),
        "rails": {
            "input_flows": [str(flow) for flow in input_flows],
            "output_flows": [str(flow) for flow in output_flows],
        },
        "instructions": [
            {
                "type": str(item.get("type", "general")),
                "summary": summarize_text(str(item.get("content", "")), limit=360),
            }
            for item in instructions
            if isinstance(item, dict)
        ],
        "prompts": [
            {
                "task": str(prompt.get("task", "unknown")),
                "summary": summarize_text(str(prompt.get("content", "")), limit=420),
            }
            for prompt in prompts
            if isinstance(prompt, dict)
        ],
        "blocked_intents": blocked_intents,
        "fallback_policy": {
            "fallback_engine": "custom_nemo",
            "deterministic_boundaries": ["ToolGateway", "RAG source isolation", "dynamic guard packs"],
        },
    }


def _parse_nemo_config(raw_config: str) -> dict[str, Any]:
    if not raw_config.strip():
        return {}
    try:
        import yaml  # type: ignore

        payload = yaml.safe_load(raw_config)
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return _parse_minimal_yaml(raw_config)


def _parse_minimal_yaml(raw_config: str) -> dict[str, Any]:
    payload: dict[str, Any] = {"rails": {"input": {"flows": []}, "output": {"flows": []}}, "prompts": [], "instructions": []}
    current_prompt: dict[str, str] | None = None
    current_instruction: dict[str, str] | None = None
    current_block: str | None = None
    for line in raw_config.splitlines():
        stripped = line.strip()
        if stripped == "input:":
            current_block = "input_flows"
            continue
        if stripped == "output:":
            current_block = "output_flows"
            continue
        if stripped.startswith("- ") and current_block in {"input_flows", "output_flows"}:
            flow = stripped[2:].strip()
            target = payload["rails"]["input" if current_block == "input_flows" else "output"]["flows"]
            target.append(flow)
            continue
        if stripped.startswith("- task:"):
            current_prompt = {"task": stripped.split(":", 1)[1].strip(), "content": ""}
            payload["prompts"].append(current_prompt)
            current_instruction = None
            continue
        if stripped.startswith("- type:"):
            current_instruction = {"type": stripped.split(":", 1)[1].strip(), "content": ""}
            payload["instructions"].append(current_instruction)
            current_prompt = None
            continue
        if current_prompt is not None and stripped.startswith("content:"):
            continue
        if current_instruction is not None and stripped.startswith("content:"):
            continue
        if current_prompt is not None and line.startswith("      "):
            current_prompt["content"] += f"{stripped}\n"
        if current_instruction is not None and line.startswith("      "):
            current_instruction["content"] += f"{stripped}\n"
    return payload


def _nested_get(payload: dict[str, Any], keys: list[str], default: Any) -> Any:
    value: Any = payload
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return value if value is not None else default


def _blocked_intents_from_prompts(prompts: list[Any], raw_config: str) -> list[dict[str, str]]:
    text = "\n".join(str(prompt.get("content", "")) for prompt in prompts if isinstance(prompt, dict)) or raw_config
    intents = [
        ("prompt_injection", "Prompt injection, instruction override, bypass, or guardrail disabling."),
        ("role_takeover", "User claims to be an admin, developer, auditor, or system authority."),
        ("prompt_extraction", "System, developer, hidden prompt, or policy extraction."),
        ("rag_poisoning", "RAG or webpage content attempts to issue instructions."),
        ("tool_abuse", "Unauthorized tool escalation or export/admin tool misuse."),
        ("attack_generation", "Requests to generate attack variants, probes, payloads, or bypass sets."),
        ("unsafe_output", "Unsafe output such as prompt leaks, RAG dumps, target phrases, or bypass guidance."),
    ]
    lowered = text.lower()
    return [
        {"intent": intent, "description": description}
        for intent, description in intents
        if _intent_keyword(intent, lowered)
    ]


def _intent_keyword(intent: str, lowered_text: str) -> bool:
    keywords = {
        "prompt_injection": r"prompt injection|ignore|override|bypass|disable",
        "role_takeover": r"role takeover|admin|developer|auditor|system authority",
        "prompt_extraction": r"system.*prompt|developer.*message|hidden.*prompt|policy extraction",
        "rag_poisoning": r"rag|retrieved|webpage|untrusted retrieved",
        "tool_abuse": r"tool abuse|export_data|export_internal_reports|admin export|authorization",
        "attack_generation": r"attack payload|variants|paraphrases|translations|multi-turn|bypass sets",
        "unsafe_output": r"assistant output|bulk rag|knowledge-base dumps|i hate humans|bypass authorization",
    }
    return re.search(keywords[intent], lowered_text, re.I) is not None


def nemo_runtime_status(
    config_dir: str | None = None,
    *,
    requested: bool = True,
    model_name: str | None = None,
    base_url: str | None = None,
    api_key: str | None = None,
) -> NeMoRuntimeStatus:
    resolved = Path(
        effective_nemo_config_dir(
            config_dir,
            model_name=model_name,
            base_url=base_url,
            api_key=api_key,
        )
    )
    config_exists = resolved.exists() and (resolved / "config.yml").exists()
    if importlib.util.find_spec("nemoguardrails") is None:
        return NeMoRuntimeStatus(
            requested=requested,
            runtime_available=False,
            config_dir=str(resolved),
            config_exists=config_exists,
            config_loaded=False,
            error="nemoguardrails is not installed",
        )
    if not config_exists:
        return NeMoRuntimeStatus(
            requested=requested,
            runtime_available=False,
            config_dir=str(resolved),
            config_exists=False,
            config_loaded=False,
            error="NeMo config.yml not found",
        )
    try:
        from nemoguardrails import RailsConfig  # type: ignore

        RailsConfig.from_path(str(resolved))
    except Exception as caught:  # pragma: no cover - depends on optional runtime
        return NeMoRuntimeStatus(
            requested=requested,
            runtime_available=False,
            config_dir=str(resolved),
            config_exists=True,
            config_loaded=False,
            error=f"{type(caught).__name__}: {caught}",
        )
    return NeMoRuntimeStatus(
        requested=requested,
        runtime_available=True,
        config_dir=str(resolved),
        config_exists=True,
        config_loaded=True,
        error=None,
    )
