from __future__ import annotations

import time
import re
from typing import Any, Protocol

import httpx
from pydantic import BaseModel


class ChatMessage(BaseModel):
    role: str
    content: str


class ModelResponse(BaseModel):
    content: str
    model: str
    latency_ms: int


class ModelProvider(Protocol):
    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelResponse:
        """Generate a response for OpenAI-style chat messages."""


class StubModelProvider:
    def __init__(self, model_name: str = "stub-security-model") -> None:
        self.model_name = model_name

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelResponse:
        started = time.perf_counter()
        user_message = _last_user_message(messages)
        return ModelResponse(
            content=f"Stub response: {user_message}",
            model=self.model_name,
            latency_ms=_elapsed_ms(started),
        )


class OllamaModelProvider:
    def __init__(
        self,
        base_url: str,
        model_name: str,
        timeout_seconds: float = 60.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.timeout_seconds = timeout_seconds

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelResponse:
        started = time.perf_counter()
        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
        }
        if max_tokens is not None:
            payload["options"] = {"num_predict": max_tokens}
        if temperature is not None:
            options = dict(payload.get("options", {}))
            options["temperature"] = temperature
            payload["options"] = options
        response = httpx.post(
            f"{self.base_url}/api/chat",
            json=payload,
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        content = sanitize_model_output(payload.get("message", {}).get("content", ""))
        return ModelResponse(
            content=content,
            model=self.model_name,
            latency_ms=_elapsed_ms(started),
        )


class OpenAICompatibleModelProvider:
    def __init__(
        self,
        base_url: str,
        model_name: str,
        api_key: str = "dummy",
        timeout_seconds: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.api_key = api_key or "dummy"
        self.timeout_seconds = timeout_seconds

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> ModelResponse:
        started = time.perf_counter()
        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0 if temperature is None else temperature,
            "stream": False,
        }
        if "qwen" in self.model_name.lower():
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        response = httpx.post(
            f"{self.base_url}/chat/completions",
            json=payload,
            headers={"Authorization": f"Bearer {self.api_key}"},
            timeout=self.timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        choices = payload.get("choices", [])
        content = ""
        if choices:
            message = choices[0].get("message", {})
            content = sanitize_model_output(message.get("content", ""), message=message)
        return ModelResponse(
            content=content,
            model=str(payload.get("model") or self.model_name),
            latency_ms=_elapsed_ms(started),
        )


def _last_user_message(messages: list[dict[str, str]]) -> str:
    for message in reversed(messages):
        if message.get("role") == "user":
            return message.get("content", "")
    return messages[-1].get("content", "") if messages else ""


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def sanitize_model_output(content: str, *, message: dict[str, Any] | None = None) -> str:
    """Remove model reasoning traces before content reaches APIs or reports."""
    text = str(content or "")
    reasoning = ""
    if message:
        reasoning = str(message.get("reasoning_content") or "")
    if reasoning and text.startswith(reasoning):
        text = text[len(reasoning) :]
    text = re.sub(r"(?is)<think>.*?</think>", "", text)
    stripped = text.lstrip()
    if stripped.lower().startswith("<think>"):
        return "I cannot provide a final answer from that response."
    return stripped.strip()
