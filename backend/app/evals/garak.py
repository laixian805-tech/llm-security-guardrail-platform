from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.evals.runner import EvalArtifacts
from app.guardrails.pipeline import GuardEngine, GuardMode
from app.schemas.security import AttackCategory, AttackResult, EvalRun, EvalStatus

_LOCAL_TO_GARAK_PROBES: dict[str, tuple[str, ...]] = {
    "injection": ("promptinject",),
    "role_override": ("sysprompt_extraction", "leakreplay"),
    "encoding": ("encoding",),
    "jailbreak": ("dan",),
    "direct_injection": ("promptinject",),
    "role_takeover": ("sysprompt_extraction",),
    "long_context_hijack": ("dan",),
    "rag_poisoning": ("latentinjection",),
    "web_poisoning": ("web_injection",),
    "tool_return_poisoning": ("promptinject",),
    "unauthorized_tool_call": ("promptinject",),
}

_DEFAULT_GARAK_PROBES: tuple[str, ...] = (
    "promptinject",
    "sysprompt_extraction",
    "encoding",
    "dan",
)

_MODULE_CATEGORY_MAP: dict[str, AttackCategory] = {
    "dan": AttackCategory.JAILBREAK,
    "encoding": AttackCategory.ENCODING,
    "latentinjection": AttackCategory.INJECTION,
    "leakreplay": AttackCategory.ROLE_OVERRIDE,
    "promptinject": AttackCategory.INJECTION,
    "sysprompt_extraction": AttackCategory.ROLE_OVERRIDE,
    "visual_jailbreak": AttackCategory.JAILBREAK,
    "web_injection": AttackCategory.INJECTION,
}


class GarakEvalRunner:
    def __init__(
        self,
        *,
        reports_dir: str | Path,
        service_base_url: str,
        model_name: str,
        python_executable: str | None = None,
        timeout_seconds: int = 900,
    ) -> None:
        self.reports_dir = Path(reports_dir)
        self.service_base_url = service_base_url.rstrip("/")
        self.model_name = model_name
        self.python_executable = python_executable or sys.executable
        self.timeout_seconds = timeout_seconds

    def run_with_artifacts(
        self,
        *,
        probes: list[str],
        guard_mode: GuardMode,
        guard_engine: GuardEngine | None = None,
        run_id: str | None = None,
        garak_probe_spec: str | None = None,
        garak_detector_spec: str | None = None,
    ) -> EvalArtifacts:
        self._require_garak()

        run_id = run_id or f"garak-{uuid4().hex[:8]}"
        started_at = datetime.now(timezone.utc)
        run_dir = self.reports_dir / run_id
        run_dir.mkdir(parents=True, exist_ok=True)

        probe_spec = garak_probe_spec or self._resolve_probe_spec(probes)
        report_prefix = run_dir / "garak"
        config_path = run_dir / "garak-config.json"
        config_payload = self._build_config(guard_mode=guard_mode, guard_engine=guard_engine, report_dir=run_dir)
        config_path.write_text(
            json.dumps(config_payload, ensure_ascii=True, indent=2),
            encoding="utf-8",
        )

        command = [
            self.python_executable,
            "-m",
            "garak",
            "--config",
            str(config_path),
            "--target_type",
            "openai.OpenAICompatible",
            "--target_name",
            self.model_name,
            "--probes",
            probe_spec,
            "--report_prefix",
            str(report_prefix),
            "--parallel_attempts",
            "1",
            "--parallel_requests",
            "1",
            "--generations",
            "1",
            "--narrow_output",
        ]
        if garak_detector_spec:
            command.extend(["--detectors", garak_detector_spec])

        env = os.environ.copy()
        env.setdefault("OPENAICOMPATIBLE_API_KEY", "dummy")

        stdout_path = run_dir / "garak.stdout.log"
        stderr_path = run_dir / "garak.stderr.log"
        try:
            completed = subprocess.run(
                command,
                cwd=run_dir,
                env=env,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_path.write_text(_timeout_text(exc.stdout), encoding="utf-8")
            stderr_path.write_text(_timeout_text(exc.stderr), encoding="utf-8")
            raise RuntimeError(
                f"Garak run timed out after {self.timeout_seconds} seconds. "
                f"See {stderr_path} for details."
            ) from exc

        stdout_path.write_text(completed.stdout, encoding="utf-8")
        stderr_path.write_text(completed.stderr, encoding="utf-8")

        if completed.returncode != 0:
            raise RuntimeError(
                "Garak run failed with exit code "
                f"{completed.returncode}. See {stderr_path} for details."
            )

        report_path = run_dir / "garak.report.jsonl"
        html_path = run_dir / "garak.report.html"
        hitlog_path = run_dir / "garak.hitlog.jsonl"
        if not report_path.exists():
            output_summary = _garak_output_summary(completed.stdout, completed.stderr)
            message = f"Garak did not produce {report_path}."
            if output_summary:
                message = f"{message} {output_summary}"
            raise RuntimeError(message)

        results = self._parse_report(run_id=run_id, report_path=report_path)
        finished_at = datetime.now(timezone.utc)
        run = EvalRun(
            run_id=run_id,
            adapter="garak",
            guard_mode=_guard_mode_value(guard_mode),
            probes=[part for part in probe_spec.split(",") if part],
            status=EvalStatus.COMPLETED,
            started_at=started_at,
            finished_at=finished_at,
            results=results,
        )

        normalized_results_path = run_dir / "results.json"
        normalized_results_path.write_text(
            json.dumps(run.model_dump(mode="json"), ensure_ascii=True, indent=2),
            encoding="utf-8",
        )

        files = {
            "json": str(normalized_results_path),
            "jsonl": str(report_path),
            "html": str(html_path),
            "config": str(config_path),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
        if hitlog_path.exists():
            files["hitlog"] = str(hitlog_path)

        return EvalArtifacts(
            run=run,
            report_dir=str(run_dir),
            files=files,
        )

    def _build_config(self, *, guard_mode: GuardMode, guard_engine: GuardEngine | None, report_dir: Path) -> dict:
        extra_body = {"guard_mode": guard_mode.value}
        if guard_engine is not None:
            extra_body["guard_engine"] = guard_engine.value
        return {
            "system": {
                "lite": True,
                "narrow_output": True,
                "parallel_attempts": 1,
                "parallel_requests": 1,
                "show_z": False,
                "verbose": 0,
            },
            "run": {
                "generations": 1,
                "eval_threshold": 0.5,
            },
            "plugins": {
                "generators": {
                    "openai": {
                        "OpenAICompatible": {
                            "name": self.model_name,
                            "uri": f"{self.service_base_url}/v1/",
                            "temperature": 0.0,
                            "retry_json": True,
                            "extra_params": {"extra_body": extra_body},
                        }
                    }
                }
            },
            "reporting": {
                "report_dir": str(report_dir),
                "taxonomy": None,
                "report_prefix": str(report_dir / "garak"),
            },
        }

    @staticmethod
    def _parse_report(*, run_id: str, report_path: Path) -> list[AttackResult]:
        results: list[AttackResult] = []
        for line in report_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("entry_type") != "eval":
                continue
            results.append(_record_to_attack_result(run_id, record))
        return results

    @staticmethod
    def _resolve_probe_spec(probes: list[str]) -> str:
        resolved: list[str] = []
        for probe in probes:
            mapped = _LOCAL_TO_GARAK_PROBES.get(probe)
            if mapped is None:
                resolved.append(probe)
                continue
            for item in mapped:
                if item not in resolved:
                    resolved.append(item)
        if not resolved:
            resolved = list(_DEFAULT_GARAK_PROBES)
        return ",".join(resolved)

    @staticmethod
    def _require_garak() -> None:
        if importlib.util.find_spec("garak") is None:
            raise RuntimeError(
                "Garak is not installed in the active backend environment. "
                'Install it with `python -m pip install -e ".[garak]"`.'
            )


def _guard_mode_value(mode: GuardMode) -> str:
    if mode == GuardMode.AUDIT:
        return "audit"
    if mode == GuardMode.OFF:
        return "off"
    return "on"


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _garak_output_summary(stdout: str, stderr: str, *, max_length: int = 500) -> str:
    output = "\n".join(part.strip() for part in [stdout, stderr] if part.strip())
    if not output:
        return ""
    output = " ".join(output.split())
    if len(output) > max_length:
        output = f"{output[:max_length]}..."
    return f"Garak output: {output}"


def _record_to_attack_result(run_id: str, record: dict) -> AttackResult:
    probe_path = str(record.get("probe", "")).removeprefix("probes.")
    detector_path = str(record.get("detector", "")).removeprefix("detectors.")
    module_name, _, probe_variant = probe_path.partition(".")
    total_evaluated = int(record.get("total_evaluated", record.get("total", 0)) or 0)
    passed = int(record.get("passed", 0) or 0)
    blocked = total_evaluated > 0 and passed == total_evaluated
    pass_ratio = (passed / total_evaluated) if total_evaluated else 0.0
    attack_success_rate = 1.0 - pass_ratio

    return AttackResult(
        run_id=run_id,
        probe=probe_path or "garak",
        category=_map_probe_category(module_name, probe_variant),
        variant=probe_variant or module_name or "unknown",
        prompt=f"Garak probe {probe_path or 'unknown'}",
        response=(
            f"Detector {detector_path or 'unknown'} reported "
            f"attack_success_rate={attack_success_rate:.2%} "
            f"with passed={passed}/{total_evaluated}."
        ),
        blocked=blocked,
        guard_triggered=None if blocked else detector_path or None,
        confidence=pass_ratio,
        latency_ms=0,
    )


def _map_probe_category(module_name: str, probe_variant: str) -> AttackCategory:
    if module_name in _MODULE_CATEGORY_MAP:
        return _MODULE_CATEGORY_MAP[module_name]
    probe_text = f"{module_name}.{probe_variant}".lower()
    if "encoding" in probe_text:
        return AttackCategory.ENCODING
    if "dan" in probe_text or "jailbreak" in probe_text:
        return AttackCategory.JAILBREAK
    if "system" in probe_text or "role" in probe_text or "leak" in probe_text:
        return AttackCategory.ROLE_OVERRIDE
    return AttackCategory.INJECTION
