from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel

from app.evals.runner import EvalArtifacts
from app.schemas.security import EvalRun


class ReportSummary(BaseModel):
    run_id: str
    adapter: str
    guard_mode: str
    status: str
    started_at: str | None = None
    finished_at: str | None = None
    report_dir: str
    files: dict[str, str]
    summary: dict


class ReportListResponse(BaseModel):
    reports: list[ReportSummary]


class ReportStore:
    def __init__(self, reports_dir: str | Path) -> None:
        self.reports_dir = Path(reports_dir)

    def list_reports(self) -> list[ReportSummary]:
        return [self._summary_from_path(path) for path in self._report_index_paths()]

    def load_artifacts(self, run_id: str) -> EvalArtifacts:
        results_path = self.reports_dir / run_id / "results.json"
        if not results_path.exists():
            raise FileNotFoundError(run_id)
        payload = json.loads(results_path.read_text(encoding="utf-8"))
        run = EvalRun.model_validate(payload)
        return EvalArtifacts(
            run=run,
            report_dir=str(results_path.parent),
            files=self._files_for(results_path.parent),
        )

    def report_file_path(self, run_id: str, file_key: str) -> Path:
        run_dir = self._safe_run_dir(run_id)
        candidates = self._file_candidates(run_dir).get(file_key)
        if candidates is None:
            raise FileNotFoundError(file_key)
        for path in candidates:
            resolved = path.resolve()
            if not str(resolved).startswith(str(run_dir) + "/") and resolved != run_dir:
                raise FileNotFoundError(file_key)
            if resolved.exists() and resolved.is_file():
                return resolved
        raise FileNotFoundError(file_key)

    def _safe_run_dir(self, run_id: str) -> Path:
        root = self.reports_dir.resolve()
        run_dir = (root / run_id).resolve()
        if run_dir != root and str(run_dir).startswith(str(root) + "/"):
            return run_dir
        raise FileNotFoundError(run_id)

    def _report_index_paths(self) -> list[Path]:
        if not self.reports_dir.exists():
            return []
        paths = list(self.reports_dir.glob("*/results.json"))
        paths.extend(
            manifest
            for manifest in self.reports_dir.glob("*/failure-ingest-manifest.json")
            if not (manifest.parent / "results.json").exists()
        )
        return sorted(
            paths,
            key=lambda path: (path.stat().st_mtime, path.parent.name),
            reverse=True,
        )

    def _summary_from_path(self, index_path: Path) -> ReportSummary:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
        if index_path.name == "failure-ingest-manifest.json":
            return self._summary_from_failure_ingest(index_path, payload)
        files = self._files_for(index_path.parent)
        return ReportSummary(
            run_id=str(payload.get("run_id", index_path.parent.name)),
            adapter=str(payload.get("adapter", "unknown")),
            guard_mode=str(payload.get("guard_mode", "unknown")),
            status=str(payload.get("status", "unknown")),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            report_dir=str(index_path.parent),
            files=files,
            summary=dict(payload.get("summary") or {}),
        )

    def _summary_from_failure_ingest(self, manifest_path: Path, payload: dict) -> ReportSummary:
        files = self._files_for(manifest_path.parent)
        created_at = payload.get("created_at")
        return ReportSummary(
            run_id=str(payload.get("run_id", manifest_path.parent.name)),
            adapter="failure_ingest",
            guard_mode=str(payload.get("guard_mode", "unknown")),
            status="completed",
            started_at=created_at,
            finished_at=created_at,
            report_dir=str(manifest_path.parent),
            files=files,
            summary={
                "total_ingested": int(payload.get("total_ingested") or 0),
                "source": payload.get("source"),
                "model": payload.get("model"),
                "original_run_id": payload.get("original_run_id"),
            },
        )

    @staticmethod
    def _files_for(run_dir: Path) -> dict[str, str]:
        files = {}
        for key, paths in ReportStore._file_candidates(run_dir).items():
            for path in paths:
                if path.exists():
                    files[key] = str(path)
                    break
        return files

    @staticmethod
    def _file_candidates(run_dir: Path) -> dict[str, list[Path]]:
        return {
            "json": [run_dir / "results.json"],
            "csv": [run_dir / "results.csv"],
            "html": [
                run_dir / "report.html",
                run_dir / "garak.report.html",
                run_dir / "experiment-report.html",
            ],
            "garak_html": [run_dir / "garak.report.html"],
            "garak_jsonl": [run_dir / "garak.report.jsonl"],
            "promptfoo": [run_dir / "promptfoo-results.json"],
            "config": [run_dir / "garak-config.json"],
            "promptfoo_config": [run_dir / "promptfooconfig.yaml"],
            "stdout": [run_dir / "garak.stdout.log", run_dir / "promptfoo.stdout.log"],
            "stderr": [run_dir / "garak.stderr.log", run_dir / "promptfoo.stderr.log"],
            "experiment_html": [run_dir / "experiment-report.html"],
            "experiment_markdown": [run_dir / "experiment-report.md"],
            "defense_feedback": [run_dir / "defense-feedback.json"],
            "defense_feedback_markdown": [run_dir / "defense-feedback.md"],
            "next_payloads": [run_dir / "next-round-payloads.json", run_dir / "failure-ingest-payloads.json"],
            "failure_manifest": [run_dir / "failure-ingest-manifest.json"],
            "candidate_guard_pack": [run_dir / "candidate-guard-pack.json"],
            "asr_comparison": [run_dir / "asr-comparison.json"],
            "graph_run": [run_dir / "graph-run.json"],
        }
