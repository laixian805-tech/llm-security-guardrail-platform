import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/lab"))

from eval_external_benchmarks import main as run_external  # noqa: E402
from eval_stats import wilson_ci  # noqa: E402


def test_wilson_ci_bounds():
    full = wilson_ci(24, 24)
    assert full["point"] == 1.0
    assert 0.85 <= full["ci_low"] < 1.0
    assert full["ci_high"] == 1.0
    zero = wilson_ci(0, 16)
    assert zero["point"] == 0.0
    assert zero["ci_low"] == 0.0
    assert 0.15 < zero["ci_high"] < 0.25


def test_external_benchmarks_suite_reproducible(tmp_path):
    res = run_external(json_out=tmp_path / "ext.json")
    assert res["total_cases"] == 40
    assert res["lineage_inferred_without_env"] == 40
    m4 = res["overall"]["M4_full_asgp"]
    m2 = res["overall"]["M2_regex_dlp"]
    assert m4["f1"] > m2["f1"]
    assert m4["fpr"] == 0.0
    assert m4["recall"] >= 0.95
