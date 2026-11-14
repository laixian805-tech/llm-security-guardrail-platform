"""P1 扩展评测守卫：保证 54 事件多跳/并发归因集、M0->M4 四层消融与千次良性负载可复现。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))


def test_scale_attribution_benchmark_exceeds_50_events_with_zero_fp(tmp_path: Path):
    import eval_attribution_scale as sc

    out = tmp_path / "scale.json"
    assert sc.main(json_out=out) == 0
    fresh = json.loads(out.read_text(encoding="utf-8"))
    saved = json.loads((ROOT / "docs" / "acceptance" / "attribution-scale-eval.json").read_text(encoding="utf-8"))
    assert fresh == saved
    assert fresh["events_evaluated"] >= 50
    assert fresh["precision"] == 1.0
    assert fresh["recall_unambiguous"] == 1.0
    assert fresh["negative_fpr"] == 0.0
    assert fresh["conflict_preserved_rate"] == 1.0


def test_four_layer_ablation_shows_marginal_gain_across_layers(tmp_path: Path):
    import eval_ablation as ab

    out = tmp_path / "ablation.json"
    assert ab.main(json_out=out) == 0
    fresh = json.loads(out.read_text(encoding="utf-8"))
    saved = json.loads((ROOT / "docs" / "acceptance" / "ablation-eval.json").read_text(encoding="utf-8"))
    assert fresh == saved
    v = fresh["variants"]
    assert v["M4_full_asgp"]["f1"] > v["M1_hook_only"]["f1"]
    assert v["M4_full_asgp"]["fpr"] < v["M2_audit_only"]["fpr"]
    assert v["M4_full_asgp"]["provenance_coverage"] == 1.0
    assert v["M3_asgp_no_source_kind"]["provenance_coverage"] == 0.0


def test_benign_1k_dev_workload_has_zero_false_positives(tmp_path: Path):
    import eval_benign_workload as bw

    out = tmp_path / "benign.json"
    assert bw.main(total_calls=200, json_out=out) == 0
    saved = json.loads((ROOT / "docs" / "acceptance" / "benign-workload-eval.json").read_text(encoding="utf-8"))
    assert saved["tool_calls"] == 1000
    assert saved["fp_per_1k_calls"] == 0.0
