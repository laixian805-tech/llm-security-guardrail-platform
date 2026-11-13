"""归因评测集：四项专项指标必须真的能测出东西。

合成集的价值不在于数字好看，而在于每一项都能被点亮。如果错误强关联率
在任何输入下恒为 0，那说明的是没测，而不是没问题——所以这里固定住一个
已知会产出 0.99 分错误强关联的场景，并断言指标抓到了它。
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts" / "lab"))

from eval_attribution import SCENARIOS, evaluate, seed  # noqa: E402


def run(tmp_path):
    db = tmp_path / "eval.db"
    seed(db)
    return evaluate(db)


def test_collector_hint_scenario_produces_a_wrong_strong_edge(tmp_path):
    result = run(tmp_path)
    detail = result["focus"]["wrong_strong_detail"]
    assert [row["event_id"] for row in detail] == ["e_hint_1"]
    assert detail[0]["method"] == "hook_id" and detail[0]["score"] == 0.99
    # 指标必须非零：恒为 0 的错误强关联率证明不了任何事。
    assert result["focus"]["false_strong_rate"] > 0


def test_unattributed_rate_denominator_is_should_attribute(tmp_path):
    """未归因率的分母是"本该归因"的事件，不是全部受评事件。

    否则正确留空的负样本会被算成失败——5 个 unresolved 场景全部正确留空，
    未归因率却会显示成 5/13。
    """
    result = run(tmp_path)
    focus = result["focus"]
    assert focus["counts"]["should_attribute"] == 8
    assert focus["counts"]["subjects"] == 13
    assert focus["counts"]["unattributed_events"] == 2
    assert focus["unattributed_rate"] == 0.25
    assert focus["no_attribution_rate"] == round(7 / 13, 4)


def test_conflict_is_kept_not_resolved(tmp_path):
    result = run(tmp_path)
    assert result["focus"]["conflict_recall"] == 1.0
    assert result["focus"]["conflict_false_positive_rate"] == 0.0
    assert result["focus"]["multi_candidate_rate"] > 0


def test_traces_cover_the_three_required_kinds(tmp_path):
    result = run(tmp_path)
    kinds = {trace["kind"] for trace in result["traces"]}
    assert kinds == {"one_to_one", "one_to_many", "unresolved"}
    # 每条 trace 都必须能回答"该归给谁、实际归给谁、判定了什么"。
    for trace in result["traces"]:
        assert trace["trace_id"] and trace["scenario"] and trace["verdict"]
        assert isinstance(trace["expected"], list) and isinstance(trace["attributed"], list)
    wrong = [t for t in result["traces"] if t["verdict"] == "wrong"]
    assert [t["event_id"] for t in wrong] == ["e_hint_1"]


def test_every_scenario_declares_a_trace_kind():
    for scene in SCENARIOS:
        assert scene["trace"] in ("one_to_one", "one_to_many", "unresolved"), scene["name"]


def test_checked_in_eval_report_matches_the_harness(tmp_path):
    """docs/acceptance/attribution-eval.json 必须是这个 harness 的当前输出。

    否则验收文档里的数字会和代码脱节，而这正是"算不出 Precision/Recall"
    抱怨的来源——数字必须可复现。
    """
    recorded = json.loads(
        (ROOT / "docs" / "acceptance" / "attribution-eval.json").read_text(encoding="utf-8"))
    fresh = run(tmp_path)
    for key in ("scenarios", "events_total", "should_attribute", "selected",
                "any_edge", "by_method", "focus", "by_trace_kind"):
        assert recorded[key] == fresh[key], key
