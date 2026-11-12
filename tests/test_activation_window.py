"""激活状态派生与时间线准入窗口。

两件事同一个根源：状态只能来自平台持有的证据，关联不能靠"同一个实例 ID 就
算相关"。

- ``activation_state`` 以前恒为 unknown（平台没有产品加载证据）。现在准入
  事务带 ``product_loaded``，只有产品会话真的认识这个 skill 才记 enabled；
  探测不可用仍然是 unknown，绝不因为"目录里有文件"就说启用。
- 时间线接入准入以前按实例全量拉，会把该实例历史上每一次准入都挂到每条执行
  上。现在限定事务活跃区间与执行窗口有交集。
"""
import pytest

from services.asset_service import derive_activation_state
from services.timeline_service import TimelineService
from storage.repositories import Storage
from test_console_auth import api, admin_token, call


def _admission(**overrides):
    base = {
        "admission_id": "admission_1",
        "asset_instance_id": "inst_1",
        "content_hash": "a" * 64,
        "product_id": None,
        "product_loaded": None,
        "state": "verified",
        "transaction_id": "txn_1",
        "created_at": "2026-11-12T00:00:00+00:00",
        "updated_at": "2026-11-12T00:01:00+00:00",
    }
    base.update(overrides)
    return base


# --- activation_state：四态都要有明确依据 ---------------------------------

def test_no_product_target_is_unknown():
    """只进平台托管存储：产品侧不存在"加载"这件事。"""
    assert derive_activation_state([_admission(product_id=None)]) == "unknown"


def test_confirmed_product_load_is_enabled():
    rows = [_admission(product_id="claude-code", product_loaded=1, state="verified")]
    assert derive_activation_state(rows) == "enabled"


def test_reconciled_after_reverify_stays_enabled():
    rows = [_admission(product_id="claude-code", product_loaded=1, state="reconciled")]
    assert derive_activation_state(rows) == "enabled"


def test_verified_but_unprobed_is_unknown_not_enabled():
    """探测不可用：文件在、verify 过了，但没有"产品认识它"的证据。"""
    rows = [_admission(product_id="claude-code", product_loaded=None, state="verified")]
    assert derive_activation_state(rows) == "unknown"


def test_product_denial_is_disabled():
    rows = [_admission(product_id="claude-code", product_loaded=0, state="verified")]
    assert derive_activation_state(rows) == "disabled"


def test_rolled_back_is_disabled_even_if_previously_loaded():
    rows = [
        _admission(admission_id="a2", product_id="claude-code", product_loaded=1,
                   state="rolled_back", updated_at="2026-11-12T00:05:00+00:00"),
        _admission(admission_id="a1", product_id="claude-code", product_loaded=1, state="verified"),
    ]
    assert derive_activation_state(rows) == "disabled"


def test_latest_targeted_admission_wins():
    rows = [
        _admission(admission_id="a2", product_id="claude-code", product_loaded=0,
                   state="verified", updated_at="2026-11-12T00:09:00+00:00"),
        _admission(admission_id="a1", product_id="claude-code", product_loaded=1,
                   state="verified", updated_at="2026-11-12T00:01:00+00:00"),
    ]
    assert derive_activation_state(rows) == "disabled"


def test_untargeted_transaction_does_not_mask_targeted_state():
    rows = [
        _admission(admission_id="a2", product_id=None, state="committed",
                   updated_at="2026-11-12T00:09:00+00:00"),
        _admission(admission_id="a1", product_id="claude-code", product_loaded=1,
                   updated_at="2026-11-12T00:01:00+00:00"),
    ]
    assert derive_activation_state(rows) == "enabled"


def test_committed_but_not_verified_is_unknown():
    rows = [_admission(product_id="claude-code", product_loaded=None, state="committed")]
    assert derive_activation_state(rows) == "unknown"


# --- 时间线：准入必须落在执行窗口内 ---------------------------------------

def _insert(storage: Storage, **fields) -> None:
    row = _admission(**fields)
    columns = ",".join(row)
    marks = ",".join("?" * len(row))
    with storage.connection() as conn:
        conn.execute(f"INSERT INTO admissions ({columns}) VALUES ({marks})", list(row.values()))
        conn.commit()


def test_timeline_excludes_admissions_outside_execution_window(tmp_path):
    storage = Storage(tmp_path / "db.sqlite")
    _insert(storage, admission_id="a_old", transaction_id="t_old",
            created_at="2026-11-01T00:00:00+00:00", updated_at="2026-11-01T00:05:00+00:00")
    _insert(storage, admission_id="a_new", transaction_id="t_new",
            created_at="2026-11-12T00:00:00+00:00", updated_at="2026-11-12T00:05:00+00:00")
    service = TimelineService(storage)
    rows = service._admissions("inst_1",
        started_at="2026-11-12T00:00:00+00:00", ended_at="2026-11-12T00:10:00+00:00")
    assert [row["admission_id"] for row in rows] == ["a_new"]


def test_admission_spanning_the_window_is_kept(tmp_path):
    """窗口前开始、窗口后仍在进行的事务与本次执行有交集，保留。"""
    storage = Storage(tmp_path / "db.sqlite")
    _insert(storage, admission_id="a_spanning", transaction_id="t_span",
            state="staged", created_at="2026-11-11T23:50:00+00:00",
            updated_at="2026-11-12T00:20:00+00:00")
    service = TimelineService(storage)
    rows = service._admissions("inst_1",
        started_at="2026-11-12T00:00:00+00:00", ended_at="2026-11-12T00:10:00+00:00")
    assert [row["admission_id"] for row in rows] == ["a_spanning"]


def test_admission_updated_before_window_starts_is_excluded(tmp_path):
    """窗口开始前就已经收尾的事务，与这次执行无关。"""
    storage = Storage(tmp_path / "db.sqlite")
    _insert(storage, admission_id="a_closed", transaction_id="t_closed",
            created_at="2026-11-11T23:00:00+00:00", updated_at="2026-11-11T23:30:00+00:00")
    service = TimelineService(storage)
    rows = service._admissions("inst_1",
        started_at="2026-11-12T00:00:00+00:00", ended_at="2026-11-12T00:10:00+00:00")
    assert rows == []


def test_zulu_timestamps_compare_correctly(tmp_path):
    """历史数据里有 Z 结尾时间，字符串直接比较会错序，必须解析后比。"""
    storage = Storage(tmp_path / "db.sqlite")
    _insert(storage, admission_id="a_zulu", transaction_id="t_zulu",
            created_at="2026-11-12T00:00:00Z", updated_at="2026-11-12T00:05:00Z")
    service = TimelineService(storage)
    rows = service._admissions("inst_1",
        started_at="2026-11-12T00:00:00+00:00", ended_at="2026-11-12T00:10:00+00:00")
    assert [row["admission_id"] for row in rows] == ["a_zulu"]


def test_open_execution_uses_now_as_window_end(tmp_path):
    storage = Storage(tmp_path / "db.sqlite")
    _insert(storage, admission_id="a_live", transaction_id="t_live",
            created_at="2026-11-12T00:00:00+00:00", updated_at="2026-11-12T00:05:00+00:00")
    service = TimelineService(storage)
    rows = service._admissions("inst_1", started_at="2026-11-12T00:00:00+00:00", ended_at=None)
    assert [row["admission_id"] for row in rows] == ["a_live"]


# --- 过滤参数：非法状态名必须报错，不能静默返回空集 -----------------------

def test_invalid_state_filter_is_rejected(api, admin_token):
    for path in ("?activation_state=enabledd", "?installation_state=install",
                 "?runtime_state=live"):
        response = call(api.base, "GET", "/api/v1/assets" + path, token=admin_token)
        assert response.status_code == 400, f"{path} -> {response.status_code}"


def test_valid_state_filter_is_accepted(api, admin_token):
    response = call(api.base, "GET", "/api/v1/assets?activation_state=unknown",
                    token=admin_token)
    assert response.status_code == 200
