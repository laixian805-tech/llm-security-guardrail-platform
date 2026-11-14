"""零外部依赖的评测统计学置信区间工具（Wilson Score 95% CI）。"""

from __future__ import annotations

import math
from typing import Any

Z_95 = 1.959963984540054


def wilson_ci(successes: int, total: int, z: float = Z_95) -> dict[str, Any]:
    """计算二项分布比例的 Wilson 得分区间（适合中小样本与 0%/100% 边界）。"""
    if total <= 0:
        return {"k": 0, "n": 0, "point": None, "ci_low": None, "ci_high": None}
    k = max(0, min(int(successes), int(total)))
    n = int(total)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z / denom) * math.sqrt((p * (1.0 - p) / n) + (z2 / (4.0 * n * n)))
    return {
        "k": k,
        "n": n,
        "point": round(p, 4),
        "ci_low": round(max(0.0, center - half), 4),
        "ci_high": round(min(1.0, center + half), 4),
    }
