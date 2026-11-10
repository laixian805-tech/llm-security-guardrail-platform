"""证据引用。

证据引用只保存定位信息，不内联敏感正文：完整 secret、API Key 和任意
prompt 正文不进入契约。列表 API 也只回传引用，不回传大段原文。
"""

from __future__ import annotations

from pydantic import Field

from domain.asset import StrictModel


class EvidenceRef(StrictModel):
    kind: str = Field(min_length=1)
    uri: str = Field(min_length=1)
    # 人类可读的短标注，不是原文摘录。
    label: str | None = None
