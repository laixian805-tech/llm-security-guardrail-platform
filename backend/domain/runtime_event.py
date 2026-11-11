"""RuntimeEvent 契约。

RuntimeEvent 是采集器观测到的运行时事实（进程创建、文件访问、网络连接
等）。与 Intent 的分界：Intent 是产品自己声明的操作请求，RuntimeEvent
是主机侧观测到的现象，两者可以不一致，也允许事件没有归因。

契约里不含完整 secret、密钥参数或 prompt 正文；进程命令行这类可能带
机密的内容不进契约，资源定位只用 host/port/path 字段。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from domain.asset import StrictModel
from domain.evidence import EvidenceRef


class ProcessInfo(StrictModel):
    """事件相关的进程信息。采集不到时字段留空，不用猜测值填充。"""

    pid: int | None = Field(default=None, ge=0)
    ppid: int | None = Field(default=None, ge=0)
    executable: str | None = None


class ResourceInfo(StrictModel):
    """事件涉及的资源定位。三类资源互斥出现，用不到的留空。"""

    host: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    path: str | None = None


class RuntimeEvent(StrictModel):
    event_id: str = Field(min_length=1)
    host_id: str = Field(min_length=1)
    # 采集器标识，如 linux-audit-v1；同一主机可有多个采集器。
    collector_id: str = Field(min_length=1)
    device_id: str = Field(min_length=1)
    # 采集器能直接关联的执行边界；关联不了留空，由 P2 的 EventAttribution
    # 建立权威关联。
    execution_id: str | None = None
    # 采集器对调用方的提示（如 hook 观测到的 tool_call_id），不是归因结论。
    intent_ref: str | None = None
    event_type: str = Field(min_length=1)
    occurred_at: datetime
    received_at: datetime
    process: ProcessInfo | None = None
    resource: ResourceInfo | None = None
    action: str | None = None
    result: str | None = None
    # 同一采集器内的事件序号，用于排序与丢流检测。
    sequence: int | None = Field(default=None, ge=0)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
