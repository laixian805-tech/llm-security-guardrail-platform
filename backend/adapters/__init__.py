"""对外集成适配器：detectors / agents / providers。

适配器只做协议转换和子进程隔离，不写 Asset 状态、不创建 Incident、
不直接执行治理动作。
"""
