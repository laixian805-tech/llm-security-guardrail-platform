"""有界子进程执行：超时、输出上限、退出码。

输出上限在读取侧强制：任一管道超过 max_output_bytes 立即终止进程并报
OUTPUT_LIMIT，不让扫描器写满磁盘或内存。
"""

from __future__ import annotations

import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from adapters.detectors.errors import DetectorError, ErrorKind

_CHUNK = 64 * 1024


@dataclass(frozen=True)
class BoundedResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_ms: int
    truncated: bool


class _Pump:
    def __init__(self, stream, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self.buffer = bytearray()
        self.exceeded = False
        self.error: BaseException | None = None

    def __call__(self) -> None:
        try:
            while True:
                chunk = self._stream.read(_CHUNK)
                if not chunk:
                    break
                self.buffer += chunk
                if len(self.buffer) > self._limit:
                    self.exceeded = True
                    return
        except BaseException as exc:  # noqa: BLE001 - 记录后由主线程判定
            self.error = exc


def run_bounded(
    argv: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    preexec=None,
) -> BoundedResult:
    started = time.monotonic()
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv 由本仓适配器构造，不经 shell
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(cwd),
            env=env,
            preexec_fn=preexec,
        )
    except FileNotFoundError as exc:
        raise DetectorError(ErrorKind.NOT_INSTALLED, f"找不到可执行文件：{argv[0]}") from exc
    except OSError as exc:
        raise DetectorError(ErrorKind.NOT_INSTALLED, f"无法启动 {argv[0]}：{exc}") from exc

    pumps = [_Pump(proc.stdout, max_output_bytes), _Pump(proc.stderr, max_output_bytes)]
    threads = [threading.Thread(target=pump, daemon=True) for pump in pumps]
    for thread in threads:
        thread.start()

    deadline = started + timeout_seconds
    try:
        while True:
            # 超限必须立即终止：另一个管道可能仍阻塞在读，等不到自然结束。
            if any(pump.exceeded for pump in pumps):
                break
            if not any(thread.is_alive() for thread in threads):
                break
            if time.monotonic() > deadline:
                proc.kill()
                raise DetectorError(
                    ErrorKind.TIMEOUT,
                    f"{Path(argv[0]).name} 超过 {timeout_seconds} 秒未结束，已终止。",
                )
            for thread in threads:
                thread.join(0.05)
    finally:
        for thread in threads:
            thread.join(timeout=5)

    duration_ms = int((time.monotonic() - started) * 1000)

    for pump in pumps:
        if pump.error is not None:
            raise DetectorError(ErrorKind.FAILED, f"读取扫描器输出失败：{pump.error}")

    if any(pump.exceeded for pump in pumps):
        proc.kill()
        proc.wait(timeout=10)
        raise DetectorError(
            ErrorKind.OUTPUT_LIMIT,
            f"扫描器输出超过 {max_output_bytes} 字节上限，已终止。",
        )

    returncode = proc.wait()
    return BoundedResult(
        returncode=returncode,
        stdout=bytes(pumps[0].buffer),
        stderr=bytes(pumps[1].buffer),
        duration_ms=duration_ms,
        truncated=pumps[0].exceeded or pumps[1].exceeded,
    )


def secret_values(env: dict[str, str]) -> dict[str, str]:
    """只保留看起来是密钥的条目，用于错误详情脱敏。"""
    return {
        name: value
        for name, value in env.items()
        if any(marker in name.upper() for marker in ("KEY", "TOKEN", "PASSWORD", "SECRET"))
    }


def redact(text: str, secrets: dict[str, str], placeholder: str = "[密钥已脱敏]") -> str:
    for secret in secrets.values():
        if secret and len(secret) >= 8:
            text = text.replace(secret, placeholder)
    return text
