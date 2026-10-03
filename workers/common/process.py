"""Bounded subprocess execution for scanner binaries.

* argv lists only (never a shell), built from validated job/policy fields
* hard wall-clock timeout and output size cap
* cooperative cancellation (polls a callback, kills the process group)
"""

from __future__ import annotations

import contextlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


class ToolError(RuntimeError):
    pass


class ToolTimeoutError(ToolError):
    pass


class ToolCancelledError(ToolError):
    pass


@dataclass
class ToolResult:
    argv: list[str]
    returncode: int
    stdout_lines: list[str]
    stderr_tail: str
    duration: float
    truncated: bool
    limit_reached: bool = False

    @property
    def ok(self) -> bool:
        """Exit code 0, or stopped by us because the output limit was reached."""
        return self.returncode == 0 or self.limit_reached


def run_tool(
    argv: list[str],
    *,
    timeout: float,
    is_cancelled: Callable[[], bool] | None = None,
    max_output_bytes: int = 64 * 1024 * 1024,
    max_lines: int | None = None,
    poll_interval: float = 2.0,
    env: dict[str, str] | None = None,
) -> ToolResult:
    start = time.monotonic()
    proc = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,  # own process group so we can kill children too
        env={**os.environ, **(env or {})},
    )
    lines: list[str] = []
    limit_hit = threading.Event()
    size = 0
    truncated = False
    stderr_buf: list[str] = []

    def _read_stdout() -> None:
        nonlocal size, truncated
        assert proc.stdout is not None
        for line in proc.stdout:
            if size + len(line) > max_output_bytes:
                truncated = True
                continue  # keep draining so the process does not block
            size += len(line)
            lines.append(line.rstrip("\n"))
            if max_lines is not None and len(lines) >= max_lines:
                truncated = True
                limit_hit.set()
                return

    def _read_stderr() -> None:
        assert proc.stderr is not None
        for line in proc.stderr:
            stderr_buf.append(line)
            if len(stderr_buf) > 200:
                del stderr_buf[:100]

    readers = [threading.Thread(target=_read_stdout, daemon=True), threading.Thread(target=_read_stderr, daemon=True)]
    for t in readers:
        t.start()

    def _kill() -> None:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
        proc.wait(timeout=10)

    try:
        while True:
            try:
                proc.wait(timeout=poll_interval)
                break
            except subprocess.TimeoutExpired:
                if limit_hit.is_set():
                    _kill()  # enough output collected (e.g. MAX_URLS_PER_CRAWL): stop the tool
                    break
                if time.monotonic() - start > timeout:
                    _kill()
                    raise ToolTimeoutError(f"{argv[0]} exceeded {timeout}s") from None
                if is_cancelled is not None and is_cancelled():
                    _kill()
                    raise ToolCancelledError(f"{argv[0]} cancelled") from None
    finally:
        for t in readers:
            t.join(timeout=5)
    return ToolResult(
        argv=argv,
        returncode=proc.returncode,
        stdout_lines=lines,
        stderr_tail="".join(stderr_buf)[-4000:],
        duration=time.monotonic() - start,
        truncated=truncated,
        limit_reached=limit_hit.is_set(),
    )
