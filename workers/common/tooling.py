"""Helpers shared by adapters that wrap ProjectDiscovery binaries."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

from workers.common.adapter import RawOutput

_VERSION_RE = re.compile(r"v?(\d+\.\d+\.\d+)")


def binary_version(binary: str, env_var: str) -> str:
    """Pinned version from the image build (env) cross-checked with the binary itself."""
    pinned = os.environ.get(env_var, "").lstrip("v")
    path = shutil.which(binary)
    if path is None:
        return pinned or "unknown"
    try:
        out = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=20)
        m = _VERSION_RE.search(out.stdout + out.stderr)
        detected = m.group(1) if m else None
    except (OSError, subprocess.SubprocessError):
        detected = None
    return detected or pinned or "unknown"


def parse_jsonl(lines: list[str]) -> RawOutput:
    raw = RawOutput()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            raw.malformed.append(line[:4000])
            continue
        if isinstance(obj, dict):
            raw.records.append(obj)
        else:
            raw.malformed.append(line[:4000])
    return raw


_HEADER_RE = re.compile(r"^[A-Za-z0-9-]{1,64}: [\x21-\x7e][\x20-\x7e]{0,255}$")


def identification_header() -> str | None:
    """BB_REQUEST_HEADER validated as a single safe "Name: value" header (no CR/LF injection)."""
    from app.config import get_settings

    value = get_settings().request_header.strip()
    if not value:
        return None
    if not _HEADER_RE.match(value):
        raise ValueError("BB_REQUEST_HEADER must look like 'X-Bug-Bounty: handle' (printable ASCII, one line)")
    return value
