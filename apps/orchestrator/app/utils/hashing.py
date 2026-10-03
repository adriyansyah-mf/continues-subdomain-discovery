import hashlib
import json
from typing import Any


def stable_hash(data: Any) -> str:
    """SHA-256 over canonical JSON (sorted keys) - used for config/state hashes."""
    return hashlib.sha256(json.dumps(data, sort_keys=True, default=str).encode()).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()
