"""Idempotent first-start seeding: default scan policies, schedules and the bootstrap admin API key."""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import Settings
from app.models import ApiKey, ScanPolicy, Schedule
from app.models.enums import Role
from app.schemas.policy import DEFAULT_POLICIES, PolicyConfig
from app.utils.hashing import sha256_text

log = logging.getLogger(__name__)

# Defaults from the platform spec. Seeded DISABLED: nothing scans until an operator enables it.
DEFAULT_SCHEDULES = [
    ("dns-periodic", "dns", 6 * 3600),
    ("httpx-periodic", "httpx", 24 * 3600),
    ("tlsx-periodic", "tlsx", 24 * 3600),
]


def seed(session: Session, settings: Settings) -> None:
    for name, (description, raw) in DEFAULT_POLICIES.items():
        if session.execute(select(ScanPolicy).where(ScanPolicy.name == name)).scalar_one_or_none() is None:
            cfg = PolicyConfig.model_validate(raw)
            session.add(ScanPolicy(name=name, description=description, config=cfg.model_dump(), active=True))
            log.info("seeded scan policy", extra={"policy": name})
    session.flush()
    for name, scanner, interval in DEFAULT_SCHEDULES:
        if session.execute(select(Schedule).where(Schedule.name == name)).scalar_one_or_none() is None:
            session.add(Schedule(name=name, scanner=scanner, interval_seconds=interval, enabled=False))
    if settings.bootstrap_admin_key is not None:
        key = settings.bootstrap_admin_key.get_secret_value()
        if len(key) < 24:
            raise ValueError("BB_BOOTSTRAP_ADMIN_KEY must be at least 24 characters")
        h = sha256_text(key)
        if session.execute(select(ApiKey).where(ApiKey.key_hash == h)).scalar_one_or_none() is None:
            existing = session.execute(select(ApiKey).where(ApiKey.name == "bootstrap-admin")).scalar_one_or_none()
            if existing is None:
                session.add(ApiKey(name="bootstrap-admin", key_hash=h, role=Role.ADMIN.value, active=True))
            else:  # rotated in .env / secret
                existing.key_hash = h
            log.info("bootstrap admin API key registered")
