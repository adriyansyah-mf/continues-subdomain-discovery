# User Auth + Dynamic Settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add DB-backed username/password login (JWT) to the management console, coexisting with API keys, plus a whitelist of dynamic settings overridable at runtime from the DB.

**Architecture:** New `users` and `settings` tables in PostgreSQL. `get_principal` accepts either a Bearer JWT (humans/UI) or an `X-API-Key` (workers/CLI, unchanged). First admin is created via an open-only-when-empty setup endpoint. A `dynamic_setting(key)` resolver reads a whitelisted override from the DB (short-TTL cache) and falls back to the env `Settings`. The `/ui` console gains login/setup gates and admin Users/Settings tabs.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy, Alembic, PostgreSQL, Redis (settings cache), pytest. New pinned deps: `bcrypt`, `pyjwt`.

**Spec:** `docs/superpowers/specs/2026-10-04-user-auth-dynamic-settings-design.md`

## Global Constraints

- Pin every new dependency to an exact version in `apps/orchestrator/pyproject.toml` (no ranges). Match the file's existing `name==x.y.z` style.
- API-key auth (`sha256_text`, `ApiKey` model, `X-API-Key`) is unchanged; workers, `bbctl`, and the autoscaler must keep working.
- RBAC roles reuse the existing `Role` enum (`viewer`/`operator`/`admin`) and `require()`/`ROLE_RANK`.
- Infra/secret config stays env-only; only keys in `DYNAMIC_KEYS` may be overridden.
- `ruff` + `ruff format` + `mypy` must stay clean (`make lint`); embedded HTML in `ui.py` is E501-ignored already.
- Passwords: bcrypt only; min length 10, max length 128 (bcrypt 72-byte limit → encode and reject > 72 bytes after UTF-8 with a clear error, or truncate-safe via pre-hash — see Task 2).
- JWT: HS256, signed with `BB_JWT_SECRET`; default TTL 43200s (12h), itself a dynamic key `AUTH_TOKEN_TTL_SECONDS`.
- Migrations are hand-written under `migrations/versions/` following the existing `revision`/`down_revision` chain; current head is `0007`.

---

## File Structure

- `apps/orchestrator/app/models/user.py` — `User` model (new).
- `apps/orchestrator/app/models/settings.py` — `SettingOverride` model (new).
- `apps/orchestrator/app/models/__init__.py` — export both (modify).
- `apps/orchestrator/app/utils/hashing.py` — add `hash_password`/`verify_password` (modify).
- `apps/orchestrator/app/utils/jwt.py` — `issue_token`/`decode_token` (new).
- `apps/orchestrator/app/config.py` — add `jwt_secret`, `auth_token_ttl_seconds`, `settings_cache_ttl` (modify).
- `apps/orchestrator/app/services/users.py` — user CRUD + auth service (new).
- `apps/orchestrator/app/services/settings_store.py` — `DYNAMIC_KEYS`, `dynamic_setting`, override CRUD (new).
- `apps/orchestrator/app/api/deps.py` — extend `get_principal` to accept Bearer JWT (modify).
- `apps/orchestrator/app/api/auth.py` — `/auth/*` routes (new).
- `apps/orchestrator/app/api/users.py` — `/users` routes (new).
- `apps/orchestrator/app/api/settings.py` — `/settings` routes (new).
- `apps/orchestrator/app/schemas/api.py` — auth/user/settings request-response models (modify).
- `apps/orchestrator/app/main.py` — include new routers (modify).
- `apps/orchestrator/app/api/ui.py` — login/setup gate + Users/Settings tabs (modify).
- `apps/orchestrator/app/cli/main.py` — `bbctl user`, `bbctl settings` (modify).
- `migrations/versions/20261004_0008_users_settings.py` — tables (new).
- `.env.example` — `BB_JWT_SECRET`, `AUTH_TOKEN_TTL_SECONDS` (modify).
- Tests: `tests/unit/test_auth.py`, `tests/unit/test_settings_store.py`, `tests/integration/test_auth.py` (new).

---

### Task 1: Pin dependencies (bcrypt, pyjwt)

**Files:**
- Modify: `apps/orchestrator/pyproject.toml` (the `dependencies = [` list)

**Interfaces:**
- Produces: `bcrypt` and `jwt` (PyJWT) importable in the orchestrator image.

- [ ] **Step 1: Add the two pins**

In `apps/orchestrator/pyproject.toml`, inside `dependencies = [ ... ]`, add (keep the list alph&version style consistent with neighbours):

```toml
    "bcrypt==4.2.1",
    "pyjwt==2.10.1",
```

- [ ] **Step 2: Rebuild the image and confirm imports**

Run:
```bash
make build
docker compose run --rm --no-deps orchestrator python -c "import bcrypt, jwt; print(bcrypt.__version__, jwt.__version__)"
```
Expected: prints the two versions, no ImportError.

- [ ] **Step 3: Commit**

```bash
git add apps/orchestrator/pyproject.toml
git commit -m "build: pin bcrypt and pyjwt for user auth"
```

---

### Task 2: Password hashing helpers

**Files:**
- Modify: `apps/orchestrator/app/utils/hashing.py`
- Test: `tests/unit/test_auth.py`

**Interfaces:**
- Produces: `hash_password(password: str) -> str`, `verify_password(password: str, hashed: str) -> bool`, and module constants `MIN_PASSWORD_LEN = 10`, `MAX_PASSWORD_LEN = 128`. Raises `ValueError` on out-of-range length.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_auth.py`:

```python
import pytest

from app.utils.hashing import hash_password, verify_password, MIN_PASSWORD_LEN


def test_hash_and_verify_roundtrip():
    h = hash_password("correct horse 10")
    assert h != "correct horse 10"
    assert verify_password("correct horse 10", h) is True
    assert verify_password("wrong", h) is False


def test_password_length_bounds():
    with pytest.raises(ValueError):
        hash_password("short")  # < MIN_PASSWORD_LEN
    with pytest.raises(ValueError):
        hash_password("x" * 129)  # > MAX_PASSWORD_LEN
    assert MIN_PASSWORD_LEN == 10
```

- [ ] **Step 2: Run test to verify it fails**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q`
Expected: FAIL (ImportError: cannot import name `hash_password`).

- [ ] **Step 3: Implement the helpers**

Append to `apps/orchestrator/app/utils/hashing.py`:

```python
import bcrypt

MIN_PASSWORD_LEN = 10
MAX_PASSWORD_LEN = 128


def hash_password(password: str) -> str:
    if not MIN_PASSWORD_LEN <= len(password) <= MAX_PASSWORD_LEN:
        raise ValueError(f"password must be {MIN_PASSWORD_LEN}-{MAX_PASSWORD_LEN} characters")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError:
        return False
```

Note: bcrypt rejects inputs > 72 bytes by raising; MAX_PASSWORD_LEN of 128 chars can exceed 72 bytes for multibyte text. Guard it: in `hash_password`, after the length check add `if len(password.encode()) > 72: raise ValueError("password too long (> 72 bytes)")`, and in `verify_password` the `except ValueError` already returns False.

- [ ] **Step 4: Run tests to verify they pass**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add apps/orchestrator/app/utils/hashing.py tests/unit/test_auth.py
git commit -m "feat: bcrypt password hashing helpers"
```

---

### Task 3: JWT helpers + config fields

**Files:**
- Create: `apps/orchestrator/app/utils/jwt.py`
- Modify: `apps/orchestrator/app/config.py`
- Test: `tests/unit/test_auth.py`

**Interfaces:**
- Produces: `issue_token(user_id: str, role: str, ttl_seconds: int, secret: str) -> str` and `decode_token(token: str, secret: str) -> dict` (raises `TokenError` on invalid/expired). `TokenError(Exception)`.
- Produces config: `Settings.jwt_secret: str` (alias `BB_JWT_SECRET`, default ""), `Settings.auth_token_ttl_seconds: int` (alias `AUTH_TOKEN_TTL_SECONDS`, default 43200), `Settings.settings_cache_ttl: int` (alias `SETTINGS_CACHE_TTL`, default 45).
- Consumes: nothing from earlier tasks.

- [ ] **Step 1: Write the failing test** (append to `tests/unit/test_auth.py`)

```python
import time

from app.utils.jwt import issue_token, decode_token, TokenError


def test_jwt_roundtrip_and_expiry():
    t = issue_token("uid-1", "admin", ttl_seconds=60, secret="s3cret")
    claims = decode_token(t, "s3cret")
    assert claims["sub"] == "uid-1" and claims["role"] == "admin"
    with pytest.raises(TokenError):
        decode_token(t, "wrong-secret")
    expired = issue_token("uid-1", "admin", ttl_seconds=-1, secret="s3cret")
    with pytest.raises(TokenError):
        decode_token(expired, "s3cret")
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q -k jwt`
Expected: FAIL (module `app.utils.jwt` missing).

- [ ] **Step 3: Implement `app/utils/jwt.py`**

```python
from __future__ import annotations

import time

import jwt as _jwt

ALGORITHM = "HS256"


class TokenError(Exception):
    """Invalid, expired, or wrong-signature token."""


def issue_token(user_id: str, role: str, ttl_seconds: int, secret: str) -> str:
    now = int(time.time())
    payload = {"sub": user_id, "role": role, "iat": now, "exp": now + ttl_seconds}
    return _jwt.encode(payload, secret, algorithm=ALGORITHM)


def decode_token(token: str, secret: str) -> dict:
    try:
        return _jwt.decode(token, secret, algorithms=[ALGORITHM])
    except _jwt.PyJWTError as exc:
        raise TokenError(str(exc)) from exc
```

- [ ] **Step 4: Add config fields** in `apps/orchestrator/app/config.py` (next to `request_header`/`user_agent`):

```python
    # --- auth / settings --------------------------------------------------
    jwt_secret: str = Field(default="", alias="BB_JWT_SECRET")
    auth_token_ttl_seconds: int = Field(default=43200, alias="AUTH_TOKEN_TTL_SECONDS")
    settings_cache_ttl: int = Field(default=45, alias="SETTINGS_CACHE_TTL")
```

- [ ] **Step 5: Run tests to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/orchestrator/app/utils/jwt.py apps/orchestrator/app/config.py tests/unit/test_auth.py
git commit -m "feat: JWT helpers and auth config fields"
```

---

### Task 4: User + SettingOverride models and migration 0008

**Files:**
- Create: `apps/orchestrator/app/models/user.py`
- Create: `apps/orchestrator/app/models/settings.py`
- Modify: `apps/orchestrator/app/models/__init__.py`
- Create: `migrations/versions/20261004_0008_users_settings.py`

**Interfaces:**
- Produces: `User` (`id, username, password_hash, role, active, last_login_at, created_at, updated_at`) and `SettingOverride` (`key, value, updated_by, updated_at`). Both importable from `app.models`.
- Consumes: `TimestampMixin` from `app.models.program`, `Base` from `app.database`.

- [ ] **Step 1: Write `app/models/user.py`**

```python
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.models.program import TimestampMixin


class User(TimestampMixin, Base):
    """A human login. Distinct from ApiKey (programmatic access)."""

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
```

- [ ] **Step 2: Write `app/models/settings.py`**

```python
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database import Base


class SettingOverride(Base):
    """A runtime override of one whitelisted (dynamic) config key; absence = env default."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSONB, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(String(128))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
```

- [ ] **Step 3: Export from `app/models/__init__.py`**

Add imports and `__all__` entries for `User` and `SettingOverride` following the existing pattern in that file (e.g. `from app.models.user import User`, `from app.models.settings import SettingOverride`, and add `"User"`, `"SettingOverride"` to `__all__`).

- [ ] **Step 4: Write migration `migrations/versions/20261004_0008_users_settings.py`**

```python
"""users and settings tables

Revision ID: 0008
Revises: 0007
Create Date: 2026-10-04 16:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0008"
down_revision: str | None = "0007"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", sa.String(length=16), nullable=False),
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("username"),
    )
    op.create_table(
        "settings",
        sa.Column("key", sa.String(length=64), primary_key=True),
        sa.Column("value", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("updated_by", sa.String(length=128), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("settings")
    op.drop_table("users")
```

- [ ] **Step 5: Apply the migration and verify**

Run:
```bash
make build && make up-dev
make migrate
PW=$(grep ^POSTGRES_PASSWORD .env|cut -d= -f2-|tr -d '"'); U=$(grep ^POSTGRES_USER .env|cut -d= -f2-|tr -d '"'); D=$(grep ^POSTGRES_DB .env|cut -d= -f2-|tr -d '"')
docker compose exec -T -e PGPASSWORD="$PW" postgres psql -U "$U" -d "$D" -tc "select count(*) from users; select count(*) from settings; select version_num from alembic_version;"
```
Expected: `0`, `0`, `0008`.

- [ ] **Step 6: Commit**

```bash
git add apps/orchestrator/app/models/user.py apps/orchestrator/app/models/settings.py apps/orchestrator/app/models/__init__.py migrations/versions/20261004_0008_users_settings.py
git commit -m "feat: users and settings tables (migration 0008)"
```

---

### Task 5: User service (CRUD + auth)

**Files:**
- Create: `apps/orchestrator/app/services/users.py`
- Test: `tests/integration/test_auth.py` (needs a DB; unit-level logic is covered via the service against the live stack)

**Interfaces:**
- Produces:
  - `user_count(session) -> int`
  - `create_user(session, principal, *, username, password, role, emitter=None) -> User` (raises `ConflictError` on dup, `ValueError` on bad role/password)
  - `authenticate(session, *, username, password) -> User | None` (None on bad creds/inactive; updates `last_login_at`)
  - `set_password(session, user, new_password)`
  - `update_user(session, principal, user, *, role=None, active=None, password=None, emitter=None) -> User` (enforces last-admin guard)
  - `delete_user(session, principal, user, emitter=None)` (enforces last-admin guard)
  - `LastAdminError(ValueError)`
- Consumes: `hash_password`/`verify_password` (Task 2), `User` (Task 4), `Role`/`ROLE_RANK`, `record_audit`, `ConflictError` from `app.services.programs`.

- [ ] **Step 1: Write the failing integration test**

Create `tests/integration/test_auth.py`:

```python
import uuid

import httpx
import pytest

pytestmark = pytest.mark.integration


def test_user_crud_and_login_flow(api):
    # api fixture authenticates with the bootstrap admin API key (see conftest)
    uname = f"op-{uuid.uuid4().hex[:6]}"
    r = api.post("/users", json={"username": uname, "password": "password123", "role": "operator"})
    assert r.status_code == 201, r.text
    uid = r.json()["id"]

    tok = api.post("/auth/login", json={"username": uname, "password": "password123"})
    assert tok.status_code == 200, tok.text
    token = tok.json()["token"]
    me = httpx.get(f"{api.base_url}/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200 and me.json()["username"] == uname

    # operator cannot list users (admin only)
    assert httpx.get(f"{api.base_url}/users", headers={"Authorization": f"Bearer {token}"}).status_code == 403

    bad = api.post("/auth/login", json={"username": uname, "password": "nope"})
    assert bad.status_code == 401
    api.delete(f"/users/{uid}")
```

(The `/users`, `/auth/*` endpoints are implemented in Tasks 6–8; this test will pass only after those. Keep it here so the service's shape is pinned; run it at Task 8.)

- [ ] **Step 2: Implement `app/services/users.py`**

```python
from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import User
from app.models.enums import Role
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.services.programs import ConflictError
from app.utils.hashing import hash_password, verify_password
from app.utils.time import utcnow


class LastAdminError(ValueError):
    """Refuses to remove/deactivate/demote the last active admin."""


def user_count(session: Session) -> int:
    return int(session.execute(select(func.count()).select_from(User)).scalar_one())


def _validate_role(role: str) -> str:
    return Role(role).value  # raises ValueError on bad role


def _active_admins(session: Session, exclude: uuid.UUID | None = None) -> int:
    q = select(func.count()).select_from(User).where(User.role == Role.ADMIN.value, User.active.is_(True))
    if exclude is not None:
        q = q.where(User.id != exclude)
    return int(session.execute(q).scalar_one())


def create_user(session, principal, *, username, password, role, emitter=None) -> User:
    username = username.strip().lower()
    _validate_role(role)
    if session.execute(select(User).where(User.username == username)).scalar_one_or_none():
        raise ConflictError(f"username {username!r} already exists")
    user = User(username=username, password_hash=hash_password(password), role=role, active=True)
    session.add(user)
    session.flush()
    record_audit(session, principal, "user.created", target_type="user", target_id=user.id,
                 details={"username": username, "role": role}, emitter=emitter)
    return user


def authenticate(session, *, username, password) -> User | None:
    user = session.execute(select(User).where(User.username == username.strip().lower())).scalar_one_or_none()
    if user is None or not user.active or not verify_password(password, user.password_hash):
        return None
    user.last_login_at = utcnow()
    return user


def update_user(session, principal, user, *, role=None, active=None, password=None, emitter=None) -> User:
    if role is not None:
        _validate_role(role)
        if user.role == Role.ADMIN.value and role != Role.ADMIN.value and _active_admins(session, exclude=user.id) == 0:
            raise LastAdminError("cannot demote the last active admin")
        user.role = role
    if active is not None:
        if not active and user.role == Role.ADMIN.value and _active_admins(session, exclude=user.id) == 0:
            raise LastAdminError("cannot deactivate the last active admin")
        user.active = bool(active)
    if password is not None:
        user.password_hash = hash_password(password)
    session.flush()
    record_audit(session, principal, "user.changed", target_type="user", target_id=user.id,
                 details={"role": user.role, "active": user.active, "password_reset": password is not None},
                 emitter=emitter)
    return user


def delete_user(session, principal, user, emitter=None) -> None:
    if user.role == Role.ADMIN.value and _active_admins(session, exclude=user.id) == 0:
        raise LastAdminError("cannot delete the last active admin")
    record_audit(session, principal, "user.deleted", target_type="user", target_id=user.id,
                 details={"username": user.username}, emitter=emitter)
    session.delete(user)
```

- [ ] **Step 3: Lint**

Run: `make lint` → Expected: clean (the test needs the live stack; do not run it yet).

- [ ] **Step 4: Commit**

```bash
git add apps/orchestrator/app/services/users.py tests/integration/test_auth.py
git commit -m "feat: user service (crud, authenticate, last-admin guard)"
```

---

### Task 6: Extend `get_principal` to accept Bearer JWT

**Files:**
- Modify: `apps/orchestrator/app/api/deps.py`
- Test: `tests/unit/test_auth.py`

**Interfaces:**
- Consumes: `decode_token`/`TokenError` (Task 3), `User` (Task 4), `get_settings().jwt_secret`.
- Produces: `get_principal` now resolves a `Principal` from `Authorization: Bearer <jwt>` when present, else from `X-API-Key` (unchanged). Unchanged signature for `require`/`viewer`/`operator`/`admin`.

- [ ] **Step 1: Write the failing unit test** (append to `tests/unit/test_auth.py`)

```python
def test_get_principal_prefers_bearer(monkeypatch):
    # pure resolution test: a valid bearer yields a Principal with the token's role
    from types import SimpleNamespace

    from app.api import deps
    from app.utils.jwt import issue_token

    secret = "unit-secret"
    monkeypatch.setattr(deps, "get_settings", lambda: SimpleNamespace(jwt_secret=secret))
    uid = "11111111-1111-1111-1111-111111111111"
    token = issue_token(uid, "operator", ttl_seconds=60, secret=secret)

    class FakeSession:
        def get(self, model, pk):
            return SimpleNamespace(id=pk, role="operator", active=True, username="alice")

    p = deps.get_principal(authorization=f"Bearer {token}", x_api_key=None, session=FakeSession())
    assert p.role == "operator" and p.name == "alice"
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q -k principal`
Expected: FAIL (`get_principal` has no `authorization` parameter).

- [ ] **Step 3: Implement**

In `apps/orchestrator/app/api/deps.py`, add imports:

```python
from app.models import ApiKey, User
from app.utils.jwt import TokenError, decode_token
```

Replace `get_principal` with:

```python
def get_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    session: Session = Depends(get_session),
) -> Principal:
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
        secret = get_settings().jwt_secret
        if not secret:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "auth not configured")
        try:
            claims = decode_token(token, secret)
        except TokenError as exc:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"invalid token: {exc}") from exc
        user = session.get(User, uuid.UUID(claims["sub"]))
        if user is None or not user.active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "user not found or inactive")
        return Principal(name=user.username, role=user.role)
    if x_api_key:
        key = session.execute(
            select(ApiKey).where(ApiKey.key_hash == sha256_text(x_api_key), ApiKey.active.is_(True))
        ).scalar_one_or_none()
        if key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid API key")
        key.last_used_at = utcnow()
        return Principal(name=key.name, role=key.role)
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing credentials")
```

Add `import uuid` at the top if not present.

- [ ] **Step 4: Run unit + lint**

Run: `.venv/bin/python -m pytest tests/unit/test_auth.py -q` then `make lint`
Expected: PASS, clean.

- [ ] **Step 5: Commit**

```bash
git add apps/orchestrator/app/api/deps.py tests/unit/test_auth.py
git commit -m "feat: accept Bearer JWT in get_principal (API keys still work)"
```

---

### Task 7: Auth schemas + `/auth` routes

**Files:**
- Modify: `apps/orchestrator/app/schemas/api.py`
- Create: `apps/orchestrator/app/api/auth.py`
- Modify: `apps/orchestrator/app/main.py`

**Interfaces:**
- Produces routes: `GET /auth/needs-setup`, `POST /auth/setup`, `POST /auth/login`, `GET /auth/me`, `POST /auth/password`.
- Consumes: `users` service (Task 5), `issue_token` (Task 3), `get_principal`/`get_session`/`get_emitter` deps.

- [ ] **Step 1: Add schemas** to `apps/orchestrator/app/schemas/api.py`:

```python
class SetupIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=10, max_length=128)


class LoginIn(BaseModel):
    username: str
    password: str


class PasswordChangeIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=10, max_length=128)


class UserOut(ORM):
    id: uuid.UUID
    username: str
    role: str
    active: bool
    last_login_at: datetime | None


class TokenOut(BaseModel):
    token: str
    user: UserOut
```

- [ ] **Step 2: Implement `app/api/auth.py`**

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_emitter, get_principal, get_session
from app.config import get_settings
from app.models import User
from app.models.enums import Role
from app.schemas.api import LoginIn, PasswordChangeIn, SetupIn, TokenOut, UserOut
from app.services import users as svc
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter
from app.services.programs import ConflictError
from app.services.settings_store import dynamic_setting
from app.utils.hashing import verify_password
from app.utils.jwt import issue_token

router = APIRouter(tags=["auth"])


def _token_for(session: Session, user: User) -> TokenOut:
    secret = get_settings().jwt_secret
    if not secret:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "BB_JWT_SECRET not set")
    ttl = int(dynamic_setting("AUTH_TOKEN_TTL_SECONDS"))
    token = issue_token(str(user.id), user.role, ttl_seconds=ttl, secret=secret)
    return TokenOut(token=token, user=UserOut.model_validate(user))


@router.get("/auth/needs-setup")
def needs_setup(session: Session = Depends(get_session)) -> dict:
    return {"needs_setup": svc.user_count(session) == 0}


@router.post("/auth/setup", response_model=TokenOut, status_code=201)
def setup(body: SetupIn, session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> TokenOut:
    if svc.user_count(session) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "setup already completed")
    principal = Principal(name="setup", role=Role.ADMIN.value)
    try:
        user = svc.create_user(session, principal, username=body.username, password=body.password,
                               role=Role.ADMIN.value, emitter=emitter)
    except (ConflictError, ValueError) as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    record_audit(session, principal, "auth.setup", target_type="user", target_id=user.id,
                 details={"username": user.username}, emitter=emitter)
    return _token_for(session, user)


@router.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn, session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> TokenOut:
    user = svc.authenticate(session, username=body.username, password=body.password)
    if user is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid username or password")
    record_audit(session, Principal(name=user.username, role=user.role), "auth.login",
                 target_type="user", target_id=user.id, emitter=emitter)
    return _token_for(session, user)


@router.get("/auth/me", response_model=UserOut)
def me(principal: Principal = Depends(get_principal), session: Session = Depends(get_session)) -> UserOut:
    from sqlalchemy import select

    user = session.execute(select(User).where(User.username == principal.name)).scalar_one_or_none()
    if user is None:  # an API-key principal has no user row
        raise HTTPException(status.HTTP_404_NOT_FOUND, "not a user session")
    return UserOut.model_validate(user)


@router.post("/auth/password")
def change_password(
    body: PasswordChangeIn,
    principal: Principal = Depends(get_principal),
    session: Session = Depends(get_session),
    emitter: EventEmitter = Depends(get_emitter),
) -> dict:
    from sqlalchemy import select

    user = session.execute(select(User).where(User.username == principal.name)).scalar_one_or_none()
    if user is None or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "current password incorrect")
    svc.set_password(session, user, body.new_password)
    record_audit(session, principal, "user.changed", target_type="user", target_id=user.id,
                 details={"password_reset": True}, emitter=emitter)
    return {"changed": True}
```

Add `set_password` to `app/services/users.py`:

```python
def set_password(session, user, new_password) -> None:
    user.password_hash = hash_password(new_password)
    session.flush()
```

- [ ] **Step 3: Register the router** in `apps/orchestrator/app/main.py`: add `auth` to the `from app.api import ...` line and add `auth.router,` to the `include_router` loop (place it before `ui.router`).

- [ ] **Step 4: Rebuild, restart, smoke the setup→login flow**

Run:
```bash
make build && make up-dev && make health
BASE=http://127.0.0.1:18000
curl -s $BASE/auth/needs-setup
# If it returns needs_setup:false (users already exist from a prior run), use a fresh DB or an existing admin.
curl -s -X POST $BASE/auth/setup -H 'content-type: application/json' -d '{"username":"admin","password":"adminpass123"}'
```
Expected: `needs-setup` returns JSON; `setup` returns a token (or 409 if a user already exists). **Set `BB_JWT_SECRET` in `.env` first** (Task 10 adds it to `.env.example`; for this smoke add it manually) or `setup` returns 503.

- [ ] **Step 5: Lint + commit**

```bash
make lint
git add apps/orchestrator/app/schemas/api.py apps/orchestrator/app/api/auth.py apps/orchestrator/app/services/users.py apps/orchestrator/app/main.py
git commit -m "feat: /auth routes (needs-setup, setup, login, me, password)"
```

---

### Task 8: `/users` admin routes

**Files:**
- Create: `apps/orchestrator/app/api/users.py`
- Modify: `apps/orchestrator/app/main.py`
- Modify: `apps/orchestrator/app/schemas/api.py`
- Test: `tests/integration/test_auth.py` (Task 5's test runs now)

**Interfaces:**
- Produces routes: `GET /users`, `POST /users`, `PATCH /users/{id}`, `DELETE /users/{id}` (all admin).
- Consumes: `users` service, `admin` dependency.

- [ ] **Step 1: Add schemas** to `schemas/api.py`:

```python
class UserCreateIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=10, max_length=128)
    role: str = "viewer"


class UserPatchIn(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = Field(default=None, min_length=10, max_length=128)
```

- [ ] **Step 2: Implement `app/api/users.py`**

```python
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import admin, get_emitter, get_session
from app.models import User
from app.schemas.api import UserCreateIn, UserOut, UserPatchIn
from app.services import users as svc
from app.services.audit import Principal
from app.services.events import EventEmitter
from app.services.programs import ConflictError

router = APIRouter(tags=["users"])


@router.get("/users", response_model=list[UserOut])
def list_users(_: Principal = Depends(admin), session: Session = Depends(get_session)) -> list[User]:
    return list(session.execute(select(User).order_by(User.username)).scalars())


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(body: UserCreateIn, principal: Principal = Depends(admin),
                session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> User:
    try:
        return svc.create_user(session, principal, username=body.username, password=body.password,
                               role=body.role, emitter=emitter)
    except ConflictError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


def _get(session: Session, user_id: uuid.UUID) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "user not found")
    return user


@router.patch("/users/{user_id}", response_model=UserOut)
def patch_user(user_id: uuid.UUID, body: UserPatchIn, principal: Principal = Depends(admin),
               session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> User:
    try:
        return svc.update_user(session, principal, _get(session, user_id), role=body.role,
                               active=body.active, password=body.password, emitter=emitter)
    except svc.LastAdminError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc


@router.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: uuid.UUID, principal: Principal = Depends(admin),
                session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> None:
    try:
        svc.delete_user(session, principal, _get(session, user_id), emitter=emitter)
    except svc.LastAdminError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
```

- [ ] **Step 3: Register the router** in `main.py` (`users.router`).

- [ ] **Step 4: Run the Task 5 integration test**

Run:
```bash
make build && make up-dev && make health
BB_API_URL=http://127.0.0.1:18000 BB_API_KEY=$(docker compose exec -T orchestrator printenv BB_BOOTSTRAP_ADMIN_KEY|tr -d '\r') .venv/bin/python -m pytest -q tests/integration/test_auth.py
```
Expected: PASS. (Requires `BB_JWT_SECRET` set in `.env`.)

- [ ] **Step 5: Lint + commit**

```bash
make lint
git add apps/orchestrator/app/api/users.py apps/orchestrator/app/schemas/api.py apps/orchestrator/app/main.py
git commit -m "feat: /users admin CRUD with last-admin guard"
```

---

### Task 9: Dynamic settings store + `/settings` routes

**Files:**
- Create: `apps/orchestrator/app/services/settings_store.py`
- Create: `apps/orchestrator/app/api/settings.py`
- Modify: `apps/orchestrator/app/main.py`
- Modify: `apps/orchestrator/app/schemas/api.py`
- Test: `tests/unit/test_settings_store.py`

**Interfaces:**
- Produces:
  - `DYNAMIC_KEYS: dict[str, DynamicKey]` where `DynamicKey` has `env_attr: str`, `cast: Callable[[Any], Any]`, `validate: Callable[[Any], None]`.
  - `dynamic_setting(key: str) -> Any` — DB override (cached, TTL = `settings_cache_ttl`) else env default.
  - `set_override(session, principal, key, value, emitter=None)` / `clear_override(session, principal, key, emitter=None)` / `effective_settings(session) -> list[dict]`.
  - `UnknownSettingError(KeyError)`, `InvalidSettingError(ValueError)`.
- Consumes: `get_settings()`, `SettingOverride` (Task 4), `get_redis` for the cache.

- [ ] **Step 1: Write the failing unit test** — `tests/unit/test_settings_store.py`

```python
import pytest

from app.services import settings_store as ss


def test_dynamic_keys_registry_is_well_formed():
    assert "HTTPX_RATE_LIMIT" in ss.DYNAMIC_KEYS
    assert "CERTSTREAM_FOLLOWUP_SCANNERS" in ss.DYNAMIC_KEYS
    assert "AUTH_TOKEN_TTL_SECONDS" in ss.DYNAMIC_KEYS
    # infra/secret keys must never be dynamic
    for forbidden in ("DATABASE_URL", "ELASTIC_PASSWORD", "BB_JWT_SECRET", "REDIS_URL"):
        assert forbidden not in ss.DYNAMIC_KEYS


def test_validation_rejects_unknown_and_out_of_range():
    with pytest.raises(ss.UnknownSettingError):
        ss.validate_value("NOT_A_KEY", 1)
    with pytest.raises(ss.InvalidSettingError):
        ss.validate_value("HTTPX_RATE_LIMIT", 0)      # must be >= 1
    with pytest.raises(ss.InvalidSettingError):
        ss.validate_value("HTTPX_RATE_LIMIT", 99999)  # above sane cap
    ss.validate_value("HTTPX_RATE_LIMIT", 20)          # ok, no raise
```

- [ ] **Step 2: Run to verify fail**

Run: `.venv/bin/python -m pytest tests/unit/test_settings_store.py -q`
Expected: FAIL (module missing).

- [ ] **Step 3: Implement `app/services/settings_store.py`**

```python
from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import SettingOverride
from app.queue.redis_queue import get_redis
from app.services.audit import Principal, record_audit
from app.services.events import EventEmitter


class UnknownSettingError(KeyError):
    pass


class InvalidSettingError(ValueError):
    pass


@dataclass(frozen=True)
class DynamicKey:
    env_attr: str                      # attribute on Settings
    cast: Callable[[Any], Any]         # coerce an incoming JSON value
    validate: Callable[[Any], None]    # raise InvalidSettingError if out of range


def _int_range(lo: int, hi: int) -> Callable[[Any], None]:
    def _v(v: Any) -> None:
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            raise InvalidSettingError(f"must be an integer in [{lo}, {hi}]")
    return _v


def _nonempty_str(v: Any) -> None:
    if not isinstance(v, str):
        raise InvalidSettingError("must be a string")


DYNAMIC_KEYS: dict[str, DynamicKey] = {
    "HTTPX_RATE_LIMIT": DynamicKey("httpx_rate_limit", int, _int_range(1, 1000)),
    "TLSX_RATE_LIMIT": DynamicKey("tlsx_rate_limit", int, _int_range(1, 1000)),
    "NUCLEI_RATE_LIMIT": DynamicKey("nuclei_rate_limit", int, _int_range(1, 1000)),
    "KATANA_RATE_LIMIT": DynamicKey("katana_rate_limit", int, _int_range(1, 1000)),
    "BBOT_RATE_LIMIT": DynamicKey("bbot_rate_limit", int, _int_range(1, 1000)),
    "MAX_CONCURRENCY": DynamicKey("max_concurrency", int, _int_range(1, 1000)),
    "MAX_CIDR_SIZE": DynamicKey("max_cidr_size", int, _int_range(1, 1 << 24)),
    "MAX_IPS_PER_JOB": DynamicKey("max_ips_per_job", int, _int_range(1, 1 << 20)),
    "MAX_URLS_PER_CRAWL": DynamicKey("max_urls_per_crawl", int, _int_range(1, 1 << 20)),
    "MAX_CRAWL_DEPTH": DynamicKey("max_crawl_depth", int, _int_range(1, 20)),
    "MAX_SCAN_DURATION": DynamicKey("max_scan_duration", int, _int_range(10, 86400)),
    "CERTSTREAM_FOLLOWUP_SCANNERS": DynamicKey("certstream_followup_scanners", str, _nonempty_str),
    "BB_REQUEST_HEADER": DynamicKey("request_header", str, _nonempty_str),
    "BB_USER_AGENT": DynamicKey("user_agent", str, _nonempty_str),
    "AUTH_TOKEN_TTL_SECONDS": DynamicKey("auth_token_ttl_seconds", int, _int_range(300, 30 * 86400)),
}
# NOTE: AUTOSCALE_* live in the host-side script's own env (scripts/autoscale.py), not in Settings;
# they are documented as env-only there and intentionally excluded from this registry.

_CACHE_PREFIX = "bb:setting:"


def validate_value(key: str, value: Any) -> Any:
    if key not in DYNAMIC_KEYS:
        raise UnknownSettingError(key)
    dk = DYNAMIC_KEYS[key]
    coerced = dk.cast(value)
    dk.validate(coerced)
    return coerced


def dynamic_setting(key: str) -> Any:
    dk = DYNAMIC_KEYS[key]
    r = get_redis()
    try:
        cached = r.get(_CACHE_PREFIX + key)
        if cached is not None:
            return json.loads(cached)
    except Exception:  # cache is best-effort; fall through to DB/env
        pass
    # not cached: read DB once, then env default
    from app.database import session_scope

    value: Any = getattr(get_settings(), dk.env_attr)
    with session_scope() as s:
        row = s.get(SettingOverride, key)
        if row is not None:
            value = row.value
    try:
        r.setex(_CACHE_PREFIX + key, get_settings().settings_cache_ttl, json.dumps(value))
    except Exception:
        pass
    return value


def _bust(key: str) -> None:
    try:
        get_redis().delete(_CACHE_PREFIX + key)
    except Exception:
        pass


def set_override(session: Session, principal: Principal, key: str, value: Any, emitter: EventEmitter | None = None) -> Any:
    coerced = validate_value(key, value)
    row = session.get(SettingOverride, key)
    if row is None:
        row = SettingOverride(key=key, value=coerced, updated_by=principal.name)
        session.add(row)
    else:
        row.value, row.updated_by = coerced, principal.name
    session.flush()
    _bust(key)
    record_audit(session, principal, "settings.changed", target_type="setting", target_id=None,
                 details={"key": key, "value": coerced}, emitter=emitter)
    return coerced


def clear_override(session: Session, principal: Principal, key: str, emitter: EventEmitter | None = None) -> None:
    if key not in DYNAMIC_KEYS:
        raise UnknownSettingError(key)
    row = session.get(SettingOverride, key)
    if row is not None:
        session.delete(row)
    _bust(key)
    record_audit(session, principal, "settings.reverted", target_type="setting", target_id=None,
                 details={"key": key}, emitter=emitter)


def effective_settings(session: Session) -> list[dict]:
    overrides = {r.key: r.value for r in session.query(SettingOverride).all()}
    out = []
    for key, dk in DYNAMIC_KEYS.items():
        env_default = getattr(get_settings(), dk.env_attr)
        overridden = key in overrides
        out.append({"key": key, "value": overrides.get(key, env_default),
                    "default": env_default, "source": "override" if overridden else "env"})
    return out
```

- [ ] **Step 4: Run unit test to verify pass**

Run: `.venv/bin/python -m pytest tests/unit/test_settings_store.py -q`
Expected: PASS.

- [ ] **Step 5: Add schemas + implement `app/api/settings.py`**

Add to `schemas/api.py`:

```python
class SettingPutIn(BaseModel):
    value: Any
```

Create `app/api/settings.py`:

```python
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import admin, get_emitter, get_session
from app.schemas.api import SettingPutIn
from app.services import settings_store as ss
from app.services.audit import Principal
from app.services.events import EventEmitter

router = APIRouter(tags=["settings"])


@router.get("/settings")
def list_settings(_: Principal = Depends(admin), session: Session = Depends(get_session)) -> dict:
    return {"settings": ss.effective_settings(session)}


@router.put("/settings/{key}")
def put_setting(key: str, body: SettingPutIn, principal: Principal = Depends(admin),
                session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> dict:
    try:
        value = ss.set_override(session, principal, key, body.value, emitter=emitter)
    except ss.UnknownSettingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown setting {exc}") from exc
    except ss.InvalidSettingError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {"key": key, "value": value, "source": "override"}


@router.delete("/settings/{key}", status_code=204)
def delete_setting(key: str, principal: Principal = Depends(admin),
                   session: Session = Depends(get_session), emitter: EventEmitter = Depends(get_emitter)) -> None:
    try:
        ss.clear_override(session, principal, key, emitter=emitter)
    except ss.UnknownSettingError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"unknown setting {exc}") from exc
```

Register `settings.router` in `main.py`.

- [ ] **Step 6: Wire one real consumer through the resolver (proof it works end-to-end)**

In `workers/common/tooling.py::request_headers`, change the two reads from `get_settings().user_agent` / `identification_header()`'s `get_settings().request_header` to go through `dynamic_setting("BB_USER_AGENT")` / `dynamic_setting("BB_REQUEST_HEADER")`. Keep the same validation. This proves a worker honours a DB override. (Other consumers can be migrated incrementally; the registry already lists them.)

- [ ] **Step 7: Lint + commit**

```bash
make lint
git add apps/orchestrator/app/services/settings_store.py apps/orchestrator/app/api/settings.py apps/orchestrator/app/schemas/api.py apps/orchestrator/app/main.py workers/common/tooling.py tests/unit/test_settings_store.py
git commit -m "feat: dynamic settings store + /settings routes"
```

---

### Task 10: `.env.example` + integration test for settings override

**Files:**
- Modify: `.env.example`
- Modify: `tests/integration/test_auth.py`

**Interfaces:**
- Consumes: `/settings` routes (Task 9), `/auth` (Task 7).

- [ ] **Step 1: Add env docs** to `.env.example` (near the auth/limits block):

```bash
# --- auth (management console login) ---
# HS256 secret for signing login tokens. MUST be set and identical across orchestrator replicas.
BB_JWT_SECRET=CHANGE_ME_LONG_RANDOM_SECRET
# Login token lifetime (seconds). Also overridable at runtime via Settings.
AUTH_TOKEN_TTL_SECONDS=43200
# Dynamic-settings cache TTL (seconds) — how fast DB overrides take effect.
SETTINGS_CACHE_TTL=45
```

- [ ] **Step 2: Add the integration test** (append to `tests/integration/test_auth.py`)

```python
def test_settings_override_roundtrip(api):
    got = {s["key"]: s for s in api.get("/settings").json()["settings"]}
    assert got["HTTPX_RATE_LIMIT"]["source"] == "env"
    assert api.put("/settings/HTTPX_RATE_LIMIT", json={"value": 7}).status_code == 200
    after = {s["key"]: s for s in api.get("/settings").json()["settings"]}
    assert after["HTTPX_RATE_LIMIT"]["value"] == 7 and after["HTTPX_RATE_LIMIT"]["source"] == "override"
    assert api.put("/settings/DATABASE_URL", json={"value": "x"}).status_code == 404  # not dynamic
    assert api.put("/settings/HTTPX_RATE_LIMIT", json={"value": 0}).status_code == 422  # out of range
    assert api.delete("/settings/HTTPX_RATE_LIMIT").status_code == 204
    final = {s["key"]: s for s in api.get("/settings").json()["settings"]}
    assert final["HTTPX_RATE_LIMIT"]["source"] == "env"
```

- [ ] **Step 3: Run the full integration auth suite**

Run:
```bash
BB_API_URL=http://127.0.0.1:18000 BB_API_KEY=$(docker compose exec -T orchestrator printenv BB_BOOTSTRAP_ADMIN_KEY|tr -d '\r') .venv/bin/python -m pytest -q tests/integration/test_auth.py
```
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add .env.example tests/integration/test_auth.py
git commit -m "feat: document auth env; integration test for settings override"
```

---

### Task 11: UI login/setup gate + Users & Settings tabs

**Files:**
- Modify: `apps/orchestrator/app/api/ui.py`

**Interfaces:**
- Consumes: `/auth/*`, `/users`, `/settings` routes. The page stores the JWT in `localStorage` (`bb_jwt`) and sends `Authorization: Bearer`.

- [ ] **Step 1: Replace credential handling in the embedded page**

In the `<script>`:
- Replace the `S` state's `key`/`base` usage: keep `base` (optional, default same-origin) but store the JWT as `S.jwt = localStorage.getItem('bb_jwt')||''`.
- In `api(method,path,body)`, set the header from the JWT: `if(S.jwt)h['Authorization']='Bearer '+S.jwt;` (remove the `X-API-Key` header).
- On any `401` from `api()`, clear `S.jwt`/localStorage and show the login screen.

- [ ] **Step 2: Add the auth gate** — before rendering tabs, call `GET /auth/needs-setup` (no auth):
  - if `needs_setup` → render a **Create first admin** form (username + password → `POST /auth/setup` → store `token` as `bb_jwt`).
  - else if no `S.jwt` → render a **Login** form (username + password → `POST /auth/login` → store token).
  - else render the app; header shows the username (from `GET /auth/me`) + a **Logout** button that clears `bb_jwt` and reloads.

- [ ] **Step 3: Replace the header controls** — remove `#apiBase`/`#apiKey`/Connect; add a `#who` span (username · role) and a Logout button.

- [ ] **Step 4: Add two admin-only tabs** to `TABS` (shown only when `me.role==='admin'`):
  - **users**: table of users (username, role, active, last_login) + create form (username, password, role select) + per-row role/active edit, password reset, delete. Calls `/users`.
  - **settings**: table from `GET /settings` (key, value, source, default) + inline edit (`PUT /settings/{key}` with `{value}`) + reset button (`DELETE`). Calls `/settings`.

- [ ] **Step 5: Validate the embedded JS + serve check**

Run:
```bash
make build && make up-dev && make health
curl -s localhost:18000/ui | sed -n '/<script>/,/<\/script>/p' | sed '1d;$d' > /tmp/ui.js && node --check /tmp/ui.js && echo JS_OK
curl -s -o /dev/null -w "ui %{http_code}\n" localhost:18000/ui
```
Expected: `JS_OK`, `ui 200`.

- [ ] **Step 6: Manual smoke (describe in commit)** — open `/ui`, confirm: first-run shows setup; after setup you are logged in; logout returns to login; a wrong password is rejected; Users and Settings tabs appear for admin only.

- [ ] **Step 7: Lint + commit**

```bash
make lint
git add apps/orchestrator/app/api/ui.py
git commit -m "feat: console login/setup gate + Users and Settings tabs"
```

---

### Task 12: `bbctl user` and `bbctl settings`

**Files:**
- Modify: `apps/orchestrator/app/cli/main.py`

**Interfaces:**
- Consumes: `/users`, `/settings` routes. `bbctl` keeps using the API key (`_call` already sends `X-API-Key`).

- [ ] **Step 1: Add a `user` sub-app** with `list`, `create <username> --role --password`, `delete <id>`; and a `settings` sub-app with `list`, `set <key> <value>`, `unset <key>`. Follow the existing sub-app registration pattern (`app.add_typer(sub, name=...)`) and `_call`/`_out` helpers. For `settings set`, parse the value as JSON if possible else pass the raw string.

```python
user_app = typer.Typer(help="Users (admin)", no_args_is_help=True)
settings_app = typer.Typer(help="Dynamic settings (admin)", no_args_is_help=True)
# register alongside the other add_typer(...) calls

@user_app.command("list")
def user_list(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/users"), as_json, ["username", "role", "active", "last_login_at", "id"])

@user_app.command("create")
def user_create(username: str, role: str = typer.Option("viewer"),
                password: str = typer.Option(..., prompt=True, hide_input=True)) -> None:
    _out(_call("POST", "/users", json={"username": username, "password": password, "role": role}), True)

@user_app.command("delete")
def user_delete(user_id: str) -> None:
    _call("DELETE", f"/users/{user_id}"); console.print("deleted")

@settings_app.command("list")
def settings_list(as_json: bool = JSON_OPT) -> None:
    _out(_call("GET", "/settings")["settings"], as_json, ["key", "value", "source", "default"])

@settings_app.command("set")
def settings_set(key: str, value: str) -> None:
    import json as _json
    try:
        parsed = _json.loads(value)
    except ValueError:
        parsed = value
    _out(_call("PUT", f"/settings/{key}", json={"value": parsed}), True)

@settings_app.command("unset")
def settings_unset(key: str) -> None:
    _call("DELETE", f"/settings/{key}"); console.print("reverted to env default")
```

- [ ] **Step 2: Smoke the CLI**

Run:
```bash
./bbctl settings list
./bbctl settings set HTTPX_RATE_LIMIT 9
./bbctl settings list | grep HTTPX_RATE_LIMIT
./bbctl settings unset HTTPX_RATE_LIMIT
```
Expected: shows override then reverts.

- [ ] **Step 3: Lint + commit**

```bash
make lint
git add apps/orchestrator/app/cli/main.py
git commit -m "feat: bbctl user and settings commands"
```

---

### Task 13: Full regression, docs, final commit

**Files:**
- Modify: `README.md`, `docs/operations.md`, `docs/final-report.md` (reflect login + dynamic settings)

- [ ] **Step 1: Run the whole suite**

Run:
```bash
make lint
make test
BB_API_URL=http://127.0.0.1:18000 BB_API_KEY=$(docker compose exec -T orchestrator printenv BB_BOOTSTRAP_ADMIN_KEY|tr -d '\r') .venv/bin/python -m pytest -q -m integration tests/integration
```
Expected: lint clean, all unit + integration tests pass.

- [ ] **Step 2: Update docs** — README security section: console now uses username/password login (JWT) alongside API keys; first-run setup; dynamic settings editable in the Settings tab / `bbctl settings`. Add `BB_JWT_SECRET` to the required-config list. Note the JWT-in-localStorage tradeoff in the security section.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/operations.md docs/final-report.md
git commit -m "docs: console login and dynamic settings"
```

---

## Self-Review

**Spec coverage:**
- users table + first-run setup → Tasks 4, 5, 7. ✓
- JWT login / me / password → Tasks 3, 7. ✓
- API keys coexist (get_principal dual) → Task 6. ✓
- user CRUD + last-admin guard → Tasks 5, 8. ✓
- dynamic settings whitelist + resolver + env fallback + cache → Task 9. ✓
- settings routes + env-only infra rejection → Tasks 9, 10. ✓
- worker honours an override → Task 9 Step 6. ✓
- UI login/setup/logout + Users/Settings tabs → Task 11. ✓
- CLI → Task 12. ✓
- migration 0008, .env, bcrypt/pyjwt pins → Tasks 1, 4, 10. ✓
- tests (unit + integration) → Tasks 2,3,5,6,8,9,10. ✓
- docs → Task 13. ✓

**Placeholder scan:** no "TBD"/"handle edge cases"; all code steps carry real code.

**Type consistency:** `Principal(name, role)`; `dynamic_setting(key)->Any`; `validate_value`, `set_override`, `clear_override`, `effective_settings`; `issue_token(user_id, role, ttl_seconds, secret)`, `decode_token(token, secret)`; `create_user/authenticate/update_user/delete_user/set_password`; `UserOut`/`TokenOut`/`UserCreateIn`/`UserPatchIn`/`SetupIn`/`LoginIn`/`PasswordChangeIn`/`SettingPutIn` — consistent across tasks.

**Note on AUTOSCALE_*:** the spec listed `AUTOSCALE_*` among dynamic keys, but those are read only by the host-side `scripts/autoscale.py` from its own environment, not by `Settings`. They are therefore documented as env-only and excluded from `DYNAMIC_KEYS`. If runtime control of autoscaling is wanted later, it needs the autoscaler to read `/settings` — a separate task.
