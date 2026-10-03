"""Notification providers. Each only performs one outbound HTTPS request or SMTP send.

* Secrets (webhook URLs, bot tokens, SMTP passwords, HMAC keys) are never stored in the
  database: a channel holds ``secret_ref``, the name of an environment variable or Docker
  secret (/run/secrets/<NAME>) resolved at send time.
* Outbound destinations must use HTTPS and must not resolve to private/loopback/link-local
  addresses (SSRF protection), unless NOTIFY_ALLOW_PRIVATE_DESTINATIONS=true (lab use).
* No provider runs commands or templates user input.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import ipaddress
import json
import os
import re
import smtplib
import socket
import ssl
from email.message import EmailMessage
from pathlib import Path
from typing import Any, ClassVar
from urllib.parse import urlsplit

import httpx

from app.services.notify.catalog import Notification, render_text

SECRET_REF_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


class NotificationError(RuntimeError):
    pass


class ConfigError(NotificationError):
    """Permanent configuration problem: do not retry."""


def resolve_secret(ref: str | None) -> str | None:
    if not ref:
        return None
    if not SECRET_REF_RE.match(ref):
        raise ConfigError(f"invalid secret_ref {ref!r}")
    path = Path("/run/secrets") / ref
    if path.is_file():
        return path.read_text().strip()
    value = os.environ.get(ref)
    if not value:
        raise ConfigError(f"secret {ref} is not set (env var or /run/secrets/{ref})")
    return value


def _allow_private() -> bool:
    return os.environ.get("NOTIFY_ALLOW_PRIVATE_DESTINATIONS", "false").lower() == "true"


def check_destination(url: str) -> None:
    parts = urlsplit(url)
    allow_private = _allow_private()
    if parts.scheme != "https" and not (allow_private and parts.scheme == "http"):
        raise ConfigError("notification destinations must use https")
    if not parts.hostname or parts.username or parts.password:
        raise ConfigError("invalid destination URL")
    try:
        infos = socket.getaddrinfo(parts.hostname, parts.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise NotificationError(f"cannot resolve {parts.hostname}: {exc}") from exc
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%")[0])
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        ) and not allow_private:
            raise ConfigError(f"destination {parts.hostname} resolves to non-public address {ip}")


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    check_destination(url)
    body = json.dumps(payload).encode()
    try:
        r = httpx.post(
            url,
            content=body,
            headers={"Content-Type": "application/json", **(headers or {})},
            timeout=15,
            follow_redirects=False,
        )
    except httpx.HTTPError as exc:
        raise NotificationError(f"delivery failed: {exc}") from exc
    if r.status_code >= 400:
        err = ConfigError if r.status_code in (400, 401, 403, 404) else NotificationError
        raise err(f"destination answered HTTP {r.status_code}")


class Provider(abc.ABC):
    type: ClassVar[str]
    config_keys: ClassVar[frozenset[str]] = frozenset()

    @classmethod
    def validate_config(cls, config: dict[str, Any], secret_ref: str | None) -> None:
        unknown = set(config) - cls.config_keys
        if unknown:
            raise ConfigError(f"unknown config keys for {cls.type}: {sorted(unknown)}")
        if secret_ref is not None and not SECRET_REF_RE.match(secret_ref):
            raise ConfigError("secret_ref must be an UPPER_CASE env var / Docker secret name")

    @abc.abstractmethod
    def send(self, n: Notification, config: dict[str, Any], secret: str | None) -> None: ...


class SlackProvider(Provider):
    type = "slack"

    def send(self, n, config, secret):
        if not secret:
            raise ConfigError("slack needs secret_ref -> incoming webhook URL")
        _post_json(secret, {"text": render_text(n)})


class DiscordProvider(Provider):
    type = "discord"

    def send(self, n, config, secret):
        if not secret:
            raise ConfigError("discord needs secret_ref -> webhook URL")
        _post_json(secret, {"content": render_text(n)[:1900], "allowed_mentions": {"parse": []}})


class TelegramProvider(Provider):
    type = "telegram"
    config_keys = frozenset({"chat_id"})

    @classmethod
    def validate_config(cls, config, secret_ref):
        super().validate_config(config, secret_ref)
        if not re.match(r"^-?\d{1,20}$|^@[A-Za-z0-9_]{5,32}$", str(config.get("chat_id", ""))):
            raise ConfigError("telegram needs config.chat_id")

    def send(self, n, config, secret):
        if not secret or not re.match(r"^\d+:[A-Za-z0-9_-]{20,}$", secret):
            raise ConfigError("telegram needs secret_ref -> bot token")
        _post_json(
            f"https://api.telegram.org/bot{secret}/sendMessage",
            {"chat_id": config["chat_id"], "text": render_text(n)[:4000], "disable_web_page_preview": True},
        )


class WebhookProvider(Provider):
    """Generic JSON webhook. URL from config.url or the secret; optional HMAC-SHA256 signature."""

    type = "webhook"
    config_keys = frozenset({"url", "sign"})

    def send(self, n, config, secret):
        url = config.get("url")
        if url:
            headers = {}
            if config.get("sign"):
                if not secret:
                    raise ConfigError("signing requires secret_ref -> HMAC key")
                payload = json.dumps(n.to_dict()).encode()
                headers["X-BB-Signature"] = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
            _post_json(url, n.to_dict(), headers)
        elif secret:
            _post_json(secret, n.to_dict())
        else:
            raise ConfigError("webhook needs config.url or secret_ref -> URL")


class EmailProvider(Provider):
    type = "email"
    config_keys = frozenset({"host", "port", "username", "from", "to", "starttls"})

    @classmethod
    def validate_config(cls, config, secret_ref):
        super().validate_config(config, secret_ref)
        for k in ("host", "from", "to"):
            if not config.get(k):
                raise ConfigError(f"email needs config.{k}")

    def send(self, n, config, secret):
        msg = EmailMessage()
        msg["Subject"] = f"[bugbounty-platform] {n.severity.upper()} {n.title}"[:200]
        msg["From"] = config["from"]
        to = config["to"] if isinstance(config["to"], list) else [config["to"]]
        msg["To"] = ", ".join(to)
        msg.set_content(render_text(n))
        try:
            with smtplib.SMTP(config["host"], int(config.get("port", 587)), timeout=20) as smtp:
                if config.get("starttls", True):
                    smtp.starttls(context=ssl.create_default_context())
                if config.get("username"):
                    smtp.login(config["username"], secret or "")
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise NotificationError(f"SMTP delivery failed: {exc}") from exc


PROVIDERS: dict[str, Provider] = {
    p.type: p() for p in (SlackProvider, DiscordProvider, TelegramProvider, WebhookProvider, EmailProvider)
}


def get_provider(channel_type: str) -> Provider:
    try:
        return PROVIDERS[channel_type]
    except KeyError as exc:
        raise ConfigError(f"unknown channel type {channel_type!r}") from exc
