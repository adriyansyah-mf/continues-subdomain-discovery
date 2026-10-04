"""Runtime configuration.

All configuration comes from environment variables (``.env`` in development) or
Docker secrets mounted under ``/run/secrets`` in production. Nothing secret is
hardcoded here; secret fields have no default and are optional so that services
which do not need them can start without them.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from urllib.parse import quote

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

_SECRETS_DIR = "/run/secrets"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
        secrets_dir=_SECRETS_DIR if Path(_SECRETS_DIR).is_dir() else None,
    )

    # --- service identity -------------------------------------------------
    service_name: str = Field(default="orchestrator", alias="BB_SERVICE_NAME")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    environment: str = Field(default="development", alias="BB_ENVIRONMENT")

    # --- PostgreSQL (canonical state) -------------------------------------
    postgres_host: str = Field(default="postgres", alias="POSTGRES_HOST")
    postgres_port: int = Field(default=5432, alias="POSTGRES_PORT")
    postgres_db: str = Field(default="bugbounty", alias="POSTGRES_DB")
    postgres_user: str = Field(default="bugbounty", alias="POSTGRES_USER")
    postgres_password: SecretStr | None = Field(default=None, alias="POSTGRES_PASSWORD")
    database_url_override: str | None = Field(default=None, alias="DATABASE_URL")

    # --- Redis (queue / control / event buffer) ---------------------------
    redis_url: str = Field(default="redis://redis:6379/0", alias="REDIS_URL")
    redis_password: SecretStr | None = Field(default=None, alias="REDIS_PASSWORD")

    # --- Elasticsearch (search / event store; read-only from orchestrator)
    elasticsearch_url: str = Field(default="http://elasticsearch:9200", alias="ELASTICSEARCH_URL")
    elasticsearch_username: str = Field(default="bb_monitor", alias="ES_MONITOR_USER")
    elasticsearch_password: SecretStr | None = Field(default=None, alias="ES_MONITOR_PASSWORD")

    # --- API authentication ----------------------------------------------
    bootstrap_admin_key: SecretStr | None = Field(default=None, alias="BB_BOOTSTRAP_ADMIN_KEY")

    # --- data sources -----------------------------------------------------
    certstream_url: str = Field(default="wss://certstream.calidog.io", alias="CERTSTREAM_URL")
    # Store certificates that matched no program (passive observations only; can be high volume).
    certstream_store_out_of_scope: bool = Field(default=False, alias="CERTSTREAM_STORE_OUT_OF_SCOPE")
    # Follow-up scanners queued for *newly discovered* in-scope assets of *active* programs.
    certstream_followup_scanners: str = Field(default="dns", alias="CERTSTREAM_FOLLOWUP_SCANNERS")
    certstream_dedup_ttl: int = Field(default=86400, alias="CERTSTREAM_DEDUP_TTL")
    certstream_idle_timeout: int = Field(default=300, alias="CERTSTREAM_IDLE_TIMEOUT")
    bounty_targets_url: str = Field(
        default="https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/domains.txt",
        alias="BOUNTY_TARGETS_URL",
    )
    ipranges_repo: str = Field(default="https://github.com/lord-alfred/ipranges", alias="IPRANGES_REPO")
    # Seconds between automatic provider-range syncs (0 disables).
    ipranges_sync_interval: int = Field(default=86400, alias="IPRANGES_SYNC_INTERVAL")
    asn_feed_url: str = Field(default="https://iptoasn.com/data/ip2asn-combined.tsv.gz", alias="ASN_FEED_URL")
    asn_sync_interval: int = Field(default=86400, alias="ASN_SYNC_INTERVAL")
    epss_feed_url: str = Field(
        default="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", alias="EPSS_FEED_URL"
    )
    nvd_api_key: SecretStr | None = Field(default=None, alias="NVD_API_KEY")
    kev_sync_interval: int = Field(default=6 * 3600, alias="KEV_SYNC_INTERVAL")
    epss_sync_interval: int = Field(default=86400, alias="EPSS_SYNC_INTERVAL")
    cve_correlation_interval: int = Field(default=86400, alias="CVE_CORRELATION_INTERVAL")
    kev_feed_url: str = Field(
        default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        alias="KEV_FEED_URL",
    )

    # --- scanner rate limits (upper bounds; policies may only go lower) ----
    httpx_rate_limit: int = Field(default=20, alias="HTTPX_RATE_LIMIT")
    tlsx_rate_limit: int = Field(default=20, alias="TLSX_RATE_LIMIT")
    nuclei_rate_limit: int = Field(default=10, alias="NUCLEI_RATE_LIMIT")
    katana_rate_limit: int = Field(default=10, alias="KATANA_RATE_LIMIT")
    bbot_rate_limit: int = Field(default=10, alias="BBOT_RATE_LIMIT")

    # --- resource limits --------------------------------------------------
    max_concurrency: int = Field(default=4, alias="MAX_CONCURRENCY")
    max_concurrent_scans: int = Field(default=4, alias="MAX_CONCURRENT_SCANS")
    # Cluster-wide: concurrent active jobs per program, and per target host (0 disables).
    program_max_concurrent: int = Field(default=8, alias="PROGRAM_MAX_CONCURRENT")
    per_host_max_concurrent: int = Field(default=1, alias="PER_HOST_MAX_CONCURRENT")
    # Fair share: max jobs per (program, scanner) waiting in Redis at once (0 disables)
    dispatch_max_queued_per_program: int = Field(default=25, alias="DISPATCH_MAX_QUEUED_PER_PROGRAM")
    # Autoscaling hints (GET /scaling)
    scaling_target_jobs_per_worker: int = Field(default=5, alias="SCALING_TARGET_JOBS_PER_WORKER")
    scaling_max_replicas: int = Field(default=10, alias="SCALING_MAX_REPLICAS")
    max_cidr_size: int = Field(default=256, alias="MAX_CIDR_SIZE")
    max_ips_per_job: int = Field(default=256, alias="MAX_IPS_PER_JOB")
    max_urls_per_crawl: int = Field(default=1000, alias="MAX_URLS_PER_CRAWL")
    max_crawl_depth: int = Field(default=3, alias="MAX_CRAWL_DEPTH")
    max_scan_duration: int = Field(default=900, alias="MAX_SCAN_DURATION")
    max_targets_per_scan: int = Field(default=1000, alias="MAX_TARGETS_PER_SCAN")
    max_event_backlog: int = Field(default=500_000, alias="MAX_EVENT_BACKLOG")
    # Scanning hosts that resolve to private/loopback/link-local space is refused
    # unless the IP itself is explicitly in scope (protects the platform's own network).
    allow_private_targets: bool = Field(default=False, alias="ALLOW_PRIVATE_TARGETS")
    # Optional identification header sent by active HTTP scanners (httpx, katana, nuclei), e.g.
    # "X-Bug-Bounty: yourhandle" - many programs require it. Empty = not sent.
    request_header: str = Field(default="", alias="BB_REQUEST_HEADER")
    # Fixed, honest User-Agent for the same scanners. httpx/nuclei otherwise rotate random browser
    # User-Agents, which disguises the scanner; the platform never does that.
    user_agent: str = Field(default="bugbounty-platform/0.1.0 (authorized security testing)", alias="BB_USER_AGENT")

    # --- queue / retry ----------------------------------------------------
    job_max_retries: int = Field(default=3, alias="JOB_MAX_RETRIES")
    job_retry_base_seconds: int = Field(default=30, alias="JOB_RETRY_BASE_SECONDS")
    worker_heartbeat_seconds: int = Field(default=15, alias="WORKER_HEARTBEAT_SECONDS")

    # --- scheduler --------------------------------------------------------
    scheduler_tick_seconds: int = Field(default=15, alias="SCHEDULER_TICK_SECONDS")
    asset_processing_interval: int = Field(default=300, alias="ASSET_PROCESSING_INTERVAL")

    @property
    def database_url(self) -> str:
        if self.database_url_override:
            return self.database_url_override
        password = self.postgres_password.get_secret_value() if self.postgres_password else ""
        auth = quote(self.postgres_user, safe="")
        if password:
            auth += ":" + quote(password, safe="")
        return f"postgresql+psycopg://{auth}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def redis_password_value(self) -> str | None:
        return self.redis_password.get_secret_value() if self.redis_password else None


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    # Allow `*_FILE` indirection (common docker-secrets convention) for the secrets we read.
    for name in ("POSTGRES_PASSWORD", "REDIS_PASSWORD", "ES_MONITOR_PASSWORD", "BB_BOOTSTRAP_ADMIN_KEY", "NVD_API_KEY"):
        file_var = os.environ.get(f"{name}_FILE")
        if file_var and name not in os.environ and Path(file_var).is_file():
            os.environ[name] = Path(file_var).read_text().strip()
    return Settings()
