"""Enumerations shared by models, schemas, workers and the scope engine.

Stored as plain strings in PostgreSQL (validated in the application layer) so
that adding a value never requires an enum-type migration.
"""

from enum import StrEnum


class ScopeType(StrEnum):
    DOMAIN = "domain"
    WILDCARD = "wildcard"
    CIDR = "cidr"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    ASN = "asn"
    URL = "url"


class ScopeMode(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class AssetType(StrEnum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    URL = "url"
    CERTIFICATE = "certificate"
    ASN = "asn"
    TECHNOLOGY = "technology"
    CVE = "cve"


class AssetStatus(StrEnum):
    DISCOVERED = "discovered"
    ACTIVE = "active"
    INACTIVE = "inactive"
    RETIRED = "retired"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class LifecycleStage(StrEnum):
    DISCOVERED = "DISCOVERED"
    VALIDATED = "VALIDATED"
    HTTP_PROBED = "HTTP_PROBED"
    TLS_IDENTIFIED = "TLS_IDENTIFIED"
    TECH_IDENTIFIED = "TECH_IDENTIFIED"
    CRAWLED = "CRAWLED"
    VULN_SCANNED = "VULN_SCANNED"
    MONITORED = "MONITORED"


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ProgramAssetStatus(StrEnum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    EXCLUDED = "excluded"
    REMOVED = "removed"


class RelationshipType(StrEnum):
    RESOLVES_TO = "RESOLVES_TO"
    HOSTS = "HOSTS"
    USES_CERTIFICATE = "USES_CERTIFICATE"
    BELONGS_TO_ASN = "BELONGS_TO_ASN"
    BELONGS_TO_CIDR = "BELONGS_TO_CIDR"
    USES_TECHNOLOGY = "USES_TECHNOLOGY"
    HAS_URL = "HAS_URL"
    RELATED_TO = "RELATED_TO"
    AFFECTED_BY_CVE = "AFFECTED_BY_CVE"
    DISCOVERED_FROM = "DISCOVERED_FROM"
    CNAME_TO = "CNAME_TO"
    USES_NAMESERVER = "USES_NAMESERVER"
    USES_MAIL_SERVER = "USES_MAIL_SERVER"


class JobStatus(StrEnum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"


TERMINAL_JOB_STATUSES = frozenset(
    {JobStatus.SUCCESS, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.BLOCKED, JobStatus.OUT_OF_SCOPE}
)


class ScanStatus(StrEnum):
    CREATED = "CREATED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class Role(StrEnum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


ROLE_RANK = {Role.VIEWER: 0, Role.OPERATOR: 1, Role.ADMIN: 2}


class BlockReason(StrEnum):
    NOT_IN_SCOPE = "NOT_IN_SCOPE"
    EXCLUDED = "EXCLUDED"
    SCOPE_UNAVAILABLE = "SCOPE_UNAVAILABLE"
    PROGRAM_INACTIVE = "PROGRAM_INACTIVE"
    SCANNER_PAUSED = "SCANNER_PAUSED"
    ASSET_PAUSED = "ASSET_PAUSED"
    MAINTENANCE_WINDOW = "MAINTENANCE_WINDOW"
    POLICY_DISABLED = "POLICY_DISABLED"
    CIDR_LIMIT_EXCEEDED = "CIDR_LIMIT_EXCEEDED"
    PRIVATE_ADDRESS = "PRIVATE_ADDRESS"
    UNSUPPORTED_TARGET = "UNSUPPORTED_TARGET"
    INVALID_TARGET = "INVALID_TARGET"
