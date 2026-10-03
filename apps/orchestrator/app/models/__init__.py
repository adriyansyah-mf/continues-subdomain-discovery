"""ORM models. Importing this package registers every table on Base.metadata."""

from app.models.asset import Asset, AssetState, ProgramAsset
from app.models.audit import ApiKey, AuditEvent
from app.models.cloud import AsnRange, CloudRange
from app.models.notification import NotificationChannel, NotificationDelivery, NotificationPolicy
from app.models.policy import MaintenanceWindow, ScannerControl, ScanPolicy, Schedule
from app.models.program import Program
from app.models.relationship import AssetRelationship
from app.models.scan import Scan, ScanJob
from app.models.scope import ScopeEntry
from app.models.source import ImportRun, SourceRecord
from app.models.vuln import CpeLookup, CveRecord, EpssScore, KevEntry, VulnCorrelation

__all__ = [
    "ApiKey",
    "AsnRange",
    "Asset",
    "AssetRelationship",
    "AssetState",
    "AuditEvent",
    "CloudRange",
    "CpeLookup",
    "CveRecord",
    "EpssScore",
    "ImportRun",
    "KevEntry",
    "MaintenanceWindow",
    "NotificationChannel",
    "NotificationDelivery",
    "NotificationPolicy",
    "Program",
    "ProgramAsset",
    "Scan",
    "ScanJob",
    "ScanPolicy",
    "ScannerControl",
    "Schedule",
    "ScopeEntry",
    "SourceRecord",
    "VulnCorrelation",
]
