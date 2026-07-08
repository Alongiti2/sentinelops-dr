"""
Common normalized event schema, loosely modeled on OCSF (Open Cybersecurity
Schema Framework) core fields. Every ingestion normalizer converts its
source-specific log format into this shape so the detection engine only
ever has to reason about one schema, regardless of where the telemetry
came from (cloud, Kubernetes, endpoint, etc).

This is intentionally a simplified subset of real OCSF -- enough fields
to support meaningful detections without pulling in the full spec.
"""

from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class NormalizedEvent:
    # --- Core identity ---
    event_id: str
    timestamp: str  # ISO 8601
    source_type: str  # "cloud" | "kubernetes" | "endpoint"
    source_system: str  # e.g. "aws_cloudtrail", "k8s_audit", "edr"

    # --- Actor ---
    actor_user: Optional[str] = None
    actor_type: Optional[str] = None  # e.g. IAMUser, ServiceAccount, human

    # --- Action ---
    action: Optional[str] = None  # e.g. CreateAccessKey, exec, process_start
    outcome: Optional[str] = None  # e.g. success, failure, 200, 403

    # --- Object / target ---
    target_resource: Optional[str] = None
    target_namespace: Optional[str] = None

    # --- Network context ---
    source_ip: Optional[str] = None

    # --- Raw / extra context kept for enrichment & investigation ---
    raw: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)
