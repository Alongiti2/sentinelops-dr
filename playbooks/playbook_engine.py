"""
SOAR-lite response playbook engine.

Takes a Detection (from detections/engine.py) and runs it through a
triage -> enrichment -> containment pipeline. Every step is logged to
an append-only audit trail (audit_log.jsonl) so every automated action
is reviewable after the fact -- this is the "measurable, auditable,
safe" bar the JD calls out for agent-style response automation.

Containment actions are SIMULATED (they print/log what would happen)
rather than calling real cloud/k8s APIs -- this is a portfolio project,
not a live-fire system. The structure is what matters: swap the
`simulate_*` functions for real API calls in a production deployment.
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detections"))
from engine import Detection  # noqa: E402

AUDIT_LOG_PATH = os.path.join(os.path.dirname(__file__), "audit_log.jsonl")

# Static enrichment lookups standing in for real threat-intel/IPAM calls
KNOWN_BAD_IPS = {"198.51.100.23", "198.51.100.77", "203.0.113.99"}
KNOWN_SERVICE_ACCOUNTS = {"svc-deploy-bot", "build-runner"}


def _audit(event: str, detail: dict):
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "detail": detail,
    }
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def triage(detection: Detection) -> dict:
    """Assign initial priority based on rule severity + detection context."""
    priority_map = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
    priority = priority_map.get(detection.severity, "P4")
    result = {"detection_id": detection.rule_id, "event_id": detection.event_id, "priority": priority}
    _audit("triage", result)
    return result


def enrich(detection: Detection) -> dict:
    """Add context: is the source IP known-bad? Is the actor a known service account?"""
    source_ip = detection.matched_event.get("source_ip")
    actor = detection.matched_event.get("actor_user", "")

    enrichment = {
        "detection_id": detection.rule_id,
        "event_id": detection.event_id,
        "source_ip_flagged": source_ip in KNOWN_BAD_IPS if source_ip else False,
        "actor_is_known_service_account": any(sa in (actor or "") for sa in KNOWN_SERVICE_ACCOUNTS),
    }
    _audit("enrich", enrichment)
    return enrichment


def simulate_containment(detection: Detection, enrichment: dict) -> dict:
    """
    Decide (and simulate) a containment action. Only acts automatically
    on high-confidence signals; anything else is routed to human review
    -- this mirrors a real "human-in-the-loop" containment gate.
    """
    high_confidence = enrichment["source_ip_flagged"] and detection.severity in ("high", "critical")

    if high_confidence:
        action = {
            "detection_id": detection.rule_id,
            "event_id": detection.event_id,
            "action": "SIMULATED: revoke credentials / isolate identity",
            "auto_executed": True,
            "reason": "known-bad source IP + high/critical severity",
        }
    else:
        action = {
            "detection_id": detection.rule_id,
            "event_id": detection.event_id,
            "action": "queued for human review",
            "auto_executed": False,
            "reason": "confidence below auto-containment threshold",
        }

    _audit("containment_decision", action)
    return action


def run_playbook(detection: Detection) -> dict:
    start = time.perf_counter()
    triage_result = triage(detection)
    enrichment_result = enrich(detection)
    containment_result = simulate_containment(detection, enrichment_result)
    elapsed_ms = round((time.perf_counter() - start) * 1000, 3)

    summary = {
        "triage": triage_result,
        "enrichment": enrichment_result,
        "containment": containment_result,
        "playbook_latency_ms": elapsed_ms,
    }
    _audit("playbook_complete", summary)
    return summary


if __name__ == "__main__":
    # Demo run: pull real detections from the engine against sample logs,
    # then run each one through the playbook.
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ingestion"))
    from normalize_cloud import load_and_normalize as load_cloud
    from engine import load_rules, run_detections

    base = os.path.join(os.path.dirname(__file__), "..", "tests", "sample_logs")
    events = load_cloud(os.path.join(base, "aws_cloudtrail_sample.json"))
    rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "detections"))
    detections = run_detections(events, rules)

    if os.path.exists(AUDIT_LOG_PATH):
        os.remove(AUDIT_LOG_PATH)

    for d in detections:
        result = run_playbook(d)
        print(json.dumps(result, indent=2))

    print(f"\nAudit trail written to {AUDIT_LOG_PATH}")
