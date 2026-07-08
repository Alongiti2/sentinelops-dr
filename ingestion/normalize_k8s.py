"""
Normalizer: Kubernetes audit log -> common NormalizedEvent schema.
"""

import json
import sys
import os

sys.path.append(os.path.dirname(__file__))
from schema import NormalizedEvent


def normalize_k8s_event(item: dict) -> NormalizedEvent:
    user = item.get("user", {})
    object_ref = item.get("objectRef", {})
    source_ips = item.get("sourceIPs", [])
    return NormalizedEvent(
        event_id=item.get("auditID"),
        timestamp=item.get("requestReceivedTimestamp"),
        source_type="kubernetes",
        source_system="k8s_audit",
        actor_user=user.get("username"),
        actor_type="ServiceAccount" if "serviceaccount" in user.get("username", "") else "User",
        action=item.get("verb"),
        outcome=str(item.get("responseStatus", {}).get("code")),
        target_resource=object_ref.get("resource"),
        target_namespace=object_ref.get("namespace"),
        source_ip=source_ips[0] if source_ips else None,
        raw=item,
    )


def load_and_normalize(path: str) -> list[NormalizedEvent]:
    with open(path) as f:
        data = json.load(f)
    return [normalize_k8s_event(item) for item in data.get("items", [])]


if __name__ == "__main__":
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "tests", "sample_logs", "k8s_audit_sample.json"
    )
    events = load_and_normalize(sample_path)
    for e in events:
        print(json.dumps(e.to_dict(), indent=2))
