"""
Normalizer: AWS CloudTrail -> common NormalizedEvent schema.

Designed to be cloud-agnostic in spirit: Azure Activity Log and GCP Audit
Log normalizers would live alongside this file and produce the exact same
NormalizedEvent shape, so the detection engine never has to know which
cloud a given event came from.
"""

import json
import sys
import os

sys.path.append(os.path.dirname(__file__))
from schema import NormalizedEvent


def normalize_cloudtrail_record(record: dict) -> NormalizedEvent:
    user_identity = record.get("userIdentity", {})
    return NormalizedEvent(
        event_id=record.get("eventID", f"aws-{record.get('eventTime')}-{record.get('eventName')}"),
        timestamp=record.get("eventTime"),
        source_type="cloud",
        source_system="aws_cloudtrail",
        actor_user=user_identity.get("userName"),
        actor_type=user_identity.get("type"),
        action=record.get("eventName"),
        outcome="success" if "errorCode" not in record else record.get("errorCode"),
        target_resource=record.get("eventSource"),
        source_ip=record.get("sourceIPAddress"),
        raw=record,
    )


def load_and_normalize(path: str) -> list[NormalizedEvent]:
    with open(path) as f:
        data = json.load(f)
    return [normalize_cloudtrail_record(r) for r in data.get("Records", [])]


if __name__ == "__main__":
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "tests", "sample_logs", "aws_cloudtrail_sample.json"
    )
    events = load_and_normalize(sample_path)
    for e in events:
        print(json.dumps(e.to_dict(), indent=2))
