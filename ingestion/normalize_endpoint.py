"""
Normalizer: Endpoint / EDR events -> common NormalizedEvent schema.
"""

import json
import sys
import os

sys.path.append(os.path.dirname(__file__))
from schema import NormalizedEvent


def normalize_edr_event(event: dict) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event.get("event_id"),
        timestamp=event.get("timestamp"),
        source_type="endpoint",
        source_system="edr",
        actor_user=event.get("user"),
        actor_type="human",
        action=event.get("action"),
        outcome="observed",
        target_resource=event.get("process_name"),
        source_ip=None,
        raw=event,
    )


def load_and_normalize(path: str) -> list[NormalizedEvent]:
    with open(path) as f:
        data = json.load(f)
    return [normalize_edr_event(e) for e in data.get("events", [])]


if __name__ == "__main__":
    sample_path = os.path.join(
        os.path.dirname(__file__), "..", "tests", "sample_logs", "endpoint_edr_sample.json"
    )
    events = load_and_normalize(sample_path)
    for e in events:
        print(json.dumps(e.to_dict(), indent=2))
