"""
Detection engine: loads Sigma-style YAML rules from this directory and
evaluates them against a stream of NormalizedEvent objects.

This is a deliberately small, dependency-light rule matcher -- not a
reimplementation of the full Sigma spec -- but it supports the condition
types the rules in this repo actually use:

  - exact field match          (e.g. event_name: PutBucketPolicy)
  - substring match             (condition_contains)
  - regex match                 (condition_regex)

Each match produces a Detection record with enough context (rule id,
ATT&CK technique, matched event) to feed both the lifecycle dashboard
and downstream playbooks.
"""

import glob
import os
import re
import sys
from dataclasses import dataclass, asdict
from typing import Any

import yaml

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ingestion"))
from schema import NormalizedEvent  # noqa: E402


@dataclass
class Detection:
    rule_id: str
    rule_title: str
    attack_technique: str
    attack_tactic: str
    severity: str
    event_id: str
    event_timestamp: str
    matched_event: dict

    def to_dict(self) -> dict:
        return asdict(self)


def load_rules(rules_dir: str) -> list[dict]:
    rules = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.yml"))):
        with open(path) as f:
            rule = yaml.safe_load(f)
            rule["_source_file"] = os.path.basename(path)
            rules.append(rule)
    return rules


def _get_nested(obj: dict, dotted_path: str) -> Any:
    parts = dotted_path.split(".")
    cur = obj
    for p in parts:
        if isinstance(cur, dict):
            cur = cur.get(p)
        else:
            return None
    return cur


def _event_matches_rule(event: NormalizedEvent, rule: dict) -> bool:
    detection = rule.get("detection", {})
    event_dict = event.to_dict()

    # Rule must target this event's source system
    if rule.get("source_system") and rule["source_system"] != event.source_system:
        return False

    for key, expected in detection.items():
        if key == "condition_contains":
            field_value = str(_get_nested(event_dict, expected["field"]) or "")
            if expected["value"] not in field_value:
                return False
        elif key == "condition_regex":
            field_value = str(_get_nested(event_dict, expected["field"]) or "")
            if not re.search(expected["pattern"], field_value):
                return False
        elif key == "requestURI_contains":
            field_value = str(_get_nested(event_dict, "raw.requestURI") or "")
            if expected not in field_value:
                return False
        elif key == "event_name":
            if _get_nested(event_dict, "raw.eventName") != expected:
                return False
        else:
            # direct field match against the normalized schema, e.g.
            # verb, target_resource, target_namespace, actor_type, process_name
            actual = event_dict.get(key)
            if actual is None:
                actual = _get_nested(event_dict, f"raw.{key}")
            if actual != expected:
                return False

    return True


def run_detections(events: list[NormalizedEvent], rules: list[dict]) -> list[Detection]:
    detections = []
    for event in events:
        for rule in rules:
            if _event_matches_rule(event, rule):
                detections.append(
                    Detection(
                        rule_id=rule["id"],
                        rule_title=rule["title"],
                        attack_technique=rule.get("attack_technique", "unknown"),
                        attack_tactic=rule.get("attack_tactic", "unknown"),
                        severity=rule.get("severity", "unknown"),
                        event_id=event.event_id,
                        event_timestamp=event.timestamp,
                        matched_event=event.to_dict(),
                    )
                )
    return detections


if __name__ == "__main__":
    import json

    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ingestion"))
    from normalize_cloud import load_and_normalize as load_cloud
    from normalize_k8s import load_and_normalize as load_k8s
    from normalize_endpoint import load_and_normalize as load_endpoint

    base = os.path.join(os.path.dirname(__file__), "..", "tests", "sample_logs")
    all_events = (
        load_cloud(os.path.join(base, "aws_cloudtrail_sample.json"))
        + load_k8s(os.path.join(base, "k8s_audit_sample.json"))
        + load_endpoint(os.path.join(base, "endpoint_edr_sample.json"))
    )

    rules = load_rules(os.path.dirname(__file__))
    detections = run_detections(all_events, rules)

    print(f"Loaded {len(rules)} rules, evaluated {len(all_events)} events, "
          f"found {len(detections)} detections.\n")
    for d in detections:
        print(json.dumps(d.to_dict(), indent=2, default=str))
