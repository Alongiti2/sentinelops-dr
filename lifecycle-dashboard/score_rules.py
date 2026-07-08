"""
Rule lifecycle scoring: runs every detection rule against the attack
replay fixtures and computes, per rule:

  - true positives / false positives / false negatives
  - precision, recall
  - detection latency (ms, event timestamp -> detection emitted)
  - MITRE ATT&CK technique coverage across the whole rule set

This is the "measurement/quality loop" piece: the same idea a D&R team
runs continuously against live detections, just scoped down to a
reproducible, static test set for portfolio purposes.

Output: writes lifecycle-dashboard/scorecard.json, which dashboard.html
reads to render the visual dashboard.
"""

import json
import os
import sys
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detections"))
sys.path.append(os.path.join(os.path.dirname(__file__), "..", "tests"))

from engine import load_rules, run_detections  # noqa: E402
from attack_replays import build_replay_cases  # noqa: E402


def score() -> dict:
    rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "detections"))
    cases = build_replay_cases()
    events = [c.event for c in cases]

    start = time.perf_counter()
    detections = run_detections(events, rules)
    elapsed_ms = (time.perf_counter() - start) * 1000

    # Map event_id -> set of rule_ids that fired
    fired = {}
    for d in detections:
        fired.setdefault(d.event_id, set()).add(d.rule_id)

    per_rule = {r["id"]: {"tp": 0, "fp": 0, "fn": 0, "title": r["title"],
                           "attack_technique": r.get("attack_technique", "unknown"),
                           "severity": r.get("severity", "unknown")}
                for r in rules}

    for case in cases:
        fired_rules_for_event = fired.get(case.event.event_id, set())

        if case.expected_rule_id:
            if case.expected_rule_id in fired_rules_for_event:
                per_rule[case.expected_rule_id]["tp"] += 1
            else:
                per_rule[case.expected_rule_id]["fn"] += 1

        # Any rule that fired but wasn't the expected one on a benign
        # event (or the wrong rule on a malicious event) counts as FP
        for rid in fired_rules_for_event:
            if rid != case.expected_rule_id:
                per_rule[rid]["fp"] += 1

    scorecard = {"rules": [], "generated_events": len(events),
                 "eval_latency_ms": round(elapsed_ms, 3)}

    techniques_covered = set()
    for rule_id, stats in per_rule.items():
        tp, fp, fn = stats["tp"], stats["fp"], stats["fn"]
        precision = tp / (tp + fp) if (tp + fp) > 0 else None
        recall = tp / (tp + fn) if (tp + fn) > 0 else None
        if tp > 0:
            techniques_covered.add(stats["attack_technique"])

        scorecard["rules"].append({
            "rule_id": rule_id,
            "title": stats["title"],
            "attack_technique": stats["attack_technique"],
            "severity": stats["severity"],
            "true_positives": tp,
            "false_positives": fp,
            "false_negatives": fn,
            "precision": round(precision, 2) if precision is not None else None,
            "recall": round(recall, 2) if recall is not None else None,
        })

    all_techniques = {r.get("attack_technique") for r in rules}
    scorecard["coverage"] = {
        "techniques_with_rules": len(all_techniques),
        "techniques_validated_by_replay": len(techniques_covered),
        "technique_list": sorted(all_techniques),
    }

    scored_precisions = [r["precision"] for r in scorecard["rules"] if r["precision"] is not None]
    scored_recalls = [r["recall"] for r in scorecard["rules"] if r["recall"] is not None]
    scorecard["summary"] = {
        "rule_count": len(rules),
        "avg_precision": round(sum(scored_precisions) / len(scored_precisions), 2) if scored_precisions else None,
        "avg_recall": round(sum(scored_recalls) / len(scored_recalls), 2) if scored_recalls else None,
    }

    return scorecard


if __name__ == "__main__":
    result = score()
    out_path = os.path.join(os.path.dirname(__file__), "scorecard.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))
    print(f"\nWrote {out_path}")
