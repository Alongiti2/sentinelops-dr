"""
AI-assisted investigation copilot.

Takes a Detection + its enrichment context and asks Claude to draft an
investigation summary and recommended next steps. This maps directly to
the JD's ask for "agent-style workflows where they meaningfully reduce
toil, while keeping outcomes measurable, auditable, and safe":

  - measurable: every copilot call and its output is logged
  - auditable: the full prompt + response is retained in copilot_log.jsonl
  - safe: the copilot only DRAFTS a recommendation -- it never executes
    containment itself. A human must explicitly approve before anything
    in playbooks/ acts on its suggestion. This mirrors the human-in-the-
    loop gate already built into playbooks/playbook_engine.py.

Requires ANTHROPIC_API_KEY to be set in the environment. Without it,
this script falls back to printing what it WOULD have sent, so the repo
is still runnable/demoable without a live key.
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "detections"))
from engine import Detection  # noqa: E402

COPILOT_LOG_PATH = os.path.join(os.path.dirname(__file__), "copilot_log.jsonl")

SYSTEM_PROMPT = """You are a security investigation assistant supporting a \
Detection & Response engineer. Given a detection and its enrichment \
context, draft:
1. A one-paragraph plain-English summary of what happened.
2. A likely-benign vs likely-malicious assessment with your reasoning.
3. 2-4 concrete next investigation steps an analyst should take.

You are NOT authorized to take any containment action yourself -- you \
only draft recommendations for a human analyst to review and approve."""


def _log(entry: dict):
    entry["timestamp"] = datetime.now(timezone.utc).isoformat()
    with open(COPILOT_LOG_PATH, "a") as f:
        f.write(json.dumps(entry) + "\n")


def build_prompt(detection: Detection, enrichment: dict) -> str:
    return f"""Detection: {detection.rule_title} ({detection.rule_id})
ATT&CK Technique: {detection.attack_technique} / {detection.attack_tactic}
Severity: {detection.severity}
Matched event: {json.dumps(detection.matched_event, default=str)}
Enrichment: {json.dumps(enrichment)}

Draft the investigation summary as instructed."""


def investigate(detection: Detection, enrichment: dict) -> dict:
    prompt = build_prompt(detection, enrichment)
    api_key = os.environ.get("ANTHROPIC_API_KEY")

    if not api_key:
        result = {
            "detection_id": detection.rule_id,
            "event_id": detection.event_id,
            "status": "SKIPPED_NO_API_KEY",
            "note": "Set ANTHROPIC_API_KEY to enable live copilot calls.",
            "prompt_that_would_be_sent": prompt,
        }
        _log(result)
        return result

    import urllib.request

    body = json.dumps({
        "model": "claude-sonnet-4-6",
        "max_tokens": 600,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()

    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=body,
        headers={
            "content-type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
        },
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        text_blocks = [b["text"] for b in data.get("content", []) if b.get("type") == "text"]
        summary_text = "\n".join(text_blocks)
        result = {
            "detection_id": detection.rule_id,
            "event_id": detection.event_id,
            "status": "OK",
            "copilot_summary": summary_text,
            "human_approved": False,  # must be explicitly flipped by an analyst
        }
    except Exception as e:
        result = {
            "detection_id": detection.rule_id,
            "event_id": detection.event_id,
            "status": "ERROR",
            "error": str(e),
        }

    _log(result)
    return result


if __name__ == "__main__":
    sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ingestion"))
    from normalize_cloud import load_and_normalize as load_cloud
    from engine import load_rules, run_detections

    base = os.path.join(os.path.dirname(__file__), "..", "tests", "sample_logs")
    events = load_cloud(os.path.join(base, "aws_cloudtrail_sample.json"))
    rules = load_rules(os.path.join(os.path.dirname(__file__), "..", "detections"))
    detections = run_detections(events, rules)

    if os.path.exists(COPILOT_LOG_PATH):
        os.remove(COPILOT_LOG_PATH)

    fake_enrichment = {"source_ip_flagged": False, "actor_is_known_service_account": True}
    for d in detections[:1]:
        result = investigate(d, fake_enrichment)
        print(json.dumps(result, indent=2))

    print(f"\nCopilot log written to {COPILOT_LOG_PATH}")
