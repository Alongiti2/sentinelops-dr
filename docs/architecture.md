# Architecture

## Overview

SentinelOps-DR is organized as five layers, each mapping directly to a
core responsibility in a Detection & Response engineering role: ingest
telemetry, detect threats, measure detection quality, automate response,
and use AI to reduce investigation toil — all with a human approval gate
before anything destructive happens.

```
┌─────────────────────────────────────────────────────────────────┐
│                        Telemetry Sources                         │
│        (AWS CloudTrail · Kubernetes Audit · Endpoint/EDR)         │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  ingestion/                                                       │
│  normalize_cloud.py · normalize_k8s.py · normalize_endpoint.py    │
│  → common OCSF-style NormalizedEvent schema (schema.py)           │
└───────────────────────────────┬───────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│  detections/                                                      │
│  Sigma-style YAML rules tagged by MITRE ATT&CK technique           │
│  engine.py evaluates rules against NormalizedEvents                │
└───────────────────────────────┬───────────────────────────────────┘
                     │                              │
                     ▼                              ▼
┌───────────────────────────────┐   ┌───────────────────────────────┐
│  lifecycle-dashboard/           │   │  playbooks/                    │
│  score_rules.py runs rules       │   │  triage → enrich → contain     │
│  against tests/attack_replays.py │   │  human-in-the-loop gate for    │
│  → scorecard.json                │   │  auto-containment              │
│  → dashboard.html (coverage,     │   │  → audit_log.jsonl             │
│    precision, recall, latency)   │   └───────────────┬─────────────────┘
└───────────────────────────────┘                       │
                                                          ▼
                                        ┌───────────────────────────────┐
                                        │  copilot/                       │
                                        │  investigation_copilot.py       │
                                        │  LLM drafts investigation        │
                                        │  summary + next steps            │
                                        │  NEVER auto-executes             │
                                        │  → copilot_log.jsonl             │
                                        └───────────────────────────────┘
```

## Design decisions and why

**Cloud-agnostic schema first.** Every normalizer converts source-specific
logs into the same `NormalizedEvent` schema (loosely modeled on OCSF).
The detection engine, scoring, and playbooks never touch a
cloud-specific field directly — this is what "cloud-agnostic detection
approaches" (from the JD) means in practice, not just a buzzword. Adding
Azure or GCP support means writing one new normalizer file; nothing
downstream changes.

**Rule lifecycle measurement is a first-class citizen, not an
afterthought.** Most detection-engineering portfolio projects stop at
"here are some rules that fire." This one tracks precision, recall, and
ATT&CK technique coverage against a reproducible replay set, and
explicitly flags rules with zero replay coverage as "Untested" rather
than hiding the gap. A detection rule nobody has validated is a known
risk, and the dashboard says so.

**Human-in-the-loop by default.** `playbooks/playbook_engine.py` only
auto-executes containment on high-confidence signals (known-bad IP +
high/critical severity); everything else routes to human review. The
copilot in `copilot/` never executes anything — it drafts, a human
approves. This isn't a limitation of the tooling; it's the actual safety
posture a frontier AI lab's security team would require of any
agent-assisted response system.

**Static, reproducible test fixtures over live infrastructure.** Real
CloudTrail/K8s/EDR access isn't available in a portfolio context, so
`tests/sample_logs/` and `tests/attack_replays.py` provide realistic,
versioned fixtures instead. This keeps the whole pipeline runnable end
to end with `python3 <script>.py` and no cloud credentials, while still
proving the same reasoning a live deployment would need.

## Known gaps (intentionally documented, not hidden)

- No runtime/eBPF telemetry (Falco or similar) — see
  `threat-models/new-k8s-cluster-rollout.md` for what that would add.
- No BMC/firmware-level telemetry — see
  `threat-models/datacenter-firmware-bmc-risk.md` for the reasoning on
  why that's a hard-to-observe control path and what would close it.
- `DR-CLOUD-002` and `DR-EDR-002` currently have zero replay coverage —
  visible directly in the dashboard as "Untested," which is the point:
  a lifecycle dashboard's job is to surface gaps, not hide them.
