# SentinelOps-DR

**A cloud-agnostic Detection & Response engineering platform demonstrating
rule lifecycle management, Kubernetes-native threat detection, automated
response workflows, and AI-assisted investigation — with a human-approval
gate on every action that matters.**

Built to reflect how a Detection & Response team actually measures and
operates its detection stack: not just "rules that fire," but rules whose
precision, recall, and ATT&CK coverage are tracked, tested, and visibly
flagged when unproven.

---

## Why this exists

Most detection-engineering portfolio projects stop at "here's a SIEM rule
that catches X." This project goes one layer further and answers the
question a D&R team actually has to answer continuously: **how do we know
our detections are still good?**

That's the rule lifecycle dashboard — coverage, precision, recall, and
latency, scored against reproducible attack replay fixtures, with
untested rules called out rather than hidden.

## What's inside

| Component | What it does |
|---|---|
| [`ingestion/`](ingestion/) | Normalizes AWS CloudTrail, Kubernetes audit logs, and endpoint/EDR events into one common OCSF-style schema |
| [`detections/`](detections/) | Sigma-style YAML detection rules tagged by MITRE ATT&CK technique, with a lightweight rule-matching engine |
| [`lifecycle-dashboard/`](lifecycle-dashboard/) | Scores every rule against replay fixtures for precision/recall/coverage, rendered as a dark-mode HTML dashboard |
| [`playbooks/`](playbooks/) | Triage → enrichment → containment automation with a human-in-the-loop gate and full audit logging |
| [`copilot/`](copilot/) | LLM-assisted investigation summaries (Claude API) — drafts recommendations only, never auto-executes |
| [`threat-models/`](threat-models/) | Written threat models for a new K8s cluster rollout and datacenter/firmware/BMC risk — the reasoning, not just the code |
| [`tests/`](tests/) | Sample raw logs and labeled attack-replay fixtures used to score detection quality |

## Try it yourself

```bash
git clone https://github.com/Alongiti2/sentinelops-dr.git
cd sentinelops-dr
pip install -r requirements.txt

# See ingestion normalize a raw CloudTrail sample
python3 ingestion/normalize_cloud.py

# Run all detection rules against sample logs
python3 detections/engine.py

# Score every rule against attack replay fixtures, generate scorecard.json
python3 lifecycle-dashboard/score_rules.py
open lifecycle-dashboard/dashboard.html   # or python3 -m http.server, then visit it

# Run a detection through the full triage/enrich/contain playbook
python3 playbooks/playbook_engine.py

# (Optional) run the AI investigation copilot — falls back gracefully
# without a key, so this works out of the box either way
export ANTHROPIC_API_KEY=your-key-here
python3 copilot/investigation_copilot.py
```

## Current detection coverage

6 rules across 3 telemetry sources, mapped to 6 distinct MITRE ATT&CK
techniques (T1098, T1530, T1552.007, T1609, T1105, T1059.002). Run
`lifecycle-dashboard/score_rules.py` for live numbers — this README
intentionally doesn't hardcode metrics that the dashboard already
computes and could drift out of date.

## What I'd build next

- Runtime/eBPF telemetry (Falco) for container escape detection —
  scoped out in [`threat-models/new-k8s-cluster-rollout.md`](threat-models/new-k8s-cluster-rollout.md)
- Azure/GCP normalizers alongside the existing AWS one, to prove the
  "cloud-agnostic" claim with a second cloud, not just the schema design
- A real Atomic Red Team-style replay harness instead of static fixtures

## About

Built by Delphin Zaki — Senior Cybersecurity Engineer (CISSP, CCSP,
PCNSE, CEH, AWS Solutions Architect Professional), 20+ years across
network security, multi-cloud architecture, SIEM/detection engineering,
and incident response. This project was built specifically to reflect
the responsibilities in OpenAI's Security Engineer, Detection and
Response role.
