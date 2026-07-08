# Threat Model: New Kubernetes Cluster Rollout

## Scenario

The platform team is standing up a new production Kubernetes cluster to
host a customer-facing service. As the D&R engineer, I'm asked: *what
telemetry, controls, and playbooks does this cluster need before it
carries production traffic?*

This mirrors the JD's ask directly: *"evaluate new infrastructure or
features, identify D&R implications... and turn that into concrete
requirements for teams shipping the system."*

## What could go wrong

| Risk | Why it matters | Attack surface |
|---|---|---|
| Overly broad ServiceAccount RBAC | A compromised workload identity can read secrets or exec into unrelated pods | control plane, RBAC |
| No audit logging enabled by default | Without audit logs, none of the detections in `detections/k8s_*.yml` can fire at all | control plane |
| Node-level container escape | A compromised container reaches the underlying host, then the broader network | nodes, kernel |
| Unrestricted egress from pods | Compromised workload exfiltrates data or pulls a second-stage payload | networking |
| Secrets stored as plain K8s Secrets (not vaulted) | Base64 is not encryption; anyone with `get secrets` RBAC can read credentials in cleartext | control plane, etcd |
| CI/CD service account over-permissioned | The `build-runner` identity used in this repo's sample detections (`DR-K8S-001`, `DR-K8S-002`) is a realistic example of an over-scoped automation identity | supply chain |

## What we'd need to see (telemetry requirements)

1. **Kubernetes audit logs** shipped to the D&R pipeline at `RequestResponse`
   level for `secrets`, `exec`, and `rolebindings` resources at minimum
   (see `ingestion/normalize_k8s.py` for the schema this expects).
2. **Falco or eBPF-based runtime telemetry** for container escape and
   anomalous syscall detection — not currently in this repo's detection
   set, and a concrete gap the lifecycle dashboard should track.
3. **Network flow logs** (VPC flow logs / CNI-level) to catch unrestricted
   egress before it becomes exfiltration.
4. **CI/CD identity usage logs** — which pipeline used which
   ServiceAccount, and from where — so `DR-K8S-001`/`DR-K8S-002` can be
   tuned against real automation baselines instead of static allow-lists.

## How we'd respond

- **RBAC-scoped, least-privilege ServiceAccounts** per workload, reviewed
  before the cluster goes live (a control, not just a detection).
- **`DR-K8S-001`** (kube-system secrets listing) and **`DR-K8S-002`**
  (prod pod exec) from this repo's `detections/` directory apply directly
  and should be enabled on day one, not bolted on after an incident.
- **Playbook**: any exec into a prod namespace outside a known
  change-ticket window should route to `playbooks/playbook_engine.py`'s
  human-review queue by default — auto-containment stays off until the
  false-positive rate is proven low against real traffic.
- **Quarterly threat model review** as the cluster's workloads change —
  this document should be a living artifact, not a one-time exercise.

## Residual risk

Even with the above, container escape and supply-chain compromise of a
CI/CD identity remain the highest-severity unresolved risks for this
cluster, since this repo currently has no runtime (Falco/eBPF) detection
coverage. That gap is intentionally visible in this document rather than
implied to be solved — a threat model that hides its own gaps isn't
useful to the team that has to act on it.
