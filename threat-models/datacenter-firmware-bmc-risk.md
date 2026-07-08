# Threat Model: Firmware/BMC and Datacenter-Adjacent Risk

## Why this is in scope for a D&R engineer

The JD explicitly calls out being "comfortable reasoning about lower-level
infrastructure and datacenter risks, such as firmware/BMC surfaces,
network segmentation/telemetry, and hard-to-observe control paths." This
project's detection/response tooling operates at the OS/cloud/K8s layer;
this document is here to show the reasoning extends below that, even
though building live BMC telemetry collection is out of scope for a
portfolio repo.

## What a BMC is, and why it's dangerous

A Baseboard Management Controller (BMC, e.g. IPMI, iDRAC, iLO) runs on
server hardware independently of the host OS, with its own network
interface, its own firmware, and privileged access to power, console,
and sometimes disk. If compromised, it survives OS reinstalls and is
largely invisible to normal host-based EDR — which is exactly the kind
of "hard-to-observe control path" the JD is pointing at.

## Key risks

1. **Default or weak BMC credentials** left unchanged at deployment —
   historically one of the most common real-world BMC compromises.
2. **BMC network interfaces reachable from general compute VLANs**
   instead of an isolated out-of-band management network.
3. **Firmware not kept current** — BMC CVEs (e.g. historical IPMI/iDRAC
   vulnerabilities) often go unpatched because firmware updates require
   physical/maintenance-window coordination, unlike OS patching.
4. **No telemetry from the BMC layer at all** — most detection stacks
   (including this repo's) only see host OS and application-layer
   events; a BMC-level compromise is often not observable by these
   detections at all, which is itself the risk worth naming.

## What D&R visibility would require

- Out-of-band network segmentation for all BMC interfaces, with flow
  logs feeding the same ingestion layer this repo already normalizes
  cloud/K8s/endpoint telemetry into (a BMC normalizer would be a natural
  `ingestion/normalize_bmc.py` extension of this project).
- Periodic authenticated firmware-version scanning against known-CVE
  lists, tracked the same way `lifecycle-dashboard/score_rules.py`
  tracks detection rule health — coverage and staleness, not just
  pass/fail.
- Alerting on BMC login events and configuration changes, correlated
  against approved maintenance windows (same pattern as the "approved
  on-call debugging session" false-positive note in `DR-K8S-002`).

## Honest scope statement

This repo does not implement BMC telemetry ingestion or detection —
doing so requires hardware access this portfolio project doesn't have.
What this document demonstrates is the threat-modeling reasoning: naming
the risk, the reason it's hard to observe, and what instrumentation
would close the gap, which is the skill being evaluated, not the
hardware itself.
