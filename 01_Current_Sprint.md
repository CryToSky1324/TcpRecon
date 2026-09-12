# 01_Current_Sprint: Wazuh Ingestion & Analytics Pipeline

**Updated:** 12 September 2026
**Status:** ACTIVE
**Active branch:** `feat/phase-d-wazuh-integration` (Ready for merge to `main`)
**Current workstream:** Phase D complete — Transitioning to Phase E (OpenSearch Analytics & Dashboards)

## Sprint Goal

Deploy reproducible Wazuh SIEM detection, native NDJSON ingestion, and deployment automation on Ubuntu Server 24.04 without crashing `wazuh-analysisd` or dropping telemetry. Transition raw Layer 4/7 state deltas into actionable security alerts.

---

## Verified Starting Baseline

### Phase C: Contextual Enrichment & Explainable Risk Scoring
**Status:** COMPLETE (Merged into `main`)

Verified work includes:
- Non-fatal Layer 7 TLS inspection (version, cipher suites, validity timestamps).
- Zero-alloc LPM CIDR `Matcher` for asset identity mapping (`asset.environment`, `asset.criticality`).
- Deterministic 0–100 risk scoring with strict remediation gating (`service.closed` forced to 0).
- Pure NDJSON telemetry stream adhering strictly to `docs/EVENT_SCHEMA.md`.

---

## Phase D Progress

### D.1: Telemetry Plumbing & Rule Hierarchy
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Configured native `<localfile>` NDJSON ingestion path for `/var/log/tcprecon/events.ndjson`.
- [x] Implemented hierarchical detection rules (`100050`–`100058`) anchored to Suricata parent rule `86600`.
- [x] Added dynamic description interpolation for `data.risk.score` across Low, Medium, and High thresholds.
- [x] Mapped specific threat reasons (`deprecated_tls`, `untrusted_cert`) to escalated severity (Rule `100058`, Level 10).
- [x] Created offline test fixtures under `deployments/wazuh/fixtures/` covering open, closed, changed, and cryptographic findings.
- [x] Verified full offline rule compilation and alert triggering via `wazuh-logtest`.

### D.2: Deployment Automation & Engine Hardening
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Authored portable `install-rules.sh` and `uninstall-rules.sh` lifecycle scripts under `deployments/wazuh/scripts/`.
- [x] Resolved path-resolution bugs using multi-tier fallback detection across standalone and monorepo checkouts.
- [x] Replaced fragile multi-line `sed` expressions with Python DOM XML parsers to prevent `ossec.conf` corruption.
- [x] Enforced `wazuh-analysisd -t` pre-flight syntax gates prior to restarting daemon services.
- [x] Stabilized low-memory laptop host (pinned JVM heap to 2GB, configured startup timeouts).
- [x] Executed end-to-end live probe: injected raw NDJSON into `/var/log/tcprecon/events.ndjson` and confirmed live alert generation in `/var/ossec/logs/alerts/alerts.json`.

---

## Phase D Completion Gate

Phase D is complete only when all of the following are demonstrated:
- [x] `deployments/wazuh/` directory structured cleanly with rules, fixtures, config, and scripts.
- [x] `wazuh-logtest` passes all positive and negative control fixtures.
- [x] `install-rules.sh` and `uninstall-rules.sh` run idempotently with exit code 0.
- [x] Live log sink tails and generates verified alerts in `/var/ossec/logs/alerts/alerts.json`.
- [x] No manual XML edits required; configuration changes survive daemon restarts.

**Gate Status:** PASSED

---

## Immediate Next Actions (Phase E)

1. Merge `feat/phase-d-wazuh-integration` into `main`.
2. Cut feature branch `feat/phase-e-opensearch-analytics`.
3. Bring `wazuh-indexer` and `wazuh-dashboard` online within the 2GB JVM heap boundary.
4. Establish the `wazuh-alerts-*` index pattern and verify aggregations for `data.risk.score` and `data.asset.*`.
5. Construct visualization dashboards tracking exposure lifecycles, risk scores, and deprecated cryptographic findings.
