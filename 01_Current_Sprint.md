# 01_Current_Sprint: Phase C Enrichment and Risk Scoring Foundation

**Updated:** 09 September 2026
**Status:** ACTIVE
**Active branch:** `feat/phase-c-tls-enrichment`
**Current workstream:** Phase C complete — preparing for Phase D (Reproducible Wazuh Integration)

## Sprint goal

Enhance the Phase B lifecycle foundation by integrating deterministic Layer 7 cryptographic inspection, asset inventory enrichment, and multi-factor explainable risk scoring directly into the scanner engine. The scanner must emit enriched, pre-scored telemetry via an active NDJSON event bus without violating SIEM ingestion constraints.

---

## Verified starting baseline

### Phase B: Service Lifecycle and Remediation Detection

**Status:** COMPLETE

Verified work includes:
- Stable `scope_id` and `service_key` derivation.
- Versioned bbolt state metadata and baseline persistence.
- Successful-scan-gated lifecycle reconciliation (`service.opened`, `service.changed`, `service.closed`, `service.reopened`).
- Phase B builds on this baseline rather than reopening lifecycle core logic without new evidence.

---

## Phase C progress

### C.1: Non-Fatal TLS Inspection
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Extract `TLSVersion`, `CipherSuite`, and certificate validity timestamps.
- [x] Configure out-of-band X.509 verification against custom root pools.
- [x] Aggregate standard and insecure cipher suites to detect deprecated TLS 1.0/1.1 endpoints.
- [x] Ensure non-fatal fallback (retain Layer 4 `open` state on TLS handshake timeouts/failures).

### C.2: Asset Inventory Enrichment & NDJSON Pipeline
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Implement zero-allocation Longest Prefix Match (LPM) CIDR `Matcher`.
- [x] Author robust `LoadRulesFromFile` and `LoadRulesFromJSON` configuration parsers with `"unassigned"` safe fallbacks.
- [x] Export `EmitLifecycleChanges` to stream reconciled deltas unconditionally to `stdout` as NDJSON.
- [x] Wire `-asset-rules` CLI flag through execution bounds.

### C.3: Deterministic Explainable Risk Scoring
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Implement `internal/risk` package evaluating ports, TLS posture, and asset criticality multipliers.
- [x] Bound integer `score` between 0 and 100 with dynamic `severity` thresholds.
- [x] Enforce Remediation Gate: `service.closed` strictly resets score to 0 (`severity: "informational"`).
- [x] Enforce Zero-Nested-Arrays Invariant: Serialize `reasons` as a comma-delimited scalar string.
- [x] Map `models.RiskMeta` envelope directly into the canonical lifecycle event structure.

---

## Phase C completion gate

Phase C is complete only when all of the following are demonstrated:
- [x] `go test -race -count=1 ./...` passes cleanly across all packages.
- [x] `go vet ./...` reports zero static analysis failures.
- [x] `git diff --check` passes with zero whitespace defects.
- [x] Output strictly segregates pure NDJSON lifecycle events on `stdout` and diagnostic summaries on `stderr`.
- [x] Emitted events contain no JSON arrays/slices that break `wazuh-analysisd` compatibility.

**Gate status:** PASSED

---

## Immediate next actions

1. Prepare for **Phase D (Reproducible Wazuh Integration)**: Validate clean Ubuntu Server 24.04 environment.
2. Configure Wazuh `<localfile>` native JSON ingestion path for TCPRecon NDJSON output.
3. Author hierarchical XML rules in `local_rules.xml` matching canonical `service.*` event types and evaluating `risk.score` metrics.
4. Run comprehensive validation of all fixtures via `wazuh-logtest` before manager restarts.
