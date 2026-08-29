# 01_Current_Sprint: Phase B Service Lifecycle Foundation

**Updated:** 29 August 2026
**Status:** ACTIVE
**Active branch:** `feat/service-lifecycle-reconciliation`
**Current workstream:** B7 — lifecycle event emission (B6 complete)

## Sprint goal

Replace TCPRecon's positive-observation hash suppression with a trustworthy lifecycle foundation. The scanner must eventually compare a successfully completed current scan against a committed baseline and emit stable `service.opened`, `service.changed`, `service.closed`, and `service.reopened` events without treating cancelled or partial scans as remediation.

This sprint remains limited to identity, completion, state ownership, reconciliation, and evidence. Wazuh rules, dashboards, contextual risk scoring, and broad enrichment remain outside the active scope.

---

## Verified starting baseline

### Phase 0: Wazuh lab baseline

**Status:** COMPLETE

- Ubuntu Server 24.04 LTS is the supported lab baseline.
- The Wazuh all-in-one environment was rebuilt and verified.
- TCPRecon-specific Wazuh rules and integrations are not part of the active Phase B work.

### Phase A: Repository correctness and baseline tests

**Status:** COMPLETE

Verified work includes:

- direct hostname, IPv4, IPv6, and CIDR input;
- corrected input-source selection and CLI validation;
- IPv6-safe TCP and UDP address construction;
- stdout telemetry and stderr diagnostics separation;
- baseline unit tests, race-enabled tests, and `go vet` cleanup;
- removal of the tracked binary and correction of repository documentation.

Phase B builds on this baseline rather than reopening Phase A without new evidence.

---

## Phase B progress

### B0: Branch and safety baseline

**Status:** COMPLETE

- [x] Create `feat/service-lifecycle-reconciliation` from the verified Phase A baseline.
- [x] Run package tests.
- [x] Run race-enabled tests.
- [x] Run `go vet`.
- [x] Keep local-only assistant instructions outside the repository.

### B1: Trace the current data flow

**Status:** COMPLETE

The runtime path was traced from CLI input through target parsing/resolution, dispatch, TCP/UDP worker execution, the results channel, the state manager, bbolt updates, and current output.

Confirmed limitations:

- workers mainly emit positive observations;
- failed target resolution can be skipped without a scan-level failure result;
- channel closure proves worker exit, not successful scan completion;
- persistent state is updated before a trustworthy completed-scan boundary exists;
- absence cannot currently be interpreted as closure.

**Result:** B1 established the failure model that B2-B5 must respect.

### B2: Define lifecycle and baseline contracts

**Status:** COMPLETE ON PAPER

Defined contracts:

- `service.opened`;
- `service.changed`;
- `service.closed`;
- `service.reopened`;
- `scan_id`;
- `scope_id`;
- `service_key`;
- stable observation fingerprints;
- temporary current-scan observations;
- committed baseline state;
- successful-scan-only baseline promotion.

The original B2 design also proposed `finding_id`. During B4 this was deliberately deferred because the current Phase B model has one lifecycle history per service and does not yet need a second permanent one-to-one identifier.

Active identity model:

```text
scope_id -> service_key -> event_id
```

### B3: Stable scan-scope identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Implementation files:

- `internal/scanner/scope.go`
- `internal/scanner/scope_test.go`

Completed behaviour:

- [x] Define `ScanScope` from target definitions and separate TCP/UDP port sets.
- [x] Normalize hostnames, IP addresses, IPv6 forms, and CIDRs.
- [x] Remove duplicate targets and ports.
- [x] Sort target and port sets deterministically.
- [x] Preserve TCP and UDP as separate scope dimensions.
- [x] Serialize a versioned canonical representation.
- [x] Derive `scope_id` with SHA-256.
- [x] Exclude timestamps and execution-tuning settings.
- [x] Avoid mutating caller-owned input slices.

Verification evidence:

```bash
gofmt -w internal/scanner/scope.go internal/scanner/scope_test.go
git diff --check
go test -count=1 ./internal/scanner -run ScanScope
go test -count=1 ./internal/scanner
go test -race -count=1 ./internal/scanner
go vet ./internal/scanner
```

Runtime note: `ScanScope.ID()` now partitions the lifecycle baseline using the prepared logical targets and separate TCP/UDP port sets.

### B4: Stable service identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Implementation files:

- `internal/scanner/service_identity.go`
- `internal/scanner/service_identity_test.go`

Identity contract:

```text
service_key = f(scope_id, canonical IP, port, protocol)
```

Completed behaviour:

- [x] Identical services produce identical keys.
- [x] Different ports produce different keys.
- [x] TCP and UDP on the same IP/port produce different keys.
- [x] Different IPs produce different keys.
- [x] The same endpoint in different scopes produces different keys.
- [x] Equivalent IPv6 textual forms produce identical keys.
- [x] IPv4-mapped IPv6 and native IPv4 are canonicalized to the same identity through `Unmap()`.
- [x] Invalid IP input returns an error.
- [x] Protocol is strict and accepts only canonical lowercase `tcp` or `udp`.
- [x] Ports outside `1..65535` are rejected.
- [x] Port boundaries `1` and `65535` are accepted.
- [x] Empty `scope_id` is rejected.
- [x] Mutable observation fields are excluded structurally from `ServiceIdentity`.

Verification evidence:

```bash
gofmt -w \
  internal/scanner/service_identity.go \
  internal/scanner/service_identity_test.go

git diff --check
go test -count=1 ./internal/scanner -run 'TestServiceIdentityKey'
go test -count=1 ./internal/scanner
go test -race -count=1 ./internal/scanner
go vet ./internal/scanner
```

Observed result:

- focused service-identity tests passed;
- full scanner-package tests passed;
- race-enabled scanner tests passed;
- `go vet` produced no findings;
- `git diff --check` produced no whitespace errors.

Design decisions closed during B4:

- `finding_id` is deferred until one service can own multiple independent security findings;
- protocol normalization is not performed inside the identity layer; upstream code must provide canonical `tcp`/`udp` values and the identity layer validates them;
- a fixed known-vector compatibility test is deferred until `service_key` becomes persistent bbolt state.

Runtime note: `ServiceIdentity.Key()` is now the durable record key used by temporary observations, reconciliation, and committed baselines.

### B5: Explicit scan completion

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Goal: create an explicit scan-level outcome so lifecycle logic can distinguish successful completion from worker/channel termination.

Implemented completion contract:

```text
successful scan
= producer success
+ router success
+ worker success
+ state persistence success
```

`ScanCompletion.Successful()` returns true only when:

```text
Status == completed
AND
Err == nil
```

Completed behaviour:

- [x] define the `ScanCompletion` result type and ownership boundary;
- [x] represent successful completion explicitly;
- [x] represent cancellation explicitly;
- [x] represent target-resolution failure that makes the intended scope incomplete;
- [x] represent parser/job-production failure;
- [x] represent worker failure that prevents intended work from completing;
- [x] represent state-manager/persistence failure;
- [x] distinguish result-channel closure from successful scan completion;
- [x] expose scanner completion asynchronously from `scanner.Run`;
- [x] preserve producer, router, worker, and persistence diagnostics;
- [x] make persistence failure sticky while continuing to drain results;
- [x] prevent unsupported UDP work from being silently skipped;
- [x] keep worker failure sticky while draining queued UDP jobs;
- [x] make CLI success reporting depend on finalized scanner + state completion;
- [x] establish `Successful()` as the authorization gate that B6 must check before committed-baseline promotion;
- [x] add focused, repeated, race-enabled, static-analysis, and repository-wide tests.

Failure classification:

```text
cancellation          -> cancelled
target parse failure  -> parse_failed
resolution failure    -> resolution_failed
worker failure        -> worker_failed
state failure         -> state_failed
unknown/inconsistent  -> unsuccessful (fail closed)
```

Safety invariant:

```text
results channel closed                  != successful scan
absence + successful complete scan      = lifecycle evidence
absence + incomplete/failed scan        = not closure evidence
ScanCompletion.Successful() == false     = baseline promotion forbidden
```

Verification evidence:

```bash
go test -count=100 ./internal/scanner \
  -run 'TestRun|TestAwaitScannerCompletion|TestStartScannerCompletion|TestUDPWorker'

go test -race -count=1 ./internal/scanner
go test -race -count=1 ./cmd/tcprecon
go vet ./...
git diff --check
go test -count=1 ./...
```

Observed result:

- repeated scanner completion/worker tests passed 100 runs;
- race-enabled scanner tests passed;
- race-enabled CLI tests passed;
- `go vet ./...` produced no findings;
- `git diff --check` produced no whitespace errors;
- the full repository test suite passed.

Boundary with B6:

B5 determines whether a scan is eligible to advance durable lifecycle state. B6 owns the actual versioned baseline schema, temporary current-scan state, reconciliation, and atomic baseline promotion.

### B6: Versioned state and reconciliation

**Status:** COMPLETE — IMPLEMENTED, RUNTIME-ACTIVE, AND VERIFIED

- [x] add versioned bbolt metadata;
- [x] freeze the persistent `service_key` v1 representation with a known-vector compatibility test before using it as durable state;
- [x] isolate baselines by `scope_id`;
- [x] key service records by `service_key`;
- [x] keep temporary current observations separate from committed state;
- [x] compute opened, changed, closed, and reopened transitions;
- [x] commit only after B5 reports a complete successful scan;
- [x] discard incomplete-scan temporary state without changing the baseline;
- [x] preserve state across database restart;
- [x] explicitly reject unknown, incomplete, malformed, and legacy schemas;
- [x] pass focused, repository-wide, race-enabled, vet, B6-touched-file formatting, and whitespace verification;
- [x] replace the CLI's legacy `PortStates` path with runtime calls to `InitializeStateSchema`, `SaveCurrentService`, and `FinalizeCurrentScan`;
- [x] generate one `scan_id`, derive one canonical `scope_id`, and pair both with the matching finalized `ScanCompletion` after writers are quiesced.

#### B6.10 — State-subsystem verification and gap audit

**Status:** COMPLETE CHECKPOINT; NOT FINAL B6 VERIFICATION

The package-level state subsystem passed focused, repository, race, vet, formatting, and tracked/untracked whitespace checks. The audit identified the missing runtime caller and therefore did not close B6.

#### B6.11 — Runtime lifecycle-state integration

**Status:** COMPLETE — B6.11.1-B6.11.9 IMPLEMENTED AND VERIFIED

- [x] share one target-line tokenizer between scope capture and scanner replay;
- [x] spool one-shot target sources with deterministic cleanup and cancellation checks;
- [x] define the temporary B6 output contract: empty stdout, no legacy delta or B7 event serialization;
- [x] initialize/refuse schema v1 before reservation and clean prepared input on rejection;
- [x] generate collision-resistant runtime scan IDs and exclusively create an existing-empty current scan;
- [x] keep persistence scan IDs opaque outside the runtime generator/reservation boundary;
- [x] establish ownership only after durable exclusive reservation;
- [x] coordinate results and scanner completion without arrival-order assumptions;
- [x] attempt persistence for every observation, retain the first failure, and fully drain results;
- [x] finalize exactly once after result-writer quiescence and clean owned replay input afterward;
- [x] freeze missing-completion plus scanner/persistence/finalization error precedence in B6.11.6;
- [x] map every `ScanResult` comparison field into `SaveCurrentService` through the real runtime adapter;
- [x] characterize orphan isolation and non-promotion across restart without adding cleanup policy;
- [x] wire target preparation, canonical `scope_id`, reservation, scanner execution, persistence, and finalization into `main`;
- [x] prove actual CLI ordering opens bbolt only after target preparation and refuses legacy state before scanning.

#### B6.12 — Final cumulative verification and documentation closure

**Status:** COMPLETE

- [x] rerun focused integration tests repeatedly;
- [x] rerun package, repository, race, vet, B6-touched-file formatting, and tracked/untracked whitespace checks;
- [x] document the actual runtime path, schema refusal behavior, empty-scan handling, and remaining limitations;
- [x] close B6 after runtime activation and cumulative verification passed.

All B6-touched Go files are gofmt-clean. The repository-wide audit still reports one pre-existing formatting defect in `internal/scanner/dispatcher_test.go`; it is outside the B6 change set and does not block closure.

Maintenance backlog outside the B6 completion gate:

- **B6-M1 — Orphan Temporary-Scan Retention and Cleanup:** define a future retention policy for isolated, unpromotable orphan scan buckets. B6.11 performs no startup sweep, TTL deletion, migration, or repair.

### B7: Lifecycle event emission

**Status:** PENDING

- [ ] emit one versioned NDJSON object per lifecycle event;
- [ ] use the active identity chain `scope_id -> service_key -> event_id`;
- [ ] include stable identifiers and timestamps;
- [ ] suppress duplicate events for unchanged scans;
- [ ] keep diagnostics on stderr;
- [ ] add unit, integration, and restart tests.

---

## Phase B completion gate

Phase B is complete only when all of the following are demonstrated:

- [ ] the first complete scan creates a committed baseline;
- [ ] an identical complete scan emits no lifecycle delta;
- [ ] a newly observed service emits `service.opened`;
- [ ] a changed positive observation emits `service.changed`;
- [ ] an absent previously open service emits `service.closed` only after a complete scan;
- [ ] a previously closed service emits `service.reopened` when observed again;
- [ ] cancellation and partial scans do not generate false closure or remediation;
- [ ] state and stable identifiers survive database restart;
- [ ] stdout remains valid NDJSON and diagnostics remain on stderr;
- [ ] tests, commands, actual output, and known limitations are documented.

---

## Current documentation evidence

B1-B6 are implemented and verified. `main` now delegates to the lifecycle runtime, which prepares replayable targets, derives `scope_id`, enforces schema v1, reserves a unique `scan_id`, persists temporary observations, and finalizes exactly once after quiescence. Legacy `StateManager` and `PortStates` code remains in the scanner package but is unreachable from the production CLI.

Current documentation responsibilities:

- `ARCHITECTURE.md`: verified current architecture, invariants, explicit completion boundary, and planned reconciliation design;
- `01_Current_Sprint.md`: active Phase B status and completion gates;
- `docs/development/DEVLOG.md`: chronological engineering progression, mistakes, decisions, evidence, and limitations.

README, changelog, event-schema, Wazuh, and dashboard documentation should not claim B6-B7 lifecycle behaviour until the corresponding runtime work exists and is verified.

---

## Immediate next actions

1. Begin B7 with the versioned lifecycle-event schema and stable `event_id` contract.
2. Keep B6 reconciliation results internal until B7 serialization is verified.
3. Retain **B6-M1** as non-blocking maintenance work for orphan temporary-scan retention and cleanup.
