# 01_Current_Sprint: Phase B Service Lifecycle Foundation

**Updated:** 05 September 2026
**Status:** ACTIVE
**Active branch:** `feat/service-lifecycle-reconciliation`
**Current workstream:** B7 complete — preparing for Phase 0 / Phase D (Wazuh integration rebuild)

## Sprint goal

Replace TCPRecon's positive-observation hash suppression with a trustworthy lifecycle foundation[cite: 5]. The scanner must eventually compare a successfully completed current scan against a committed baseline and emit stable `service.opened`, `service.changed`, `service.closed`, and `service.reopened` events without treating cancelled or partial scans as remediation[cite: 5].

This sprint remains limited to identity, completion, state ownership, reconciliation, and evidence[cite: 5]. Wazuh rules, dashboards, contextual risk scoring, and broad enrichment remain outside the active scope[cite: 5].

---

## Verified starting baseline

### Phase 0: Wazuh lab baseline

**Status:** COMPLETE

- Ubuntu Server 24.04 LTS is the supported lab baseline[cite: 5].
- The Wazuh all-in-one environment was rebuilt and verified[cite: 5].
- TCPRecon-specific Wazuh rules and integrations are not part of the active Phase B work[cite: 5].

### Phase A: Repository correctness and baseline tests

**Status:** COMPLETE

Verified work includes:

- direct hostname, IPv4, IPv6, and CIDR input[cite: 5];
- corrected input-source selection and CLI validation[cite: 5];
- IPv6-safe TCP and UDP address construction[cite: 5];
- stdout telemetry and stderr diagnostics separation[cite: 5];
- baseline unit tests, race-enabled tests, and `go vet` cleanup[cite: 5];
- removal of the tracked binary and correction of repository documentation[cite: 5].

Phase B builds on this baseline rather than reopening Phase A without new evidence[cite: 5].

---

## Phase B progress

### B0: Branch and safety baseline

**Status:** COMPLETE

- [x] Create `feat/service-lifecycle-reconciliation` from the verified Phase A baseline[cite: 5].
- [x] Run package tests[cite: 5].
- [x] Run race-enabled tests[cite: 5].
- [x] Run `go vet`[cite: 5].
- [x] Keep local-only assistant instructions outside the repository[cite: 5].

### B1: Trace the current data flow

**Status:** COMPLETE

The runtime path was traced from CLI input through target parsing/resolution, dispatch, TCP/UDP worker execution, the results channel, the state manager, bbolt updates, and current output[cite: 5].

Confirmed limitations:

- workers mainly emit positive observations[cite: 5];
- failed target resolution can be skipped without a scan-level failure result[cite: 5];
- channel closure proves worker exit, not successful scan completion[cite: 5];
- persistent state is updated before a trustworthy completed-scan boundary exists[cite: 5];
- absence cannot currently be interpreted as closure[cite: 5].

**Result:** B1 established the failure model that B2-B5 must respect[cite: 5].

### B2: Define lifecycle and baseline contracts

**Status:** COMPLETE ON PAPER

Defined contracts:

- `service.opened`[cite: 5];
- `service.changed`[cite: 5];
- `service.closed`[cite: 5];
- `service.reopened`[cite: 5];
- `scan_id`[cite: 5];
- `scope_id`[cite: 5];
- `service_key`[cite: 5];
- stable observation fingerprints[cite: 5];
- temporary current-scan observations[cite: 5];
- committed baseline state[cite: 5];
- successful-scan-only baseline promotion[cite: 5].

The original B2 design also proposed `finding_id`[cite: 5]. During B4 this was deliberately deferred because the current Phase B model has one lifecycle history per service and does not yet need a second permanent one-to-one identifier[cite: 5].

Active identity model:

```text
scope_id -> service_key -> event_id
```

### B3: Stable scan-scope identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Implementation files:

- `internal/scanner/scope.go`[cite: 5]
- `internal/scanner/scope_test.go`[cite: 5]

Completed behaviour:

- [x] Define `ScanScope` from target definitions and separate TCP/UDP port sets[cite: 5].
- [x] Normalize hostnames, IP addresses, IPv6 forms, and CIDRs[cite: 5].
- [x] Remove duplicate targets and ports[cite: 5].
- [x] Sort target and port sets deterministically[cite: 5].
- [x] Preserve TCP and UDP as separate scope dimensions[cite: 5].
- [x] Serialize a versioned canonical representation[cite: 5].
- [x] Derive `scope_id` with SHA-256[cite: 5].
- [x] Exclude timestamps and execution-tuning settings[cite: 5].
- [x] Avoid mutating caller-owned input slices[cite: 5].

Verification evidence:

```bash
gofmt -w internal/scanner/scope.go internal/scanner/scope_test.go
git diff --check
go test -count=1 ./internal/scanner -run ScanScope
go test -count=1 ./internal/scanner
go test -race -count=1 ./internal/scanner
go vet ./internal/scanner
```

Runtime note: `ScanScope.ID()` now partitions the lifecycle baseline using the prepared logical targets and separate TCP/UDP port sets[cite: 5].

### B4: Stable service identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Implementation files:

- `internal/scanner/service_identity.go`[cite: 5]
- `internal/scanner/service_identity_test.go`[cite: 5]

Identity contract:

```text
service_key = f(scope_id, canonical IP, port, protocol)
```

Completed behaviour:

- [x] Identical services produce identical keys[cite: 5].
- [x] Different ports produce different keys[cite: 5].
- [x] TCP and UDP on the same IP/port produce different keys[cite: 5].
- [x] Different IPs produce different keys[cite: 5].
- [x] The same endpoint in different scopes produces different keys[cite: 5].
- [x] Equivalent IPv6 textual forms produce identical keys[cite: 5].
- [x] IPv4-mapped IPv6 and native IPv4 are canonicalized to the same identity through `Unmap()`[cite: 5].
- [x] Invalid IP input returns an error[cite: 5].
- [x] Protocol is strict and accepts only canonical lowercase `tcp` or `udp`[cite: 5].
- [x] Ports outside `1..65535` are rejected[cite: 5].
- [x] Port boundaries `1` and `65535` are accepted[cite: 5].
- [x] Empty `scope_id` is rejected[cite: 5].
- [x] Mutable observation fields are excluded structurally from `ServiceIdentity`[cite: 5].

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

- focused service-identity tests passed[cite: 5];
- full scanner-package tests passed[cite: 5];
- race-enabled scanner tests passed[cite: 5];
- `go vet` produced no findings[cite: 5];
- `git diff --check` produced no whitespace errors[cite: 5].

Design decisions closed during B4:

- `finding_id` is deferred until one service can own multiple independent security findings[cite: 5];
- protocol normalization is not performed inside the identity layer; upstream code must provide canonical `tcp`/`udp` values and the identity layer validates them[cite: 5];
- a fixed known-vector compatibility test is deferred until `service_key` becomes persistent bbolt state[cite: 5].

Runtime note: `ServiceIdentity.Key()` is now the durable record key used by temporary observations, reconciliation, and committed baselines[cite: 5].

### B5: Explicit scan completion

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Goal: create an explicit scan-level outcome so lifecycle logic can distinguish successful completion from worker/channel termination[cite: 5].

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

- [x] define the `ScanCompletion` result type and ownership boundary[cite: 5];
- [x] represent successful completion explicitly[cite: 5];
- [x] represent cancellation explicitly[cite: 5];
- [x] represent target-resolution failure that makes the intended scope incomplete[cite: 5];
- [x] represent parser/job-production failure[cite: 5];
- [x] represent worker failure that prevents intended work from completing[cite: 5];
- [x] represent state-manager/persistence failure[cite: 5];
- [x] distinguish result-channel closure from successful scan completion[cite: 5];
- [x] expose scanner completion asynchronously from `scanner.Run`[cite: 5];
- [x] preserve producer, router, worker, and persistence diagnostics[cite: 5];
- [x] make persistence failure sticky while continuing to drain results[cite: 5];
- [x] prevent unsupported UDP work from being silently skipped[cite: 5];
- [x] keep worker failure sticky while draining queued UDP jobs[cite: 5];
- [x] make CLI success reporting depend on finalized scanner + state completion[cite: 5];
- [x] establish `Successful()` as the authorization gate that B6 must check before committed-baseline promotion[cite: 5];
- [x] add focused, repeated, race-enabled, static-analysis, and repository-wide tests[cite: 5].

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

- repeated scanner completion/worker tests passed 100 runs[cite: 5];
- race-enabled scanner tests passed[cite: 5];
- race-enabled CLI tests passed[cite: 5];
- `go vet ./...` produced no findings[cite: 5];
- `git diff --check` produced no whitespace errors[cite: 5];
- the full repository test suite passed[cite: 5].

Boundary with B6:

B5 determines whether a scan is eligible to advance durable lifecycle state[cite: 5]. B6 owns the actual versioned baseline schema, temporary current-scan state, reconciliation, and atomic baseline promotion[cite: 5].

### B6: Versioned state and reconciliation

**Status:** COMPLETE — IMPLEMENTED, RUNTIME-ACTIVE, AND VERIFIED

- [x] add versioned bbolt metadata[cite: 5];
- [x] freeze the persistent `service_key` v1 representation with a known-vector compatibility test before using it as durable state[cite: 5];
- [x] isolate baselines by `scope_id`[cite: 5];
- [x] key service records by `service_key`[cite: 5];
- [x] keep temporary current observations separate from committed state[cite: 5];
- [x] compute opened, changed, closed, and reopened transitions[cite: 5];
- [x] commit only after B5 reports a complete successful scan[cite: 5];
- [x] discard incomplete-scan temporary state without changing the baseline[cite: 5];
- [x] preserve state across database restart[cite: 5];
- [x] explicitly reject unknown, incomplete, malformed, and legacy schemas[cite: 5];
- [x] pass focused, repository-wide, race-enabled, vet, B6-touched-file formatting, and whitespace verification[cite: 5];
- [x] replace the CLI's legacy `PortStates` path with runtime calls to `InitializeStateSchema`, `SaveCurrentService`, and `FinalizeCurrentScan`[cite: 5];
- [x] generate one `scan_id`, derive one canonical `scope_id`, and pair both with the matching finalized `ScanCompletion` after writers are quiesced[cite: 5].

#### B6.10 — State-subsystem verification and gap audit

**Status:** COMPLETE CHECKPOINT; NOT FINAL B6 VERIFICATION[cite: 5]

The package-level state subsystem passed focused, repository, race, vet, formatting, and tracked/untracked whitespace checks[cite: 5]. The audit identified the missing runtime caller and therefore did not close B6[cite: 5].

#### B6.11 — Runtime lifecycle-state integration

**Status:** COMPLETE — B6.11.1-B6.11.9 IMPLEMENTED AND VERIFIED[cite: 5]

- [x] share one target-line tokenizer between scope capture and scanner replay[cite: 5];
- [x] spool one-shot target sources with deterministic cleanup and cancellation checks[cite: 5];
- [x] define the temporary B6 output contract: empty stdout, no legacy delta or B7 event serialization[cite: 5];
- [x] initialize/refuse schema v1 before reservation and clean prepared input on rejection[cite: 5];
- [x] generate collision-resistant runtime scan IDs and exclusively create an existing-empty current scan[cite: 5];
- [x] keep persistence scan IDs opaque outside the runtime generator/reservation boundary[cite: 5];
- [x] establish ownership only after durable exclusive reservation[cite: 5];
- [x] coordinate results and scanner completion without arrival-order assumptions[cite: 5];
- [x] attempt persistence for every observation, retain the first failure, and fully drain results[cite: 5];
- [x] finalize exactly once after result-writer quiescence and clean owned replay input afterward[cite: 5];
- [x] freeze missing-completion plus scanner/persistence/finalization error precedence in B6.11.6[cite: 5];
- [x] map every `ScanResult` comparison field into `SaveCurrentService` through the real runtime adapter[cite: 5];
- [x] characterize orphan isolation and non-promotion across restart without adding cleanup policy[cite: 5];
- [x] wire target preparation, canonical `scope_id`, reservation, scanner execution, persistence, and finalization into `main`[cite: 5];
- [x] prove actual CLI ordering opens bbolt only after target preparation and refuses legacy state before scanning[cite: 5].

#### B6.12 — Final cumulative verification and documentation closure

**Status:** COMPLETE[cite: 5]

- [x] rerun focused integration tests repeatedly[cite: 5];
- [x] rerun package, repository, race, vet, B6-touched-file formatting, and tracked/untracked whitespace checks[cite: 5];
- [x] document the actual runtime path, schema refusal behavior, empty-scan handling, and remaining limitations[cite: 5];
- [x] close B6 after runtime activation and cumulative verification passed[cite: 5].

All B6-touched Go files are gofmt-clean[cite: 5]. The repository-wide audit still reports one pre-existing formatting defect in `internal/scanner/dispatcher_test.go`; it is outside the B6 change set and does not block closure[cite: 5].

Maintenance backlog outside the B6 completion gate:

- **B6-M1 — Orphan Temporary-Scan Retention and Cleanup:** define a future retention policy for isolated, unpromotable orphan scan buckets[cite: 5]. B6.11 performs no startup sweep, TTL deletion, migration, or repair[cite: 5].

### B7: Lifecycle event emission

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

Implementation files:

- `internal/models/types.go`
- `internal/scanner/lifecycle_emitter.go`
- `internal/scanner/lifecycle_event_test.go`

Completed behaviour:

- [x] emit one versioned NDJSON object per lifecycle event (`SchemaVersion: "1.0"`);
- [x] map delta state transitions to canonical `service.opened`, `service.changed`, `service.reopened`, and `service.closed` event types;
- [x] implement deterministic service mutation tracking via `xxhash` (`hashScanResult`);
- [x] enforce fallback identity extraction from historical `prior` baseline on unobserved/closed targets (`curr == nil`);
- [x] distinguish TCP and UDP on the same port as distinct service identities;
- [x] partition comparisons strictly by `scope_id` without cross-tenant baseline leakage;
- [x] suppress emission on identical states (`nil, nil`);
- [x] suppress `service.closed` on incomplete or unauthoritative scans (`!scanSuccessful`);
- [x] eliminate nested arrays from output models to satisfy Wazuh `analysisd` ingestion constraints;
- [x] verify full 8-case state transition test matrix (`TestLifecycleEvents`) with race detector enabled.

Verification evidence:

```bash
go test -v ./internal/scanner -run TestLifecycleEvents
go test -race -v ./internal/scanner/...
```

Observed result:

- all 8 lifecycle transition cases passed (`TC-B7-01` through `TC-B7-08`);
- 37 package tests across scanner, completion, state reconciliation, and lifecycle emission passed cleanly;
- race detector confirmed zero synchronization defects (`ok github.com/CryToSky1324/TcpRecon/internal/scanner 1.164s`).

---

## Phase B completion gate

Phase B is complete only when all of the following are demonstrated:

- [x] the first complete scan creates a committed baseline[cite: 5];
- [x] an identical complete scan emits no lifecycle delta[cite: 5];
- [x] a newly observed service emits `service.opened`[cite: 5];
- [x] a changed positive observation emits `service.changed`[cite: 5];
- [x] an absent previously open service emits `service.closed` only after a complete scan[cite: 5];
- [x] a previously closed service emits `service.reopened` when observed again[cite: 5];
- [x] cancellation and partial scans do not generate false closure or remediation[cite: 5];
- [x] state and stable identifiers survive database restart[cite: 5];
- [x] stdout remains valid NDJSON and diagnostics remain on stderr[cite: 5];
- [x] tests, commands, actual output, and known limitations are documented[cite: 5].

**Gate status:** PASSED

---

## Current documentation evidence

B1-B7 are implemented and verified. `main` now delegates to the lifecycle runtime, which prepares replayable targets, derives `scope_id`, enforces schema v1, reserves a unique `scan_id`, persists temporary observations, and finalizes exactly once after quiescence[cite: 5]. `mapDeltaToLifecycleEvent` provides canonical NDJSON event translation matching `docs/EVENT_SCHEMA.md`.

Current documentation responsibilities:

- `ARCHITECTURE.md`: verified current architecture, invariants, explicit completion boundary, and planned reconciliation design[cite: 5];
- `01_Current_Sprint.md`: active Phase B status and completion gates[cite: 5];
- `docs/DEVLOG.md`: chronological engineering progression, mistakes, decisions, evidence, and limitations.

---

## Immediate next actions

1. Prepare for **Phase 0 / Phase D (Wazuh Ingestion and Detection Rebuild)**: validate clean Ubuntu Server 24.04 environment.
2. Configure Wazuh `<localfile>` native JSON ingestion path for TCPRecon NDJSON output.
3. Author hierarchical XML rules in `local_rules.xml` mapping to the canonical `service.*` event types.
4. Retain **B6-M1** as non-blocking maintenance work for orphan temporary-scan retention and cleanup[cite: 5].