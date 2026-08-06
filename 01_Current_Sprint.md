# 01_Current_Sprint: Phase B Service Lifecycle Foundation

**Updated:** 6 August 2026  
**Status:** ACTIVE  
**Active branch:** `feat/service-lifecycle-reconciliation`

## Sprint goal

Replace TCPRecon's positive-observation hash suppression with a trustworthy lifecycle foundation. The scanner must eventually compare a completed current scan against a committed baseline and emit stable `service.opened`, `service.changed`, `service.closed`, and `service.reopened` events without treating cancelled or partial scans as remediation.

This sprint is intentionally limited to identity, completion, state ownership, reconciliation, and evidence. Wazuh rules, dashboards, contextual risk scoring, and broad enrichment remain outside the active scope.

---

## Verified starting baseline

### Phase 0: Wazuh lab baseline

**Status:** COMPLETE

- Ubuntu Server 24.04 LTS is the supported lab baseline.
- The Wazuh all-in-one environment has been rebuilt and verified.
- TCPRecon-specific Wazuh rules and integrations have not yet been restored.

### Phase A: Repository correctness and baseline tests

**Status:** COMPLETE

Verified work includes:

- direct hostname, IPv4, IPv6, and CIDR input;
- corrected input-source selection and CLI validation;
- IPv6-safe TCP and UDP address construction;
- stdout telemetry and stderr diagnostics separation;
- baseline unit tests, race-enabled tests, and `go vet` cleanup;
- removal of the tracked binary and correction of repository documentation.

Phase B is built on this baseline rather than reopening Phase A without new evidence.

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

The current path was traced from CLI input through target parsing, dispatch, worker execution, the results channel, the state manager, bbolt, and event output.

Confirmed limitations:

- workers mainly emit positive observations;
- failed target resolution can be skipped without a scan-level failure result;
- channel closure proves worker exit, not successful scan completion;
- the state manager updates persistent state before a trustworthy completed-scan boundary exists;
- absence cannot currently be interpreted as closure.

### B2: Define lifecycle and identity contracts

**Status:** COMPLETE ON PAPER

Defined contracts:

- `service.opened`;
- `service.changed`;
- `service.closed`;
- `service.reopened`;
- `scan_id`;
- `scope_id`;
- `service_key`;
- `finding_id`;
- stable observation fingerprints;
- temporary current-scan observations versus committed baseline state.

These contracts are design inputs. They are not yet runtime behaviour.

### B3: Stable scan-scope identity

**Status:** IMPLEMENTED AND VERIFIED LOCALLY; COMMIT PENDING

Implementation files:

- `internal/scanner/scope.go`
- `internal/scanner/scope_test.go`

Completed behaviour:

- [x] Define a `ScanScope` from target definitions and separate TCP and UDP port sets.
- [x] Trim and lowercase hostnames and remove a trailing dot.
- [x] Canonicalise IP and IPv6 textual forms.
- [x] Mask CIDRs to their network prefix.
- [x] Remove duplicate targets and ports.
- [x] Sort targets and port sets deterministically.
- [x] Preserve TCP and UDP as separate parts of scope identity.
- [x] Serialize a versioned canonical representation.
- [x] Derive the scope ID with SHA-256.
- [x] Exclude timestamps and execution-tuning settings from the identity model.
- [x] Avoid mutating caller-owned input slices.

Tests cover:

- equivalent reordered and duplicated inputs;
- changed target definitions;
- changed TCP and UDP port sets;
- TCP and UDP separation;
- hostname, CIDR, IPv6, and whitespace normalization;
- exclusion of execution settings;
- input-slice immutability.

Verification evidence:

```bash
gofmt -w internal/scanner/scope.go internal/scanner/scope_test.go
git diff --check
go test -count=1 ./internal/scanner -run ScanScope
go test -count=1 ./internal/scanner
go test -race -count=1 ./internal/scanner
go vet ./internal/scanner
```

Observed result:

- focused scope tests passed;
- the full scanner package passed;
- race-enabled scanner tests passed;
- `go vet` produced no findings;
- `git diff --check` produced no whitespace errors.

Remaining limitation:

`ScanScope.ID()` is still an isolated helper. The CLI does not yet construct it, `scanner.Run` does not receive it, scan results do not carry it, and bbolt does not partition state by it.

### B4: Stable service and finding identity

**Status:** NEXT

Planned acceptance tests:

- [ ] identical IPv4 service input produces the same service key;
- [ ] equivalent IPv6 textual forms produce the same service key;
- [ ] TCP and UDP on the same numbered port produce different service keys;
- [ ] the same service within the same scope produces the same finding ID across process restarts;
- [ ] the same service in a different scope produces a different finding ID;
- [ ] transient observation fields do not affect identity;
- [ ] identity generation does not mutate caller-owned values.

Implementation begins only after the identity rules and failing tests are reviewed.

### B5: Explicit scan completion

**Status:** PENDING

- [ ] represent success, cancellation, target-resolution failure, parser failure, worker failure, and state failure;
- [ ] distinguish worker completion from successful scan completion;
- [ ] prevent incomplete scans from committing a baseline;
- [ ] preserve evidence about why a scan was incomplete.

### B6: Versioned state and reconciliation

**Status:** PENDING

- [ ] add versioned bbolt metadata;
- [ ] isolate baselines by `scope_id`;
- [ ] keep current observations separate from committed state;
- [ ] compute opened, changed, closed, and reopened transitions;
- [ ] commit only after a complete successful scan;
- [ ] preserve state across database restart;
- [ ] define migration or explicit incompatibility behaviour.

### B7: Lifecycle event emission

**Status:** PENDING

- [ ] emit one versioned NDJSON object per lifecycle event;
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

This B3 shipment updates:

- `ARCHITECTURE.md`, to separate current behaviour from target architecture and record the isolated scope-ID invariant;
- `00_Architecture.md`, to record delivery status and Phase B progress;
- `01_Current_Sprint.md`, to replace the stale Phase 0/Phase A plan with the active Phase B work;
- `docs/development/DEVLOG.md`, to record implementation decisions, mistakes, verification, and limitations.

No README, changelog, event-schema, Wazuh, or dashboard update is required because B3 does not yet change user-visible runtime behaviour or emitted telemetry.

---

## Immediate next actions

1. Review the B3 code and documentation diff.
2. Rewrite the personal reasoning portions of the devlog in the author's own words.
3. Stage only the B3 implementation and documentation files.
4. Re-run formatting, tests, race tests, `go vet`, and `git diff --check` against the staged change.
5. Commit the bounded B3 shipment.
6. Begin B4 with identity rules and failing tests before implementation.
