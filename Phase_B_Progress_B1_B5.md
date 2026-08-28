# Phase B Progress: B1-B5

**Updated:** 24 August 2026  
**Branch:** `feat/service-lifecycle-reconciliation`  
**Current status:** B1-B5 complete; B6 next

## Phase B objective

Replace positive-observation hash suppression with a trustworthy lifecycle foundation that can eventually reconcile a successfully completed current scan against a committed baseline without treating partial, failed, or cancelled scans as remediation.

The active identity chain is:

```text
scope_id -> service_key -> event_id
```

`finding_id` remains deferred until one service can own multiple independent security findings.

---

## B1 — Trace current data flow

**Status:** COMPLETE

### What was established

The existing runtime path was traced through:

```text
CLI/input
-> target parsing and resolution
-> job production
-> TCP/UDP routing
-> worker execution
-> results channel
-> StateManager
-> bbolt state
-> current output
```

### Key findings

- workers primarily emit positive observations;
- target-resolution failure can make the intended scan incomplete;
- connection failure or UDP silence does not prove service closure;
- cancellation can stop production or processing before the intended scope finishes;
- result-channel closure proves worker termination, not successful scan completion;
- absence cannot safely be used as lifecycle evidence without a stronger completion boundary.

### Outcome

B1 produced the failure model used by all later Phase B work.

---

## B2 — Lifecycle and baseline contracts

**Status:** COMPLETE ON PAPER

### Lifecycle vocabulary

```text
service.opened
service.changed
service.closed
service.reopened
```

### Baseline model

```text
temporary current-scan observations
              |
              | only after successful complete scan
              v
       committed baseline
```

### Core invariant

```text
absence + successful complete scan = lifecycle evidence
absence + incomplete scan          = not closure evidence
```

### Identity decision

The earlier `finding_id` proposal was deferred.

Current model:

```text
scope_id -> service_key -> event_id
```

---

## B3 — Stable scan-scope identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

### Implementation

Files:

- `internal/scanner/scope.go`
- `internal/scanner/scope_test.go`

`ScanScope.ID()` derives a deterministic SHA-256 identifier from a versioned canonical representation containing:

- normalized target definitions;
- sorted unique TCP ports;
- sorted unique UDP ports.

### Properties verified

- reordering and duplicate input do not change identity;
- target changes alter identity;
- TCP and UDP port changes alter identity;
- TCP and UDP remain separate dimensions;
- hostnames, CIDRs, IPv4, IPv6, and whitespace are normalized;
- worker count, timeout, rate, timestamps, and duration are excluded;
- canonicalization does not mutate caller-owned slices.

### Remaining boundary

The helper is not yet used to partition the durable bbolt lifecycle baseline. That belongs to B6.

---

## B4 — Stable service identity

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

### Implementation

Files:

- `internal/scanner/service_identity.go`
- `internal/scanner/service_identity_test.go`

Identity:

```text
service_key = f(scope_id, canonical IP, port, protocol)
```

### Properties verified

- identical services produce identical keys;
- different IP, port, protocol, or scope produces a different key;
- TCP and UDP on the same numbered port are separate services;
- equivalent IPv6 forms canonicalize to the same identity;
- IPv4-mapped IPv6 is unmapped to native IPv4 identity;
- protocol is strict lowercase `tcp` or `udp`;
- ports must be within `1..65535`;
- empty `scope_id` and invalid IP/protocol/port are rejected;
- mutable observation fields do not influence identity.

### Design decisions

- `finding_id` remains deferred;
- protocol is validated rather than silently normalized;
- a fixed known-vector compatibility test is deferred until `service_key` becomes durable state in B6.

### Remaining boundary

`service_key` is not yet the durable bbolt baseline key.

---

## B5 — Explicit scan completion

**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

### Goal

Create an explicit scan-level result so lifecycle logic can distinguish successful completion from worker/channel termination.

### Completion model

```text
successful scan
= producer success
+ router success
+ worker success
+ state persistence success
```

`ScanCompletion.Successful()` is true only when:

```text
Status == completed
AND
Err == nil
```

### Status vocabulary

```text
completed
cancelled
resolution_failed
parse_failed
worker_failed
state_failed
```

Unknown or inconsistent outcomes fail closed.

### Implementation completed

- `StreamTargets` now returns producer errors;
- cancellation is propagated deterministically;
- parse and resolution failures can preserve valid remaining work while still marking the run incomplete;
- producer and router goroutine outcomes cross explicit buffered error channels;
- `scanner.Run` exposes an asynchronous completion channel separately from results;
- result-channel closure is no longer treated as the success signal;
- unsupported requested UDP work produces a worker-level failure instead of being silently skipped;
- UDP worker failure is sticky while queued jobs continue to drain;
- `StateManager` returns `(openPorts, stateErr)`;
- persistence failure is sticky while results continue to drain;
- CLI orchestration combines scanner completion and persistence outcome before declaring success;
- multiple scanner/state diagnostics are preserved rather than silently overwritten.

### Important bugs found and corrected

#### Cancellation/select race

With an already-cancelled context and buffer space available, both `ctx.Done()` and a channel send could be ready. Go could choose the send, causing a cancelled producer to return success.

The producer now checks `ctx.Err()` before the context-aware send.

#### State failure deadlock risk

Returning immediately from `StateManager` after bbolt failure could leave workers blocked sending results. State failure is now retained while the manager continues draining results.

#### UDP worker early-exit risk

Returning immediately after unsupported UDP work could strand queued jobs and block the router. The worker now retains the failure and drains queued work before returning it.

### Final invariant provided to B6

```text
ScanCompletion.Successful() == true
    -> baseline promotion may proceed

ScanCompletion.Successful() == false
    -> baseline promotion forbidden
```

B5 supplies the authorization signal. It does not implement durable baseline promotion.

### Verification evidence

```bash
go test -count=100 ./internal/scanner \
  -run 'TestRun|TestAwaitScannerCompletion|TestStartScannerCompletion|TestUDPWorker'

go test -race -count=1 ./internal/scanner
go test -race -count=1 ./cmd/tcprecon
go vet ./...
git diff --check
go test -count=1 ./...
```

Observed:

- 100 repeated completion/worker test runs passed;
- race-enabled scanner tests passed;
- race-enabled CLI tests passed;
- `go vet ./...` passed;
- `git diff --check` passed;
- repository-wide tests passed.

### Known limitation

UDP blocking reads remain deadline-bound rather than immediately context-aware. Cancellation may therefore be delayed until a read deadline expires, but the final completion is still classified as cancelled.

---

## B6 handoff — Versioned state and reconciliation

**Status:** NEXT / ACTIVE WORKSTREAM

B6 should now use the B3-B5 contracts rather than redefining them.

### Required work

1. add explicit bbolt schema metadata and versioning;
2. freeze the persistent `service_key` v1 representation with a known-vector compatibility test;
3. partition durable state by `scope_id`;
4. key services by `service_key`;
5. create temporary current-scan observations separate from the committed baseline;
6. reconcile opened, changed, closed, and reopened transitions only within the same scope;
7. require `ScanCompletion.Successful() == true` before atomic baseline promotion;
8. discard temporary observations after incomplete scans;
9. preserve state across database restart;
10. define schema migration or explicit incompatibility behaviour.

### B6 safety rule

```text
B5 decides whether commit is allowed.
B6 performs the commit.
```

No `service.closed` event should be emitted merely because an observation is missing until B6 has proven same-scope successful-scan reconciliation.
