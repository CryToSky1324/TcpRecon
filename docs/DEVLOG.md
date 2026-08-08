# Development Log

## 2026-08-01: B1 — Trace Current Scanner and State flow

### Goal

Understand the scanner's existing runtime path and identify where targets enter the system, how scan jobs are produced and executed, how results reach persistent state, and which failure paths could make absence unsafe to interpret as service closure.

### Starting state

TcpRecon already had a working Go scanner, TCP and selected UDP workers, a results channel, bbolt-backed state suppression, and JSON event output. However, the lifecycle behavior was still based on positive observations and hash changes rather than complete scan reconciliation.

At this point, the important unknown was not whether the scanner could find open services. It was whether the existing control flow could prove that a missing observation meant a service had actually closed.

### Work completed

I traced the current data flow through the main scanner path:

- CLI parsing and input-source selection in cmd/tcprecon/main.go;
- target parsing and resolution through the streaming parser;
- scan-job construction inside scanner.Run;
- separation of TCP and UDP jobs;
- TCP and UDP worker execution;
- result production through the shared result channel;
- result consumption by the state manager;
- bbolt state updates and delta-event generation.

I also identified the main failure and ambiguity paths:

- target-resolution failures can be reported and skipped without failing the whole scan;
- workers primarily produce positive observations;
- TCP connection errors and UDP silence do not become durable service observations;
- cancellation can stop job production or worker execution before the intended scope finishes;
- result-channel closure proves workers have exited, but does not prove that the intended scan completed successfully;
- existing state updates occur without an explicit successful-scan commit boundary.

### Problem encountered

The main design problem was that absence had multiple possible meanings. A service could be missing from the result stream because it was closed, filtered, timed out, unresolved, skipped, cancelled, or never reached because the scan ended early.

This meant I could not safely implement service.closed by treating every missing current result as a closed service.

I also had to separate two ideas that initially looked similar: worker completion and scan completion. Closing the result channel only proves that result producers stopped. It does not prove that all intended target and port jobs were produced and processed successfully.

### Decision I made

Lifecycle reconciliation must not use absence until TcpRecon has an explicit scan-completion contract.

The future reconciliation path should therefore collect current positive observations into a temporary scan-local set and compare that set with the previous committed baseline only after the scan is known to be complete.

An incomplete or cancelled scan must not be allowed to replace the committed baseline or emit closure events based on missing services.

### Evidence

Inspection focused on the scanner path containing:

- `cmd/tcprecon/main.go`
- `target/parser code`
- `internal/scanner/Dispatcher.go`
- `TCP worker code`
- `UDP worker code`
- `state-manager/state code`

### Observed architectural facts:

- results are positive-observation oriented;
- result-channel closure is not an explicit success signal;
- resolution failures can continue without failing the entire run;
- partial and complete scans are not yet represented as different durable outcomes.

No production lifecycle code was changed during B1. The output of this step was the traced data flow and failure model used by B2.

### Remaining limitation

TcpRecon still had no explicit scan-completion state, no temporary current-scan observation set, and no safe baseline reconciliation path. Existing hash-based state suppression could identify first-seen or changed positive observations, but it could not reliably determine service closure.

### What I learned
A missing observation is not automatically evidence of absence. It becomes useful lifecycle evidence only when the measurement process can prove that the intended scope completed.

Concurrency completion and business-level scan completion are different contracts. A closed channel can prove that goroutines finished while still saying nothing about whether the intended scan was complete.

------------------------------------------------------------------------------------

## 2026-08-02: B2 — Define Lifecycle and Baseline Contracts

### Goal

Define the lifecycle, identity, and baseline rules before implementing reconciliation. The objective was to decide what opened, changed, closed, and reopened mean, what data survives across scans, and when persistent state is allowed to advance.

### Starting state

B1 showed that the scanner produced positive observations but had no reliable successful-scan boundary. The existing bbolt state was useful for suppressing duplicate hashes, but it was not sufficient for complete lifecycle tracking because an absent result could not safely be classified as a closed service.

### Work completed

Defined the Phase B lifecycle vocabulary:
- service.opened: a service is positively observed without an existing active baseline record;
- service.changed: the same stable service is observed again but its comparison fingerprint changes;
- service.closed: a previously committed service is absent from a successfully completed scan of the same scope;
- service.reopened: a previously closed service is positively observed again.

I separated identity from observation data and defined the initial identity concepts:

- scan_id: unique to one execution;
- scope_id: stable identity of the logical scan scope;
- service_key: stable identity of one service within a scope;
- finding_id: initially proposed as a separate lifecycle identity, later reconsidered and deferred during B4;
- fingerprint: mutable normalized observation data used to detect meaningful service changes.

I also defined two different state sets:
Committed baseline

- durable;
- partitioned by scope;
- represents the last successfully completed scan;
- used as the comparison source for lifecycle reconciliation.

Temporary current-scan set:

- belongs to one scan execution;
- keyed by stable service identity;
- stores current positive observations;
- discarded if the scan is incomplete;
- eligible to replace the committed baseline only after successful completion.

### Problem encountered

The difficult part was defining service.closed without turning scanner failures into fake remediation events.

If an interrupted or partially resolved scan were allowed to overwrite the baseline, previously open services could appear to disappear simply because they were never scanned. The same problem applies to DNS failures, skipped jobs, early cancellation, or fatal state errors.

Another design issue was keeping stable identity separate from mutable service metadata. Banner text, TLS metadata, timestamps, latency, and scan settings may change without changing which network service is being tracked.

### Decision I made

Only a successfully completed scan may advance the committed baseline or use absence to produce service.closed.

Incomplete scans keep their observations temporary and do not replace the previous committed baseline.

Stable identity fields must be separated from mutable fingerprint fields. Execution settings such as workers, rate, timeout, timestamps, and scan duration do not belong in persistent service identity.

At this stage I kept finding_id in the design as a possible separate lifecycle identifier, but did not implement it. 

### Evidence

B2 produced design contracts rather than runtime code. The contracts covered:

- lifecycle transition semantics;
- successful-scan-only commit behavior;
- committed baseline ownership;
- temporary current-scan ownership;
- stable identity fields;
- mutable fingerprint fields;
- failure behavior for incomplete scans.

These contracts became the basis for B3 stable scope identity and B4 stable service identity.

### Remaining limitation

All B2 work was still design-only. TcpRecon did not yet have stable scope_id, stable service_key, explicit scan completion, versioned lifecycle persistence, or reconciliation logic.

### What I learned

Lifecycle correctness depends on state-transition rules as much as on scanner accuracy. A scanner can correctly report positive observations and still produce incorrect lifecycle events if it cannot distinguish complete measurements from partial ones.

Identity and fingerprinting solve different problems: identity answers which service is being tracked, while fingerprinting answers whether the observed properties of that service changed.

------------------------------------------------------------------------------------

## 2026-08-06:  B3 — Stable Scan-Scope Identity

### Goal

Create a deterministic `scope_id` so repeated scans of the same logical scope can be compared safely even when equivalent input ordering or formatting changes.

### Starting state

The scanner already accepted target definitions and separate TCP and UDP port sets, but Phase B had no stable scope identity. The existing bbolt state was therefore not yet partitioned by a canonical scan scope, and future closure detection could not safely distinguish one scan definition from another.

### Before implementation

I defined the identity boundary on paper:

- include target definitions;
- include TCP and UDP port sets separately;
- exclude scan time and execution-tuning settings;
- make ordering and duplicate input irrelevant;
- avoid changing caller-owned input slices during canonicalization.

### Work completed

I added `internal/scanner/scope.go` with:

- a `ScanScope` model containing targets, TCP ports, and UDP ports;
- target normalization for hostnames, IP addresses, IPv6 addresses, and CIDRs;
- sorting and duplicate removal for targets and port sets;
- a versioned canonical JSON representation;
- SHA-256 hashing to produce the stable scope ID.

I added `internal/scanner/scope_test.go` with tests covering:

- reordered and duplicated equivalent input;
- changed target definitions;
- changed TCP or UDP port sets;
- TCP and UDP protocol separation;
- exclusion of worker and timeout settings from identity;
- hostname, CIDR, IPv6, and whitespace normalization;
- verification that `ID()` does not mutate the original input slices.


### Problem encountered

The  mistake was trying to compare slices directly with `!=`. Go slices are not directly comparable, and assigning one slice to another does not create an independent backup because both values may refer to the same underlying array.

I corrected the mutation test by cloning the original slices with `slices.Clone`, calling `scope.ID()`, and then comparing the originals with their clones using `slices.Equal`.

I also initially mixed the public `ScanScope` type with the private canonical representation. The tests were changed to exercise `ScanScope.ID()` through the public behaviour rather than constructing the internal canonical type directly.

### Decision I made

The scope ID is a pure function of a versioned canonical scope definition:

```text
normalized targets + sorted unique TCP ports + sorted unique UDP ports
```

TCP and UDP remain separate because the protocol is part of service identity. Worker count, rate limit, timeout, timestamps, scan duration, and scan ID are excluded because they change execution behaviour, not the intended network scope.

Canonicalization creates new result slices before sorting. This keeps `ID()` free from hidden mutation of caller-owned data.

### Evidence

Files:

- `internal/scanner/scope.go`
- `internal/scanner/scope_test.go`

Verification commands:

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
- the full `internal/scanner` test package passed;
- the race-enabled scanner tests passed;
- `go vet` produced no findings;
- `git diff --check` produced no whitespace errors.

### Remaining limitation

The scope-ID helper is implemented and tested only in isolation. It is not yet created from the selected CLI target definitions, passed through `scanner.Run`, attached to scan results, or used to partition bbolt baselines. The current change therefore establishes the identity rule but does not yet change runtime lifecycle behaviour.

Stable service keys, finding IDs, scan completion state, versioned bbolt storage, and lifecycle reconciliation remain future Phase B steps.

### What I learned

A deterministic identifier depends more on defining and testing canonical input than on choosing a hash function. Sorting and deduplication remove accidental differences, but normalization rules determine whether two inputs genuinely describe the same scope.

Go slices are descriptors over shared storage. A mutation test needs an independent clone and element-wise comparison; otherwise it can pass without proving the method is free from side effects.

------------------------------------------------------------------------------------
## 2026-08-07: B4 — Stable Service Identity

### Goal

Create a deterministic `service_key` for one network service within one stable scan scope so the same service can be recognized across repeated scans and future process restarts

### Starting state

B3 provided a deterministic `scope_id`, but individual services still had no stable identity. Scan results contained `TargetIP`, `Port`, and `Protocol`, but there was no canonical key combining those fields with the scope boundary.

Raw textual representations could also create unstable identities. For example, two equivalent IPv6 spellings would produce different hashes if the raw strings were hashed directly. IPv4-mapped IPv6 addresses also needed an explicit rule so they could be treated consistently with native IPv4.

### Before implementation

I reviewed whether service_key and finding_id represented genuinely different identities in the current lifecycle model.

Initial Model:
network service
    │
    ├── service_key      "What service is this?"
    │
    └── finding_id       "What tracked security finding belongs to it?"
             │
             ├── event_id: opened
             ├── event_id: changed
             ├── event_id: closed
             └── event_id: reopened

I defer the `finding_id` from B4 until our program introduces security findings that can exist independently from the underlying service lifecycle.

Current Model:
scope_id
   ↓
service_key
   ↓
event_id

### Revised B4 Scope
Must prove:
- same IPv4 service → same service_key
- repeated derivation of the same service → same service_key
- TCP/443 != UDP/443
- different ports → different service_key
- different IPs → different service_key
- different scope_id → different service_key
- restart/repeated execution → same service_key
- transient fields do not affect service_key
- invalid IP/protocol/port → error

### Work completed
I added `internal/scanner/service_identity.go` with:

- a `ServiceIdentity` model containing `ScopeID`, `IP`, `Port` and `Protocol`;
- a versioned canonical JSON representation;
- SHA-256 hashing to produce a stable hexadecimal `service_key`;
- IP parsing through `netip.ParseAddr`;
- canonical IPv6 formatting;
- Unmap() handling so IPv4-mapped IPv6 and native IPv4 resolve to the same service identity;
- validation of protocol which only accepts `tcp` and `udp` currently;
- validation requiring service ports to be within `1..65535`;
- rejection of an empty `scope_id`

I added `internal/scanner/service_identity_test.go` with tests covering:

- identical services produce identical keys;
- different ports produce different keys;
- TCP and UDP on the same IP/Port produce different keys;
- different IPs produce different keys;
- identical endpoints in different scopes produce different keys;
- equivalent IPv6 textual forms produce identical keys;
- IPv4 and IPv4-mapped IPv6 forms produce identical keys;
- invalid IP input returns an error;
- non-canonical or unsupported protocols return an error;
- invalid ports return an error;
- port boundaries 1 and 65535 are accepted;
- an empty scope ID returns an error. 


### Problem encountered

The first hashing implementation also used raw IP strings. An IPv6-equivalence test demonstrated that two valid textual representations of the same address produced different hashes. Fixed by parsing the address and hashing its canoncial `Unmap().String()` representation.

### Decision I made

The Phase B identity model was simplified to Model 1:

scope_id -> service_key -> event_id

service_key identifies one network service within one scope:

scope_id + canonical IP + port + protocol

A separate finding_id is deferred until TcpRecon has a real need for multiple independent security findings attached to the same service, such as exposure, TLS-policy, certificate, or vulnerability findings.

I also chose not to freeze the exact service-key hash with a known-vector compatibility test yet. The key is not persisted in bbolt at this stage. The known-vector test should be added at the persistence boundary, when changing the serialization would become a storage-compatibility problem.

Reconsidered protocol handling. Instead of normalizing arbitrary protocol casing inside the identity layer, I decided the internal contract should be strict: only canonical lowercase `tcp` and `udp` are accepted.

### Evidence

Files:

- `internal/scanner/service_identity.go`
- `internal/scanner/service_identity_test.go`

Verification commands:

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
- the full `internal/scanner` test package passed;
- the race-enabled scanner tests passed;
- `go vet` produced no findings;
- `git diff --check` produced no whitespace errors.

### Remaining limitation

`ServiceIdentity.Key()` is implemented and tested only in isolation for B4, not yet 
attached to runtime scan results, used as a bbolt key,  or consumed by lifecycle reconciliation.

The exact version-1 key representation is also not frozen by a known-vector compatibility test yet. That test is intentionally deferred until service_key becomes persistent state.

Explicit scan completion, versioned lifecycle persistence, temporary current-scan storage, baseline commit semantics, and lifecycle reconciliation remain future Phase B work.

### What I learned

Stable service identity requires both deterministic hashing and a strict definition of which fields are allowed to influence identity. Mutable observation data such as banners, TLS metadata, state, timestamps, and scan settings must stay outside the key.

Normalization belongs at the correct boundary. IP addresses have multiple equivalent textual representations, so canonicalization belongs in service identity.
