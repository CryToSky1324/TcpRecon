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

## 2026-08-24: B5 — Explicit Scan Completion

### Goal

Create a trustworthy scan-level completion boundary so TcpRecon can distinguish a genuinely complete scan from simple goroutine/channel termination before lifecycle reconciliation is allowed to interpret absence as service closure.

The required invariant was:

```text
results channel closed != successful scan
```

B5 also had to make parser, resolution, cancellation, worker, and persistence failures visible to higher-level orchestration so B6 can forbid committed-baseline promotion after any incomplete scan.

### Starting state

Before B5, `scanner.Run` returned only a results channel and start time. The results channel closed after worker `WaitGroup` completion, but that only proved the workers had stopped.

Several failure paths were still lossy:

- `StreamTargets` did not return an error to scanner orchestration;
- parse and target-resolution failures could skip intended work without producing a final failed-scan outcome;
- router cancellation could occur but its returned error was discarded;
- worker functions did not provide a reliable scan-level failure signal;
- `StateManager` logged bbolt failures but returned only the open-port count;
- `main` printed `Scan completed` without consulting a final scanner/persistence outcome.

This meant a partial or failed execution could look indistinguishable from a completed run at the orchestration boundary.

### Work completed

I added `internal/scanner/scan_completion.go` with:

- the `ScanStatus` type;
- explicit status values for `completed`, `cancelled`, `resolution_failed`, `parse_failed`, `worker_failed`, and `state_failed`;
- the `ScanCompletion` structure with `Status` and `Err`;
- `Successful()`, which returns true only for `completed` with a nil error;
- producer-error classification for cancellation, parse failure, and resolution failure.

I changed target production so `StreamTargets` returns an error and preserves incomplete-scan diagnostics. Parse and resolution failures may allow remaining valid targets to continue, but the final producer result remains unsuccessful. Cancellation is propagated immediately.

I added explicit asynchronous stage boundaries:

- `produceTargets`;
- `startTargetProducer`;
- `routeJobs`;
- `startJobRouter`;
- `awaitScannerCompletion`;
- `startScannerCompletion`.

`scanner.Run` now returns:

```text
results channel
completion channel
start time
```

rather than treating result-channel closure as the success signal.

I changed `StateManager` to return:

```text
(openPorts, stateErr)
```

instead of only the open-port count. The first persistence failure is retained, later state writes are skipped, and the function continues draining results until the scanner closes the channel.

I added final CLI orchestration so `cmd/tcprecon/main.go` combines scanner completion and state-manager outcome before printing success.

The final completion rules are:

```text
scanner success + state success
-> completed

scanner success + state failure
-> state_failed

scanner failure + state success
-> preserve scanner failure

scanner failure + state failure
-> preserve scanner status and both diagnostic errors
```

I also made unsupported UDP work explicit. An intended UDP port without a supported payload is no longer silently skipped. `UDPWorker` records the first worker-level failure, continues draining queued jobs, and returns the retained error after normal job-channel exhaustion. `Run` propagates that outcome as `worker_failed`.

### Problems encountered

#### Cancellation race in `select`

An early cancellation test initially passed in isolation but failed when repeated. The producer used a `select` containing both:

```text
ctx.Done()
rawJobs <- job
```

When the context was already cancelled and the buffered channel also had space, both cases were ready. Go was allowed to choose the send, so a cancelled producer could occasionally finish with a nil error.

I fixed this by checking `ctx.Err()` before the context-aware send and retaining the `select` for cancellation that occurs while a send is blocked. The previously flaky tests then passed 100 repeated runs.

#### Goroutine errors disappeared at ownership boundaries

`StreamTargets` and `routeJobs` could produce useful errors, but anonymous goroutines discarded them. I introduced one-result buffered error channels so the producer and router could publish their final outcomes without blocking result consumption.

#### Persistence failure could become a deadlock

The first idea was to return immediately from `StateManager` after a bbolt failure. That was unsafe because scanner workers could still be sending results. If the only consumer returned early, workers could block forever, preventing `wg.Wait()` and scanner completion.

The corrected policy makes persistence failure sticky while continuing to drain the results channel.

#### UDP worker failure could strand queued jobs

Changing `UDPWorker` to return immediately on an unsupported payload exposed another pipeline risk: remaining UDP jobs could be left unconsumed, allowing the router to block.

The worker was changed to retain the first error, continue draining queued jobs, and return the retained error only when its job channel closes.

#### Completion helper missing from production code

During CLI integration, `ScanCompletion.Successful()` was found to be missing from the production completion file. Scanner-focused work had not exposed the cross-package problem until `cmd/tcprecon` attempted to call it. The method was added to `internal/scanner/scan_completion.go`, restoring the intended scanner contract.

### Decisions I made

The success rule is intentionally strict:

```text
Status == completed
AND
Err == nil
```

Anything unknown, contradictory, cancelled, failed, or incomplete fails closed.

Result-channel closure and scan completion remain separate concepts. The results channel is an observation-stream lifecycle signal; `ScanCompletion` is the authorization signal for later lifecycle-state promotion.

Cancellation takes precedence over worker errors caused by the same cancelled context.

Ordinary network-probe failures remain per-service conditions and do not become `worker_failed`. TCP connection failures, TLS/banner failures, UDP silence, and similar network behaviour are expected during scanning. `worker_failed` is reserved for failures that prevent intended work from being executed, such as unsupported requested UDP work.

For multiple failures, the scanner status remains the primary classification while additional state failure diagnostics are preserved with joined errors rather than silently discarded.

B5 does not implement the committed lifecycle baseline. It establishes the gate that B6 must enforce:

```text
ScanCompletion.Successful() == true
```

is required before baseline promotion is allowed.

### Evidence

Primary implementation and test files touched during B5 include:

- `cmd/tcprecon/main.go`
- `cmd/tcprecon/main_test.go`
- `internal/scanner/dispatcher.go`
- `internal/scanner/dispatcher_test.go`
- `internal/scanner/scan_completion.go`
- `internal/scanner/scan_completion_test.go`
- `internal/scanner/state.go`
- `internal/scanner/state_test.go`
- `internal/scanner/udp_worker.go`
- `internal/scanner/udp_worker_test.go`
- `internal/utils/parser.go`
- `internal/utils/parser_test.go`

Final verification commands:

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

- repeated completion and UDP-worker tests passed 100 runs;
- scanner race-enabled tests passed;
- CLI race-enabled tests passed;
- `go vet ./...` produced no findings;
- `git diff --check` produced no whitespace errors;
- repository-wide tests passed.

### Remaining limitations

B5 does not yet create or reconcile a temporary current-scan observation set against a committed baseline. That is B6.

`scope_id` and `service_key` remain verified identity helpers but are not yet the durable bbolt partition/key used by reconciliation.

The exact persistent `service_key` v1 representation is still not frozen with a known-vector compatibility test. That should happen at the B6 persistence boundary.

UDP socket reads remain deadline-bound rather than directly context-aware, so cancellation may be delayed until the current UDP read deadline expires even though the final scan is still classified as cancelled.

Lifecycle event emission (`service.opened`, `service.changed`, `service.closed`, `service.reopened`) remains B7 work.

### What I learned

A concurrency pipeline needs explicit ownership not only for channels, but also for errors. A goroutine that can fail but has no outcome channel creates an information-loss boundary.

Channel closure is a transport fact, not a correctness proof. A scan can finish producing results and still be incomplete.

Fail-fast is not always safe in a producer/consumer pipeline. Sometimes the correct failure behaviour is to retain the error while continuing to drain work so other goroutines can terminate cleanly.

Tests that pass once are not sufficient evidence for cancellation-sensitive code. Repeated focused tests exposed a real scheduling-dependent bug that ordinary single-run testing missed.

B5 also reinforced the architectural separation between authorization and persistence: completion decides whether a baseline commit is allowed; B6 must implement the commit itself.

-------------------------------------------------------------------------------------

## 2026-08-28: B6.1-B6.10 — Versioned Lifecycle State Subsystem

### Goal

Build and verify the state-side lifecycle boundary before replacing the active CLI persistence path.

### Work completed

- froze persistent `service_key` v1 with a fixed known vector;
- added schema-v1 `metadata/schema_version` and `metadata/created_at`;
- explicitly rejected unknown, incomplete, malformed, and legacy schemas;
- partitioned committed and temporary state as `scope/<scope_id>/baseline` and `scope/<scope_id>/scan/<scan_id>`;
- stored strict identity-bearing records keyed by recomputable `service_key`;
- implemented successful-scan-gated same-scope opened, changed, closed, and reopened reconciliation;
- implemented atomic whole-baseline promotion with closed tombstone retention;
- implemented incomplete-scan cleanup with baseline preservation and joined diagnostics;
- verified close/reopen durability and post-restart promotion.

### Evidence

Focused tests cover persistent compatibility, schema handling, scope and scan isolation, canonical record validation, TCP/UDP separation, lifecycle transitions, completion gating, atomic rollback, every incomplete completion status, cleanup failure, and database restart.

B6.10 state-subsystem verification and gap-audit checks passed:

```bash
go test -count=1 ./internal/scanner
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
git diff --check
```

The all-files `gofmt -d` audit also exposed one pre-existing extra blank line in committed `internal/scanner/dispatcher_test.go`; B6-changed Go files produced no formatting diff. A separate non-staging `git diff --no-index --check` audit covered every untracked B6 file and found no whitespace errors.

### Remaining blocker

The state subsystem is not active at runtime. The CLI still initializes `PortStates` and calls the legacy `StateManager`. There are no non-test callers of `InitializeStateSchema`, `SaveCurrentService`, or `FinalizeCurrentScan`.

B6 therefore remains open. B6.10 is the state-subsystem verification and gap-audit checkpoint. B6.11 is runtime lifecycle-state integration; B6.12 is final cumulative verification and documentation closure.

B6.11 must initialize schema v1 before legacy bucket creation, explicitly refuse legacy `PortStates` databases, generate and pair one canonical `scope_id` and unique `scan_id`, and call `EnsureCurrentScan` before scanning so an empty successful scan exists durably. Observation persistence must retain a sticky write failure while continuing to drain results. Results-channel closure establishes writer quiescence only. A completion passed as successful to `FinalizeCurrentScan` additionally requires successful scanner completion, successful current-scan creation, and successful persistence of every observation. Finalization occurs exactly once and returned changes remain internal until B7.

-------------------------------------------------------------------------------------

## 2026-08-28: B6.11.1-B6.11.5 — Runtime Lifecycle-State Primitives

### Work completed

- added one shared `internal/utils.ParseTargetLine` boundary for both scope capture and scanner replay;
- added context-aware replay spooling for positional, file, stdin, and HTTP target streams, with immutable logical targets and joined cleanup diagnostics;
- froze the B6-only output contract: legacy `port_state_delta` is retired, stdout is intentionally empty, and B7 lifecycle events remain forbidden;
- added a pre-ownership startup boundary that prepares input, initializes or validates schema v1, refuses legacy/incompatible databases without mutation, and stops at readiness for reservation;
- added atomic exclusive current-scan creation with a distinct same-scope collision sentinel while retaining opaque persistence scan IDs;
- added CLI-local 128-bit random lowercase scan IDs, validation, four-attempt collision retry, and cancellation between attempts;
- added `ownedRuntimeScan`, making replay cleanup explicit after successful reservation;
- added an order-independent result/completion coordinator that offers every result to persistence, retains the first persistence failure, drains to writer quiescence, finalizes once, and closes ownership afterward.

### Verified decisions

- requested logical targets, not resolved result addresses, determine `scope_id`;
- full-line comments and whitespace retain existing target-stream behavior, while inline `#` remains target data;
- no scanner may start before exclusive durable scan reservation;
- results-channel closure proves quiescence only and never proves scanner success;
- persistence failures are sticky but do not stop later persistence attempts or channel drainage;
- cleanup after successful finalization cannot retroactively change the authoritative completion or undo promotion;
- orphan scan buckets remain isolated, unreused, and never automatically promoted. Cleanup remains the non-blocking **B6-M1 — Orphan Temporary-Scan Retention and Cleanup** maintenance backlog item outside the B6 completion gate.

### Evidence

- focused RED/GREEN tests for target preparation, schema refusal, output routing, exclusive reservation, collision/cancellation behavior, ownership, both channel orderings, complete drainage, sticky errors, exactly-once finalization, and cleanup;
- affected `internal/utils`, `internal/scanner`, and `cmd/tcprecon` package suites passed at their respective checkpoints;
- completion/result ordering passed 100 repeated runs;
- all changed Go files were gofmt-clean and tracked/untracked whitespace checks passed.

### Remaining work

B6.11 is not complete. B6.11.6 must freeze missing-completion and full scanner/persistence/finalization precedence. The complete `ScanResult` observation adapter and actual `main` wiring remain outstanding. The executable therefore still creates legacy `PortStates` and calls `StateManager`; the new runtime primitives are verified but inactive. B6.12 remains responsible for repository-wide, race, vet, formatting, whitespace, and documentation closure after runtime activation.

-------------------------------------------------------------------------------------

## 2026-08-29: B6.11.6-B6.12 — Runtime Activation and B6 Closure

### Work completed

- made missing scanner completion fail closed as `worker_failed` with a dedicated discoverable sentinel;
- froze scanner, persistence, finalization, and post-finalization cleanup precedence without allowing cleanup failure to retroactively invalidate a promoted baseline;
- mapped every persistent observation field from `ScanResult` while excluding `TargetName` and transient state;
- characterized orphan temporary scans across restart: IDs cannot be reused, orphans are never promoted automatically, and fresh finalization does not delete them;
- added one top-level lifecycle runtime that prepares targets, derives canonical `scope_id`, validates schema v1, exclusively reserves a runtime `scan_id`, starts the scanner, persists observations, and finalizes exactly once after quiescence;
- changed `main` to invoke that boundary directly and removed reachable CLI use of `PortStates` and `StateManager`;
- froze the B6 output boundary: stdout is intentionally empty in both modes until B7; summaries and failures are emitted through `runtimeOutput` on stderr;
- proved successful empty scans reconcile closures and incomplete or missing-completion scans preserve the committed baseline.

### Runtime contract

```text
validate CLI and ports
-> prepare one replayable logical-target stream
-> derive scope_id
-> open and validate schema v1
-> exclusively reserve scan_id
-> start scanner
-> persist every observation under (scope_id, scan_id)
-> wait for result-writer quiescence and explicit completion
-> finalize exactly once
-> close owned input and database
```

Result-channel closure remains quiescence evidence only. Successful baseline promotion still requires `ScanCompletion.Successful() == true` after scanner and temporary-persistence outcomes are composed.

### Verification

```bash
go test -count=100 ./cmd/tcprecon -run '^(TestLifecycleRuntime|TestMainDelegatesToLifecycleRuntime)'
go test -count=1 ./cmd/tcprecon
go test -count=1 ./internal/scanner
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
git diff --check
```

The package and repository tests that use `httptest` required loopback permission in the restricted execution environment and passed with that permission. All B6-changed Go files are gofmt-clean, and separate non-staging checks covered untracked files. The repository-wide formatting audit still reports the pre-existing extra blank line in `internal/scanner/dispatcher_test.go`; it was intentionally not mixed into B6.

### Remaining limitations

- B7 lifecycle-event serialization is not implemented; no `ServiceChange` leaves the runtime and stdout is intentionally empty.
- **B6-M1 — Orphan Temporary-Scan Retention and Cleanup** remains a non-blocking maintenance item. Orphans are isolated and unpromotable but may consume disk space.
- Legacy state-manager implementation remains in the scanner package as unreachable technical debt.

### Outcome

B6 is complete. Versioned lifecycle state, same-scope reconciliation, successful-scan-only atomic promotion, incomplete-scan preservation, restart behavior, and executable integration are implemented and cumulatively verified.

------------------------------------------------------------------------

## 2026-09-05: B7 — Canonical Lifecycle Event Emission

### Goal

Implement and verify the Phase B7 lifecycle event emitter to transform state reconciliation deltas into schema-compliant NDJSON security events adhering to `docs/EVENT_SCHEMA.md`.

### Starting state

B6 completed versioned state storage, scope-bounded baseline reconciliation, and atomic baseline promotion in bbolt[cite: 3]. However, the runtime stdout stream remained intentionally empty[cite: 3]. The scanner could determine state deltas internally, but could not yet emit versioned `service.opened`, `service.changed`, `service.closed`, and `service.reopened` NDJSON telemetry[cite: 3].

### Work completed

- Implemented `mapDeltaToLifecycleEvent` in `internal/scanner/lifecycle_emitter.go`:
  - `service.opened`: emitted when a port is newly observed without an active baseline record in the current scope.
  - `service.changed`: emitted when an open port mutates its Layer 7 metadata (banner, TLS certificates).
  - `service.reopened`: emitted when a previously closed service is observed open again.
  - `service.closed`: emitted when a previously open service is missing or marked closed following an authoritative scan.
- Implemented deterministic Layer 7 mutation hashing (`hashScanResult`) using `github.com/cespare/xxhash/v2` matching the state engine's hashing model.
- Aligned `models.LifecycleEvent` and sub-models in `internal/models/types.go` to match the canonical schema (`SchemaVersion`, `EventID`, `AssetIdentity`, `NetworkObservation`, `StateChange`, `ScannerMeta`).
- Created table-driven test suite `TestLifecycleEvents` in `internal/scanner/lifecycle_event_test.go` covering 8 distinct lifecycle scenarios:
  - `TC-B7-01`: Brand new service emits `service.opened`.
  - `TC-B7-02`: Modified banner on open port emits `service.changed`.
  - `TC-B7-03`: Reopened service emits `service.reopened`.
  - `TC-B7-04`: Closed service emits `service.closed`.
  - `TC-B7-05`: Identical service suppresses emission.
  - `TC-B7-06`: Incomplete scan suppresses `service.closed`.
  - `TC-B7-07`: Multi-tenant scope isolation (Scope A active port emits `service.opened` in Scope B).
  - `TC-B7-08`: Protocol isolation (TCP open port does not match UDP observation on same port, emitting `service.opened`).

### Problems encountered

#### Nil-pointer dereference in closure branch

In initial drafts of B7-04 (`service.closed`), `curr` is `nil` because the target was not observed. Referencing `curr.TargetIP`, `curr.Protocol`, or `curr.Port` when constructing `EventID` or `AssetIdentity` triggered runtime nil-pointer panics.

Fixed by establishing an identity fallback: when `curr == nil`, all network and asset identity fields fall back to reading from `prior`.

#### Variable shadowing in fallback resolution

An early implementation of the fallback assignment used short variable declarations (`:=`) inside `if curr != nil`, shadowing the outer `ip`, `hostname`, `proto`, and `port` variables and reverting values to `prior` once the block closed. Corrected by using simple assignment (`=`).

#### Multi-tenant scope boundary test failure (`TC-B7-07`)

`TC-B7-07` failed initially because the test fixture injected Scope A's `priorState` into Scope B's mapper execution. In reality, bbolt buckets are strictly partitioned by `scope_id`, so a scan in Scope B returns `nil` for prior records by definition. Corrected the test fixture to pass `priorState: nil` for Scope B.

#### Layer 4 protocol collision (`TC-B7-08`)

`TC-B7-08` failed because an observation on UDP/53 was compared against a TCP/53 baseline, saw matching open states, and was suppressed as identical. Fixed by adding a protocol parity check (`prior.Protocol != curr.Protocol`) to force classification as a new service when L4 protocols differ.

### Decisions I made

- Evaluated mutations via deterministic `xxhash.Sum64String` over normalized observation fields (`State|Banner|CertSubject|CertIssuer|SANs`) rather than chaining struct field equality checks.
- Enforced strict authoritative scan gating: `service.closed` can never be synthesized if `scanSuccessful == false`.
- Prohibited nested slices/arrays in the emitted `LifecycleEvent` envelope to prevent Wazuh `analysisd` decoding truncation bugs.
- Kept the event mapper scoped to single-scope evaluation; multi-tenant isolation is enforced at the database bucket layer, not through cross-scope mapper branching.

### Evidence

Files touched:
- `internal/models/types.go`
- `internal/scanner/lifecycle_emitter.go`
- `internal/scanner/lifecycle_event_test.go`

Verification commands:

```bash
go test -v ./internal/scanner -run TestLifecycleEvents
go test -race -v ./internal/scanner/...
```

Observed result:
- all 8 lifecycle subtests in `TestLifecycleEvents` passed cleanly;
- all 37 package-level unit and integration tests passed;
- race detector confirmed zero race conditions across concurrency pipelines (`ok github.com/CryToSky1324/TcpRecon/internal/scanner 1.164s`).

### Remaining limitations

- Telemetry output wiring into the runtime executable (`cmd/tcprecon`) and live pipeline validation against Wazuh remain to be integrated in Phase 0 / Phase D.
- Orphan temporary scan cleanup (**B6-M1**) remains an open non-blocking maintenance item.

### What I learned

State reconciliation and event mapping operate on different boundaries: the database handles partition isolation by `scope_id`, while the mapper handles transition logic for a single scope. Attempting to make the mapper aware of cross-scope comparisons violates layer separation and produces misleading test fixtures.

Defensive fallback handling is required for negative observations: when an entity disappears (`curr == nil`), the baseline record is the sole source of identity truth.


-------------------------------------------------------------------------------------

## 2026-09-09: C.1 — Non-Fatal TLS Inspection and Cryptographic Telemetry

### Goal

Capture Layer 6/7 cryptographic telemetry (negotiated TLS version, cipher suite, validity boundaries, and verification status) during active port scanning without masking Layer 4 socket availability or dropping open port states on cryptographic failures[cite: 4, 7].

### Starting state

Phase B established robust Layer 4 lifecycle reconciliation and state persistence backed by bbolt[cite: 1, 2]. However, the probe engine operated exclusively at the transport socket level[cite: 4]. The scanner had no mechanism to inspect TLS configurations, evaluate certificate expiration, detect deprecated protocols, or extract leaf identity[cite: 4].

### Work completed

- Created `internal/scanner/tls.go` to isolate cryptographic inspection from Layer 4 socket worker orchestration.
- Defined internal `tlsMetadata` value struct encapsulating version, cipher suite, UTC timestamps, and verification status.
- Implemented `probeTLS(conn net.Conn, targetName string, timeout time.Duration) tlsMetadata`:
  - Set explicit socket deadlines before handshake initiation to defeat socket tarpits.
  - Initialized `tls.Config` with `InsecureSkipVerify: true` and `MinVersion: tls.VersionTLS10` to complete handshakes on untrusted or legacy endpoints[cite: 2, 7].
  - Aggregated standard (`tls.CipherSuites()`) and legacy (`tls.InsecureCipherSuites()`) cipher suites into a zero-allocation package-level slice (`allSupportedCipherSuites`)[cite: 6].
  - Mapped canonical IANA identifiers via `tls.VersionName()` and `tls.CipherSuiteName()`[cite: 6].
  - Executed out-of-band X.509 chain verification via `leaf.Verify()` using package-scoped test hook `customRootCAPool`[cite: 2, 7].
  - Strictly formatted certificate boundaries (`NotBefore`, `NotAfter`) to UTC RFC 3339 strings with trailing `Z`[cite: 10, 11].
- Updated `internal/models/types.go` adding `TLSVersion`, `CipherSuite`, `CertVerified`, `CertNotBefore`, and `CertNotAfter` to `models.ScanResult`.
- Wired `probeTLS` into `internal/scanner/worker.go` immediately after successful Layer 4 connection.
- Standardized Layer 4 state assignment in `worker.go` to lowercase `"open"` matching schema specifications[cite: 1, 9].
- Built 7-scenario table-driven test suite `TestTLSInspection` in `internal/scanner/tls_test.go` covering TLS 1.3, deprecated TLS 1.0/1.1, expired certificates, self-signed/untrusted authorities, plaintext TCP echo services, and hanging tarpits[cite: 7].

### Problems encountered

#### Premature handshake teardown and metadata loss
A standard `tls.Dial` or `InsecureSkipVerify: false` handshake terminates immediately upon encountering expired or untrusted certificates, discarding `ConnectionState.PeerCertificates`[cite: 2].
*Remediation:* Enforced `InsecureSkipVerify: true` during the transport handshake to capture raw peer certificates, followed by out-of-band verification via `leaf.Verify(opts)` to assign `CertVerified` deterministically without failing the probe[cite: 2, 7].

#### Client cipher suite negotiation failure on legacy endpoints (TC-C1-02, TC-C1-03)
Initial test runs against TLS 1.0 and 1.1 listeners failed with empty metadata because `tlsConn.Handshake()` failed with `tls: no cipher suite supported by both client and server`. Since Go 1.14, the runtime client excludes legacy RSA key exchange and CBC cipher suites from default negotiation.
*Remediation:* Explicitly merged `tls.CipherSuites()` with `tls.InsecureCipherSuites()` in a package closure, forcing `ClientHello` to advertise legacy suites required for reconnaissance of legacy systems[cite: 6].

#### Test PKI key exchange incompatibility
The initial test fixture generator hardcoded ECDSA P-256 keys, which legacy TLS 1.0 server configurations could not negotiate with RSA ciphers.
*Remediation:* Split key generation to support both RSA-2048 and ECDSA P-256, and implemented a 2-tier PKI generator (`generateTestCA` and `generateTestLeaf`) binding loopback IPs and hostnames to SAN extensions by default[cite: 7].

#### Watchdog deadlock in test harness
`Worker` was initially invoked synchronously on the test goroutine, preventing the watchdog `select` block from catching hanging sockets.
*Remediation:* Spawned `Worker` in a separate goroutine (`go Worker(...)`), ensuring socket timeouts trigger the test context cancellation cleanly.

### Decisions I made

- **Reconnaissance Inversion Principle:** Web browsers fail closed to protect users; an attack-surface scanner must intentionally support broken/deprecated ciphers to expose vulnerabilities without losing visibility[cite: 2].
- **Non-Fatal Probe Invariant:** Handshake failures on plaintext ports, timeouts, and cryptographic anomalies must return zero-value `tlsMetadata{}` and retain `res.State = "open"`[cite: 4, 7].
- **Zero-Allocation Suite Aggregation:** Merged supported cipher suite IDs inside a package-level `var` closure executed once at startup, avoiding slice allocation overhead across high-throughput worker loops.
- **Strict Stream Separation:** No diagnostic logging or errors emitted on stdout during probe failures, preserving pure NDJSON streams for downstream SIEM consumers[cite: 1, 6, 8].

### Evidence

- Implementation files:
  - `internal/scanner/tls.go`
  - `internal/scanner/tls_test.go`
  - `internal/scanner/worker.go`
  - `internal/models/types.go`
- Verification commands:

```bash
gofmt -w internal/scanner/ internal/models/
go test -v ./internal/scanner -run TestTLSInspection
go test -race -v ./internal/scanner -run TestTLSInspection
go vet ./...

### Observed output:

        All 7 test cases passed (ok github.com/CryToSky1324/TcpRecon/internal/scanner 4.290s).

        Zero race conditions detected under go test -race.

        Zero static analysis issues reported by go vet.

### Remaining limitation

Telemetry enrichment is confined to cryptographic metadata. Target context (CIDR-to-asset mapping, owner, criticality tier) and risk scoring are not yet integrated into the lifecycle pipeline. These belong to Phase C.2 and C.3.

### What I learned

Transport establishment and trust validation are completely separate concerns. Treating an unverified or expired certificate as a fatal dial error introduces critical blind spots into attack surface discovery.

Furthermore, Go's secure-by-default standard library actively works against network reconnaissance tools by hiding legacy ciphers; a security scanner must explicitly override standard client policies to discover deprecated perimeter exposures.

---------------------------------------------------------------------------------

## 2026-09-08: Phase C.2 Asset Inventory Enrichment & Lifecycle NDJSON Plumbing

### Goal
Inject rich context into runtime discoveries by matching discovered IPs against an authoritative logical topology, and wire the entire event emission pipeline directly to `stdout`.

### Work Completed
- Built zero-allocation `Matcher` using `netip.Prefix` and Longest Prefix Matching (LPM) logic inside `internal/enrichment`.
- Authored configuration parsers `LoadRulesFromJSON` and `LoadRulesFromFile` with fail-safe `"unassigned"` fallbacks.
- Re-routed the entire event generation logic using `scanner.EmitLifecycleChanges`, officially connecting internal `ServiceChange` structures to formatted NDJSON.
- Plumbed `-asset-rules` flag from CLI boundary down to state reconciliation sinks.
- Altered test assertions in `cmd/tcprecon` to strictly monitor B7 stdout telemetry boundary rules.

### Decisions I Made
Enrichment happens in the engine, not the SIEM. Expecting downstream platforms to execute dynamic multi-CIDR regex matching imposes brutal performance penalties on the ingestion pipeline. Pre-enriching the telemetry directly during discovery allows OpenSearch to query fields natively.

---------------------------------------------------------------------------

## 2026-09-09: Phase C.3 Explainable Risk Scoring Engine

### Goal
Provide mathematical, bounded, deterministic risk scores and categorically defined severity mapped dynamically per asset exposure.

### Work Completed
- Created `internal/risk` package modeling deterministic scoring (Policy Version `1.0`).
- Mapped explicit threat weights: exposed datastores (+40), remote admin ports (+35), cleartext protocols (+15), deprecated TLS (+30), unverified certificates (+20).
- Applied asset context multipliers natively (`tier-0` adds +20, `tier-1` adds +10).
- Enforced a hard remediation gate: `service.closed` resets final scores to `0` and assigns `"informational"`.
- Wired `risk.EvaluateRisk` across all `mapDeltaToLifecycleEvent` branches.
- Verified repository tests with `go test -race -count=1 ./...` and `go vet ./...`.

### Problem Encountered
Our initial architecture drafted `Reasons` as a JSON array (`"reasons": []`). Running this payload against Wazuh `wazuh-analysisd` parsers invokes critical structural flattening defects.

### Decisions I Made
Enforced a "Zero-Nested-Arrays" invariant. The `RiskMeta` envelope now restricts `Reasons` to a single comma-delimited scalar string (`"reasons": "deprecated_tls,exposed_datastore"`). This guarantees full compatibility with Wazuh JSON decoders while preserving keyword-searchability in Elasticsearch/OpenSearch platforms.
