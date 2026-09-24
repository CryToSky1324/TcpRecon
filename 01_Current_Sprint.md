# 01_Current_Sprint: Evaluation, Documentation & Offline Engineering

**Updated:** 24 September 2026
**Status:** ACTIVE
**Active branch:** `feat/phase-f-offline-probes`
**Current workstream:** Phase F.1 complete — preparing for Phase F.2 (Stateless UDP Probes) and Worker Wiring

## Sprint Goal

Execute strictly offline systems engineering for bounded Layer 7 banner parsing and stateless UDP reconnaissance without relying on external network connectivity or the lab server. Decouple protocol parsers from socket dialing to enable deterministic in-memory verification (`net.Pipe()`), and finalize pipeline benchmarks and documentation.

---

## Verified Starting Baseline

### Phase E: OpenSearch Analytics & Dashboards
**Status:** COMPLETE (Merged into `main`)

Verified work includes:
- Registered index template `tcprecon-alerts` (order 10) enforcing Doc Values on keywords, integers, and IP primitives.
- Pinned JVM heap (`-Xms2g -Xmx2g`) and enforced `size: 0` on aggregation queries to protect host memory bounds.
- Deployed and verified three visual lenses: Exposure Lifecycles (Stacked), Risk Distribution (Histogram), and Cryptographic Findings (Data Table)[cite: 16].
- Assembled and registered `tcprecon-attack-surface-overview` master dashboard[cite: 16].

---

## Phase F Progress (Offline Engineering & App Probes)

### F.1: Layer 7 In-Memory Banner Parsers
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED

- [x] Author dedicated Layer 7 protocol extraction module in `internal/scanner/banners.go`.
- [x] Implement `ParseSSH`:
  - Enforce RFC 4253 protocol string parsing (`SSH-protoversion-softwareversion`).
  - Strip carriage returns and trailing whitespace cleanly.
  - Reject non-SSH binary and plaintext protocol mismatches.
  - Enforce bounded allocation via `io.LimitReader` (1024-byte ceiling) to defeat SSH tarpits (e.g., Endlessh).
- [x] Implement `ParseHTTP`:
  - Transmit minimal RFC-compliant GET probe request (`GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n`).
  - Case-insensitive `Server:` header token extraction.
  - Fall back cleanly to HTTP status line when `Server:` header is omitted.
  - Discard response bodies and enforce 2048-byte `io.LimitReader` allocation boundary against slowloris floods.
- [x] Author in-memory table-driven unit test suite in `internal/scanner/banners_test.go`:
  - In-memory duplex testing via synchronous `net.Pipe()` (zero OS network port binding).
  - Deadlock-free concurrency synchronization with explicit client pipe close and watchdog channels.
  - Cover happy paths, memory exhaustion tarpits, premature EOF closures, and socket deadline timeouts.
  - Verified green with zero race conditions (`go test -race -count=1 ./internal/scanner/...`).

### F.2: Stateless UDP Probes
**Status:** READY TO INITIATE

- [ ] Construct RFC-compliant binary payloads for stateless services:
  - DNS query payload (port 53).
  - NTP v4 client request payload (port 123).
  - SNMP v2c GetRequest payload (port 161).
- [ ] Author mock UDP listener test harnesses using local `net.ListenUDP`.
- [ ] Implement response byte parsers to validate protocol-specific responses versus random ICMP port unreachable replies.

### F.3: Worker Dispatch Integration
**Status:** PENDING

- [ ] Refactor `internal/scanner/worker.go` to consume `ParseHTTP` and `ParseSSH` based on target port heuristics.
- [ ] Integrate safe bounded raw read fallback for arbitrary plaintext TCP services.
- [ ] Wire stateless UDP payloads into `internal/scanner/udp_worker.go` with strict deadline handling.

### F.4: Documentation, Benchmarks & Final Freeze
**Status:** PENDING

- [ ] Measure allocations and throughput across scanner engines (`testing.AllocsPerRun`).
- [ ] Synchronize `docs/DEVLOG.md`, `ARCHITECTURE.md`, and `docs/STATUS.md`.

---

## Phase F.1 Completion Gate

- [x] Layer 7 banner parsing operates over polymorphic `net.Conn` without dialing OS sockets.
- [x] Unit tests execute purely offline in memory via `net.Pipe()`.
- [x] Memory safety enforced via `io.LimitReader` (no unbounded reads on tarpits).
- [x] `go test -race -count=1 -v ./internal/scanner -run "TestParseSSH|TestParseHTTP"` passes with zero race warnings.
- [x] `golangci-lint` passes with zero unchecked error warnings (`errcheck`).

**Gate Status:** PASSED
