# 01_Current_Sprint: Evaluation, Documentation & Offline Engineering

**Updated:** 02 October 2026
**Status:** COMPLETE (Ready for merge to `main`)
**Active branch:** `feat/phase-f-offline-probes`
**Current workstream:** Phase F complete — Documentation synchronized & Benchmarks verified

## Sprint Goal
Execute offline systems engineering for bounded Layer 7 banner parsing and stateless UDP reconnaissance without external network dependencies. Decouple protocol parsers from socket dialing to enable deterministic in-memory verification (`net.Pipe()`, `net.ListenUDP`), and record hot-path benchmark evidence.

---

## Phase F Progress (Offline Engineering & App Probes)

### F.1: Layer 7 In-Memory Banner Parsers
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Dedicated Layer 7 banner parsing in `internal/scanner/banners.go`.
- [x] Non-blocking `ParseSSH` (1024-byte `io.LimitReader`) and `ParseHTTP` (2048-byte `io.LimitReader`).
- [x] In-memory unit test suite in `internal/scanner/banners_test.go` using `net.Pipe()`.
- [x] Verified clean under `-race`.

### F.2: Stateless UDP Reconnaissance Engineering
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] `BuildDNSQuery(txID)` and `ValidateDNSResponse(req, resp)` adhering to RFC 1035 (`localhost` A-record, dynamic ID).
- [x] `BuildNTPRequest()` and `ValidateNTPResponse(resp)` adhering to RFC 5905 (NTPv4 Mode 3 Client / Mode 4 Server).
- [x] Aligned `UDPPayloads` dispatch table with builder constructors to eliminate contract split-brain.
- [x] Table-driven binary verification in `internal/scanner/payloads_test.go`.

### F.3: Pipeline Wiring & UDPWorker Hardening
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Refactored `internal/scanner/udp_worker.go` to use fixed 2048-byte allocations (`make([]byte, 2048)`).
- [x] Enforced per-job ephemeral DNS transaction IDs to eliminate concurrency collision.
- [x] Implemented binary response gatekeepers (`ValidateDNSResponse`, `ValidateNTPResponse`).
- [x] Verified non-blocking job channel draining and error tracking on unmapped UDP ports.
- [x] Offline ephemeral UDP mock listeners (`net.ListenUDP` on `127.0.0.1:0`) in `udp_worker_test.go`.

### F.4: Documentation, Benchmarks & Final Freeze
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Authored allocation benchmarks in `internal/scanner/payloads_bench_test.go`.
- [x] Verified 0 B/op and 0 allocs/op across encoders and response gatekeepers:
  - `BenchmarkBuildDNSQuery-4`: 0.3642 ns/op, 0 B/op, 0 allocs/op
  - `BenchmarkValidateDNSResponse-4`: 1.516 ns/op, 0 B/op, 0 allocs/op
  - `BenchmarkBuildNTPRequest-4`: 0.3519 ns/op, 0 B/op, 0 allocs/op
  - `BenchmarkValidateNTPResponse-4`: 1.875 ns/op, 0 B/op, 0 allocs/op
- [x] Synchronized `ARCHITECTURE.md`, `01_Current_Sprint.md`, and `docs/development/DEVLOG.md`.

---

## Phase F Completion Gate
- [x] Layer 7 banner parsing operates over polymorphic `net.Conn` without external socket dialing.
- [x] Unit tests execute purely offline in memory (`net.Pipe()`) and ephemeral mock listeners (`127.0.0.1:0`).
- [x] Memory safety strictly enforced via `io.LimitReader` and fixed 2048-byte socket allocations.
- [x] Hot-path binary validation executes with 0 heap allocations (`0 B/op`, `0 allocs/op`).
- [x] `go test -race -count=1 ./...` passes cleanly with zero race warnings.
- [x] `go vet ./...` and `git diff --check` report zero defects.

**Gate Status:** PASSED
