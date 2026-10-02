# 01_Current_Sprint: Evaluation, Documentation & Offline Engineering

**Updated:** 02 October 2026
**Status:** ACTIVE
**Active branch:** `feat/phase-f-offline-probes`
**Current workstream:** Phase F.2 & F.3 complete — Transitioning to Phase F.4 (Closure & Benchmarks)

## Sprint Goal
Execute offline engineering for stateless UDP reconnaissance and bounded Layer 7 banner parsing without relying on external network dependencies. Finalize project documentation and evaluation benchmarks.

---

## Phase F Progress

### F.1: Advanced Layer 7 Banner Parsers
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Non-blocking banner extraction for SSH (`ParseSSH`) and HTTP (`ParseHTTP`) via `io.LimitReader`.
- [x] Full offline unit testing with `net.Pipe()` across 11 scenarios.

### F.2: Stateless UDP Reconnaissance Engineering
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Implemented `BuildDNSQuery(txID)` and `ValidateDNSResponse(req, resp)` adhering to RFC 1035 (A record query for `localhost`).
- [x] Implemented `BuildNTPRequest()` and `ValidateNTPResponse(resp)` adhering to RFC 5905 (NTPv4 Mode 3 client / Mode 4 server validation).
- [x] Aligned `UDPPayloads` dispatch table with dynamic builder constructors to prevent contract drift.
- [x] Verified table-driven encoders/decoders in `internal/scanner/payloads_test.go` with zero data races.

### F.3: Scanner Pipeline Wiring & Worker Refactoring
**Status:** COMPLETE — IMPLEMENTED AND VERIFIED
- [x] Refactored `internal/scanner/worker.go` with opportunistic TLS probing and safe Layer 7 parsers.
- [x] Refactored `internal/scanner/udp_worker.go` to use fixed 2048-byte allocations (`make([]byte, 2048)`) and strict per-job timeouts.
- [x] Enforced dynamic DNS transaction correlation and protocol-level gatekeepers inside `UDPWorker`.
- [x] Verified complete channel draining and worker-level error tracking on unmapped ports.
- [x] Implemented offline ephemeral UDP mock listeners (`net.ListenUDP` on `127.0.0.1:0`) in `udp_worker_test.go`.

### F.4: Documentation, Benchmarks & Phase F Closure
**Status:** ACTIVE NEXT
- [ ] Run allocation benchmarks (`testing.AllocsPerRun`) asserting zero-allocation hot paths on binary validators.
- [ ] Update `ARCHITECTURE.md` and `docs/DEVLOG.md`.
- [ ] Prepare feature branch for final merge to `main`.
