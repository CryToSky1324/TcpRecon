# TcpRecon — System Architecture

This document describes the architecture and evolution of the TcpRecon engine. It explains design goals, tradeoffs, and implementation notes for each major phase of development. Use this as a guide for contributors, reviewers, and maintainers.

Table of contents
- [Overview](#overview)
- [High-level architecture](#high-level-architecture)
- [Phases of evolution](#phases-of-evolution)
  - [Phase 1 — Python prototype & threading limitations](#phase-1---python-prototype--threading-limitations)
  - [Phase 2 — Go migration & memory safety](#phase-2---go-migration--memory-safety)
  - [Phase 3 — Application-layer injection & polymorphism](#phase-3---application-layer-injection--polymorphism)
  - [Phase 4 — State exhaustion & traffic shaping](#phase-4---state-exhaustion--traffic-shaping)
  - [Phase 5 — Cryptographic extraction & UNIX stream discipline](#phase-5---cryptographic-extraction--unix-stream-discipline)
  - [Phase 6 — Wide-area scaling & ingestion engine](#phase-6---wide-area-scaling--ingestion-engine)
- [Observability, testing & benchmarks](#observability-testing--benchmarks)
- [Configuration & operational guidance](#configuration--operational-guidance)
- [Security, legal & ethics](#security-legal--ethics)
- [Decision log & future work](#decision-log--future-work)

## Overview
TcpRecon is a TCP reconnaissance engine designed to perform precise TCP-level checks (3-way handshakes), optionally perform application-layer interactions (TLS, HTTP banner pulls), and scale from single-host probes to wide-area scans. The primary goals are correctness of port-state detection, extraction of useful banner/certificate metadata, and safe, efficient operation at scale.

Definitions
- GIL: Global Interpreter Lock (Python)
- C10k: Informal target of handling 10k concurrent connections
- SNI: Server Name Indication (TLS)
- SAN: Subject Alternative Name (TLS certificate)
- IPS: Intrusion Prevention System

## High-level architecture

A concise view of the main components and data flow:

```mermaid
flowchart LR
  A[Input / Targets] --> B[Target Expansion / Scheduler]
  B --> C[Worker Pool / Goroutines]
  C --> D[Network I/O (epoll/kqueue)]
  D --> E[Protocol Handlers: TCP, TLS, HTTP]
  E --> F[Extraction & Normalization]
  F --> G[Ingestion / Output (JSON/CI/SIEM)]
  F --> H[Metrics & Logging]
  G --> I[Storage / Pipeline]
```

Component responsibilities
- Target Expansion / Scheduler: expands CIDRs, enqueues targets with priority and rate limits.
- Worker Pool: bounded goroutine/worker pool that issues sockets according to tokens.
- Network I/O: uses platform event loop (epoll/kqueue) and Go net package for efficient I/O.
- Protocol Handlers: modular handlers that implement connection, optional TLS handshake, simple application probes (HTTP GET, custom banner reads).
- Extraction & Normalization: cleans and normalizes banner text, certificate SANs, and metadata for ingestion.
- Ingestion / Output: emits structured output and supports CI/CD/SIEM friendly formats (JSON, newline-delimited JSON).

## Phases of evolution

Each phase uses the same structured format: Objective → Problem → Solution → Tradeoffs → Implementation notes.

### Phase 1 — Python prototype & threading limitations
- Objective: Execute full TCP 3-way handshakes to validate port states without depending on Nmap.
- Problem: The prototype used Python's socket library and ThreadPoolExecutor. The Global Interpreter Lock (GIL) limited concurrency; large thread counts consumed memory and blocked CPU-bound work; scaling caused high file-descriptor usage and poor throughput.
- Solution: Prototype validated core logic and edge cases but revealed limitations of Python for high-concurrency scanning.
- Tradeoffs: Python is easy to iterate with but suffers at high concurrency and I/O-bound scale. It was suitable for proof-of-concept but not production-scale scanning.
- Implementation notes: Keep prototype artifacts (scripts, tests) to help reproduce early behavior or for debugging.

### Phase 2 — Go migration & memory safety
- Objective: Achieve massive horizontal scalability without exhausting OS file descriptors or system memory.
- Problem: Naive concurrency leads to race conditions, deadlocks, and panics if Goroutines are unbounded and shared state is not synchronized.
- Solution: Re-implemented the engine in Go. Adopted a Worker Pool Pattern, careful synchronization (channels, contexts), and minimal shared mutable state. Leverage Go runtime and small Goroutine stacks for efficiency.
- Tradeoffs: Go gives compile-time type safety and low per-goroutine overhead; it requires discipline around channels and context cancellation to avoid leaks.
- Implementation notes:
  - Use context.Context with deadlines for every probe.
  - Use connection pools sparingly; prefer ephemeral connections for scanning.
  - Documented examples: link to source files (e.g., cmd/scan/main.go, internal/worker/pool.go) — add exact paths here.

### Phase 3 — Application-layer injection & polymorphism
- Objective: Extract banner data quickly and avoid long timeouts caused by client-first application protocols.
- Problem: Pure TCP handshakes don't retrieve application-layer data; duplicating read/write logic for TLS vs plain TCP creates code churn.
- Solution: Use Go's net.Conn interface to wrap connections and implement polymorphic handlers—wrap net.Conn with TLS when appropriate and reuse the same read/write logic.
- Tradeoffs: Wrapping adds complexity in error handling and timeout propagation; but results in smaller, reusable protocol handlers.
- Implementation notes:
  - Implement a protocol-handler interface: Probe(conn net.Conn, target Target) (Result, error).
  - Add tests for both plain and TLS-wrapped flows.

### Phase 4 — State exhaustion & traffic shaping
- Objective: Prevent self-inflicted DoS and evade target IPS systems by controlling local and remote resource usage.
- Problem: Unthrottled concurrent Goroutines can overwhelm NAT tables on consumer-grade hardware and trigger target protections (rate-limiting / blocking).
- Solution: Introduced token-bucket rate limiting (golang.org/x/time/rate) and a transmission queue so connection attempts block for tokens, decoupling execution from network transmission.
- Tradeoffs: Rate limiting increases scan duration. Need conservative defaults and configurable policies per target/port range.
- Implementation notes:
  - Provide token bucket configuration per-target and global defaults.
  - Expose backoff strategies for transient network errors.
  - Document resource limits: default FD limits, recommended ulimit settings for large scans.

### Phase 5 — Cryptographic extraction & UNIX stream discipline
- Objective: Extract hidden virtual host infrastructure and produce machine-parseable output for ingestion.
- Problem: Connecting to IP addresses without SNI yields catch-all certificates and poor domain info; standard terminal output is hard for downstream systems to parse.
- Solution: Inject the intended hostname into TLS SNI to get host-specific certificates. Normalize certificates (extract CN, SANs) and emit structured JSON for CI/SIEM ingestion. Use UNIX stream discipline (newline-delimited JSON) for easy piping.
- Tradeoffs: SNI injection can trigger additional filtering; ensure legal/ethical scanning policies are followed.
- Implementation notes:
  - Normalize certificate fields and sanitize output.
  - When raw IP testing is required, record the injected SNI and observed certificate separately.
  - Provide output options: pretty, ndjson, protobuf (if needed).

### Phase 6 — Wide-area scaling & ingestion engine
- Objective: Scale from single-target probes to mass scans (e.g., /16 networks) efficiently.
- Problem: Naively expanding CIDR blocks into string lists causes high memory usage when scanning millions of targets.
- Solution: Implemented mathematical bitwise expansion (expandCIDR) to generate IPs on demand and decoupled the IP mapping from raw input strings. Use streaming expansion and worker pull-based consumption to keep memory low.
- Tradeoffs: On-the-fly expansion reduces memory but complicates checkpointing/resume logic; add persistable cursors if scans must be resumable.
- Implementation notes:
  - Implement an iterator-style generator for IP ranges with deterministic ordering.
  - Add persistence checkpoints for long scans (e.g., save last-examined IP and offset).
  - Integrate with ingestion pipeline (ELK, Kafka, or S3) for storage.

## Observability, testing & benchmarks
- Metrics to expose:
  - Probes/sec, successes, failures (broken down by reason), average latency per port, tokens consumed, error rates, goroutine count, open file descriptors.
- Logging:
  - Structured logs (JSON) with trace IDs per probe.
- Tests:
  - Unit tests for target expansion, protocol handlers, TLS extraction and normalization.
  - Integration tests using local test servers (HTTP, TLS with multiple SANs), with deterministic timeouts using net.Pipe where appropriate.
- Benchmarks:
  - Provide benchmark scripts and a performance matrix (e.g., targets/sec vs rate limit settings on representative hardware).
- CI:
  - Add tests that run with mocked network behaviors; keep heavy integration tests optional or gated.

## Configuration & operational guidance
- Default config values:
  - Rate limit (tokens/sec): conservative default (e.g., 20 req/sec) — configurable per deployment.
  - Connection timeout: e.g., 5s
  - Read deadline: e.g., 3s after connection
- Recommended runtime:
  - ulimit -n: set according to scan size; document expected FDs per active connection.
- Runtime flags:
  - --targets, --ports, --rate, --output-format, --resume-checkpoint
- Example run:
  - tcprecon --targets targets.txt --ports 22,80,443 --rate 50 --output ndjson > results.ndjson

## Security, legal & ethics
- Scanning networks and hosts without authorization may be illegal or against provider policy. Include a prominent disclaimer and an "acceptable use" section.
- SNI injection and certificate querying are passive reads of server-provided data but can still be considered intrusive—obtain permission where required.
- Respect robots.txt-like policies if you integrate with web crawling components.
- Provide responsible disclosure guidelines and contact information for incident handling.

## Decision log & future work
- Keep a simple CHANGELOG or DECISIONS.md with entries for:
  - Why the Python prototype was replaced.
  - Why Go and worker-pool + token-bucket were chosen.
  - Why SNI injection was adopted and how it is controlled.
- Future work:
  - Resumeable scans with persistent state.
  - Distributed scanning coordination with secure keying/auth.
  - Pluggable output connectors (Kafka, S3, Elastic).
  - Advanced protocol heuristics (TLS ALPN parsing, HTTP/2 probing).

---

If you want, I can:
- Open a PR to replace ARCHITECTURE.md with this draft (tell me the target branch).
- Add commit links and exact code file references if you point me to the handler files to link.
- Generate a simple Mermaid PNG/SVG and include it in the repo.

Would you like me to create the PR and, if so, which branch should I target?
