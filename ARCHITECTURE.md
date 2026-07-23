# TcpRecon — System Architecture

This document describes the architecture and evolution of the TcpRecon engine. It explains design goals, tradeoffs, and implementation notes for each major phase of development. Use this as a guide for implementation, operations, and contribution.

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
TcpRecon is a TCP reconnaissance engine designed to perform precise TCP‑level checks (3‑way handshakes), optionally perform application‑layer interactions (TLS, HTTP banner pulls), and scale from single‑host debugging to wide‑area reconnaissance. This document covers architecture, design tradeoffs, operational guidance, and evolution history.

Definitions
- GIL: Global Interpreter Lock (Python)
- C10k: Informal target of handling 10k concurrent connections
- SNI: Server Name Indication (TLS)
- SAN: Subject Alternative Name (TLS certificate)
- IPS: Intrusion Prevention System

## High-level architecture

A concise view of the main components and data flow:

![Architecture diagram](docs/architecture.svg)

Component responsibilities
- Target Expansion / Scheduler: expands CIDRs, enqueues targets with priority and rate limits.
- Worker Pool: bounded goroutine/worker pool that issues sockets according to tokens.
- Network I/O: uses platform event loop (epoll/kqueue) and Go net package for efficient I/O.
- Protocol Handlers: modular handlers that implement connection, optional TLS handshake, simple application probes (HTTP GET, custom banner reads).
- Extraction & Normalization: cleans and normalizes banner text, certificate SANs, and metadata for ingestion.
- Ingestion / Output: emits structured output and supports CI/CD/SIEM friendly formats (JSON, newline‑delimited JSON).

## Phases of evolution

Each phase uses the same structured format: Objective → Problem → Solution → Tradeoffs → Implementation notes.

### Phase 1 — Python prototype & threading limitations

The Objective: Execute full TCP 3‑way handshakes to validate port states without relying on pre‑packaged binaries like Nmap.

The Problem: The initial prototype utilized Python's socket library and concurrent.futures.ThreadPoolExecutor, introducing two fatal structural flaws. First, Python's Global Interpreter Lock (GIL) prevented true parallel execution. OS‑level threads consumed 1–2MB of RAM per stack, meaning 1,000 threads consumed gigabytes of memory and induced severe CPU context‑switching thrashing. Second, blindly calling recv() on "client‑first" protocols (like HTTP on port 80) caused threads to hang indefinitely, forcing workers to absorb maximum timeout penalties and effectively deadlocking the scanner.

The Solution: The Python architecture was abandoned in favor of Go, capitalizing on its native C10k‑capable scheduler and lightweight concurrency model.

Tradeoffs: Python remains useful as a prototype and debugging tool; the artifacts were preserved for regression traces and early testcases.

Implementation notes
- Keep prototype artifacts (scripts, tests) to help reproduce early behavior or for debugging.

### Phase 2 — Go migration & memory safety

The Objective: Achieve massive horizontal scalability without exhausting OS file descriptors or system memory.

The Problem: Naive concurrency in systems languages leads to race conditions, deadlocks, and kernel panics if Goroutines are not strictly orchestrated.

The Solution: We replaced heavy OS threads with the Worker Pool Pattern using Go's native event loop (epoll/kqueue) and Goroutines, which start at a small memory footprint. Compile‑time memory safety was engineered using channel‑based communication to avoid shared mutable state. A sync.WaitGroup (Monitor Pattern) runs in a dedicated goroutine to prevent the main thread from blocking while workers drain queues.

Tradeoffs: Go gives compile‑time type safety and low per‑goroutine overhead; it requires discipline around channels and context cancellation to avoid leaks.

Implementation notes
- Use context.Context with deadlines for every probe.
- Prefer ephemeral connections for scanning; avoid long‑lived shared connection pools unless necessary.
- Keep examples and references to source files in the repo (e.g., cmd/scan/main.go, internal/worker/pool.go).

### Phase 3 — Application‑layer injection & polymorphism

The Objective: Extract valuable banner data instantly, bypassing the timeout penalties of client‑first protocols.

The Problem: Standard TCP handshakes without application‑layer interaction fail to extract data from modern web servers. Additionally, passing unvalidated hostnames directly into C‑level sockets can cause resolution errors and unexpected failures.

The Solution: We leveraged Go's net.Conn interface to dynamically wrap connections in TLS when appropriate and reuse read/write logic. Workers inject lightweight application‑layer payloads (for example, an HTTP GET for port 80/443) immediately after the handshake to force servers to return headers quickly. Pre‑flight resolution and validation filter invalid targets before socket creation, using controlled resolver behavior (e.g., restricting to IPv4 when configured).

Tradeoffs: Injecting application‑layer payloads increases the chance of triggering IDS/IPS rules and must be opt‑in for sensitive scans.

Implementation notes
- Implement a protocol‑handler interface: Probe(conn net.Conn, target Target) (Result, error).
- Add unit and integration tests for plain and TLS‑wrapped flows.

### Phase 4 — State exhaustion & traffic shaping

The Objective: Prevent self‑imposed Denial of Service (DoS) and evade target Intrusion Prevention Systems (IPS).

The Problem: High concurrency without throughput control exhausts local NAT tables and triggers upstream protections. Concurrency (goroutines) is not the same as transmission throughput (packets/sec). Consumer‑grade routers can hit NAT table limits, causing local packet drops and network errors.

The Solution: Decouple execution from transmission with a Token Bucket Rate Limiter (golang.org/x/time/rate). A global token bucket enforces a packets‑per‑second ceiling; goroutines block for tokens before initiating network dials. Implement context cancellation and os/signal handling to trap SIGINT and propagate cancellation to running workers, ensuring graceful teardown and preventing file descriptor leaks.

Tradeoffs: Rate limiting increases overall scan duration and requires conservative defaults tuned per deployment.

Implementation notes
- Provide per‑target and global token‑bucket configuration.
- Expose backoff strategies for transient errors.
- Document ulimit and expected FD usage per active connection.

### Phase 5 — Cryptographic extraction & UNIX stream discipline

The Objective: Extract hidden virtual host infrastructure and prepare the tool for CI/CD or SIEM ingestion.

The Problem: Connecting by raw IP without SNI yields catch‑all certificates (e.g., invalid2.invalid). Freeform terminal output is fragile for automated pipelines and tools like jq.

The Solution: Inject the target hostname into TLS SNI to retrieve host‑specific certificates. Extract certificate CN and SANs from the TLS ConnectionState and normalize them for ingestion. Adopt UNIX stream discipline: structured JSON output to stdout (ndjson) for pipeline usage, with diagnostics to stderr. The ScanReport payload is marshaled into clean JSON and sent to stdout; diagnostic and progress logs go to stderr.

Tradeoffs: SNI injection can trigger additional filtering on some networks; make injection opt‑in and record injected SNI alongside observed certificate data.

Implementation notes
- Record injected SNI and observed certificate separately when testing raw IPs.
- Sanitize certificate and banner output before ingestion.
- Provide output modes: pretty, ndjson, protobuf.

### Phase 6 — Wide‑area scaling & ingestion engine

The Objective: Scale the engine from single‑target probes to mass‑scanning wide‑area networks (e.g., /16 CIDR blocks).

The Problem: Expanding large CIDR blocks naively into in‑memory lists causes unacceptable memory usage. Scanning millions of IP/port permutations requires careful memory and state management.

The Solution: Implement on‑demand CIDR expansion (expandCIDR) and an iterator‑style generator that yields IPs deterministically. Decouple target parsing from expansion and pass compact ScanJob structs (IP, TargetName, Port) through channels to workers. Add persistence checkpoints for long‑running scans and deterministic cursors to resume scans safely.

Tradeoffs: On‑the‑fly expansion complicates checkpointing/resume logic; durable cursors and deterministic ordering are required for resumability.

Implementation notes
- Use streaming expansion and worker pull‑based consumption.
- Add resume checkpoints with deterministic cursors.
- Integrate ingestion with storage backends (ELK, Kafka, S3) as needed.

## Observability, testing & benchmarks

- Metrics to expose: probes_total (labels: result, port), probes_inflight, probe_duration_seconds (histogram), fd_open, tokens_consumed_total.
- Structured logs: include trace_id, run_id, target_ip, target_port, sni, probe_type, result, duration_ms, error.
- Tests: unit tests for expansion and handlers; integration tests using local test servers and net.Pipe.
- Benchmarks: provide scripts and a performance matrix for representative hardware and rate settings.

## Configuration & operational guidance

- Defaults: rate_limit tokens/sec 20, connect timeout 5s, read deadline 3s.
- Runtime: document ulimit -n recommendations per scan size; provide CLI flags for targets, ports, rate, and output.
- Example run: tcprecon --targets targets.txt --ports 22,80,443 --rate 50 --output ndjson > results.ndjson

## Security, legal & ethics

Scanning networks and hosts without authorization may be illegal or against provider policy. Maintain a clear acceptable‑use checklist, require authorization scope, and provide contact information for incidents. Make SNI injection and aggressive probing opt‑in and documented.

## Decision log & future work

- Keep a DECISIONS.md listing major design choices and links to PRs.
- Future work: resumable scans, distributed coordination, pluggable outputs, and advanced protocol heuristics (ALPN, HTTP/2 probing).
