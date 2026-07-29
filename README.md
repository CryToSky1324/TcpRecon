# TcpRecon

TcpRecon is a Go-based network attack-surface monitoring project for authorized environments. It combines controlled TCP and selected UDP probing, application and TLS metadata collection, persistent state comparison, NDJSON telemetry, and planned Wazuh/OpenSearch integration.

The project is intentionally scoped as a reproducible security-engineering platform, not a replacement for mature scanners such as Nmap or enterprise vulnerability-management products. Its value is the complete pipeline from observation to state change, detection, analysis, and remediation evidence.

> **Project status:** active development. Core scanning, structured output, state storage, containerization, and orchestration foundations exist. CLI correctness, lifecycle reconciliation, reproducible Wazuh deployment, and risk analytics are being hardened before a stable release.

## Why this project exists

TcpRecon demonstrates how raw network observations can become useful security telemetry:

```text
authorized target scope
        ↓
streamed target parsing
        ↓
bounded TCP and UDP worker pools
        ↓
HTTP, TLS, and protocol metadata
        ↓
single-writer state comparison
        ↓
atomic NDJSON events
        ↓
Wazuh detection and OpenSearch analytics
```

## Current capabilities

| Area | Status | Notes |
|---|---|---|
| TCP full-connect scanning | Implemented | Uses bounded Go worker pools and cancellable network operations. |
| Selected UDP probes | Implemented | Protocol-aware payloads for a limited set of services. |
| Rate limiting | Implemented | Controls probe starts independently from worker concurrency. |
| HTTP and TLS metadata | Implemented | Includes banner and certificate metadata where available. |
| Target streaming | Partially implemented | File, standard input, and remote-source support exist; large-range behavior is being hardened. |
| NDJSON output | Implemented | Machine-readable events on `stdout`; diagnostics belong on `stderr`. |
| Persistent state | Implemented, incomplete lifecycle | bbolt and xxHash suppress unchanged observations; complete opened/closed/reopened reconciliation is in progress. |
| Container image | Implemented | Multi-stage static build with a minimal unprivileged runtime. |
| Kubernetes CronJob | Implemented | Uses persistent storage and non-overlapping execution. |
| Wazuh integration | Rebuild in progress | Configuration is being converted from host-local changes into version-controlled deployment assets. |
| Explainable risk and remediation analytics | Planned | Depends on complete lifecycle tracking and asset context. |

## Repository layout

The exact tree may evolve, but the project is organized around these responsibilities:

```text
cmd/tcprecon/              CLI entry point
internal/                  scanner, protocol, state, and event packages
deployments/               container, Kubernetes, and Wazuh assets
docs/                      architecture, schema, roadmap, and operations
.github/workflows/         CI and release automation
```

## Build from source

### Requirements

- The Go version declared in [`go.mod`](./go.mod)
- Git
- Linux, macOS, or Windows through WSL for the best-tested environment

```bash
git clone https://github.com/CryToSky1324/TcpRecon.git
cd TcpRecon

go mod download
go build -o tcprecon ./cmd/tcprecon
./tcprecon -h
```

Use the binary's `-h` output as the source of truth for currently implemented flags. The CLI is being normalized, so documentation should not pretend flags are stable before the code agrees. Revolutionary concept, apparently.

## Safe local example

Run TcpRecon only against systems you own or are explicitly authorized to assess.

```bash
./tcprecon -p 22,80,443 -w 50 -r 50 127.0.0.1
```

For a list of lab targets:

```bash
./tcprecon -p 22,80,443 -iL targets.txt
```

Separate events from diagnostics:

```bash
./tcprecon -j -p 22,80,443 127.0.0.1 \
  > events.ndjson \
  2> diagnostics.log
```

Validate the event stream:

```bash
jq -c . < events.ndjson
```

## Output contract

TcpRecon follows a strict stream contract:

- `stdout`: NDJSON security events only
- `stderr`: diagnostics, progress, warnings, and internal errors

Each line on `stdout` represents one observation or lifecycle event. Aggregate documents containing arrays of ports are deliberately avoided because atomic events are easier to validate, ingest, correlate, and replay.

A simplified event shape is documented in [`docs/EVENT_SCHEMA.md`](./docs/EVENT_SCHEMA.md).

## Stateful monitoring

TcpRecon uses bbolt as an embedded state store and xxHash for fast comparison of normalized service observations. A dedicated state-manager goroutine owns database writes, preventing network workers from fighting over disk locks like humans around the final charging socket.

The target lifecycle model is:

- `service.opened`
- `service.changed`
- `service.closed`
- `service.reopened`

Only a successfully completed scan may replace a committed baseline. Cancelled or partial scans must never create false closure events.

## Deployment

The project supports a minimal static container and scheduled Kubernetes execution. Persistent bbolt storage requires:

- a writable mounted data directory;
- a single active writer;
- non-overlapping CronJob runs;
- a stable database path such as `DB_PATH=/data/tcprecon.db`.

Wazuh deployment assets will live under `deployments/wazuh/` so the integration can be rebuilt from Git rather than from somebody's fading memory of commands typed at 2 a.m.

## Development checks

Run these before opening a pull request:

```bash
gofmt -w .
git diff --exit-code
go vet ./...
go test ./...
go test -race ./...
go build ./cmd/tcprecon
```

Tests should use loopback listeners, temporary files, and Go test servers. Automated tests must not scan public hosts.

## Documentation

- [`ARCHITECTURE.md`](./ARCHITECTURE.md): system boundaries, data flow, state model, deployment, and design decisions
- [`docs/EVENT_SCHEMA.md`](./docs/EVENT_SCHEMA.md): versioned NDJSON contract and lifecycle semantics
- [`docs/ROADMAP.md`](./docs/ROADMAP.md): current delivery phases and completion gates
- [`SECURITY.md`](./SECURITY.md): authorized-use policy and vulnerability reporting

## Limitations

- The scanner is not a vulnerability scanner and does not prove exploitability.
- A timeout does not always prove that a port is filtered.
- UDP state classification is inherently less certain than TCP full-connect results.
- IPv6 and very large CIDR behavior must be verified against the current implementation.
- Stateful closure detection is not trustworthy until full-scan reconciliation is complete.
- Performance claims require published, reproducible benchmarks. None are implied merely because Go contains goroutines.

## Legal and ethical use

Use TcpRecon only on infrastructure you own or have explicit permission to test. Rate limiting is for reliability, resource protection, and controlled assessment. It is not marketed as an evasion or stealth feature.

## License

See the repository license file for applicable terms.
