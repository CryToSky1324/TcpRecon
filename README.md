# TcpRecon

TcpRecon is a Go-based network attack-surface monitoring project for authorized environments. It combines controlled TCP and selected UDP probing, application and TLS metadata collection, versioned lifecycle state, and planned NDJSON/Wazuh/OpenSearch integration.

The project is intentionally scoped as a reproducible security-engineering platform, not a replacement for mature scanners such as Nmap or enterprise vulnerability-management products. Its value is the complete pipeline from observation to state change, detection, analysis, and remediation evidence.

> **Project status:** active development. Core scanning and schema-v1 lifecycle reconciliation are runtime-active. Lifecycle-event output is deferred to B7, so the current CLI intentionally emits no stdout records.

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
scope-partitioned lifecycle reconciliation
        ↓
versioned lifecycle events (B7)
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
| NDJSON output | Pending B7 | Stdout is intentionally empty in both output modes; diagnostics remain on `stderr`. |
| Persistent state | Implemented | Schema-v1 bbolt state supports scoped opened/changed/closed/reopened reconciliation and successful-scan-only atomic promotion. |
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

IPv6 and CIDR targets are also accepted directly:

```bash
./tcprecon -p 22,80,443 ::1
./tcprecon -p 22,80,443 127.0.0.0/30
```

Target lists may also come from stdin or an HTTP(S) URL:

```bash
printf '127.0.0.1\n::1\n' | ./tcprecon -p 22,80,443
./tcprecon -p 22,80,443 https://example.internal/authorized-targets.txt
```

Choose one explicit input source: a positional target/URL or `-iL`. If neither
is supplied, piped stdin is used before the `TARGET_URL` environment fallback.

Capture the current output streams:

```bash
./tcprecon -j -p 22,80,443 127.0.0.1 \
  > events.ndjson \
  2> diagnostics.log
```

During the B6-only checkpoint, `events.ndjson` is intentionally empty. Event-stream validation applies after B7 enables serialization:

```bash
jq -c . < events.ndjson
```

## Output contract

TcpRecon currently follows this temporary B6 stream contract:

- `stdout`: intentionally empty until B7
- `stderr`: diagnostics, progress, warnings, and internal errors

The legacy `port_state_delta` output is retired and raw scan observations are not emitted as a replacement. B7 will define and activate versioned lifecycle-event serialization.

A simplified event shape is documented in [`docs/EVENT_SCHEMA.md`](./docs/EVENT_SCHEMA.md).

## Stateful monitoring

TcpRecon uses bbolt schema v1 as an embedded lifecycle store. State is partitioned by canonical `scope_id`, with temporary observations owned by a unique `scan_id` and committed records keyed by stable `service_key`.

The target lifecycle model is:

- `service.opened`
- `service.changed`
- `service.closed`
- `service.reopened`

Only a successfully completed scan may replace a committed baseline. Cancelled or partial scans must never create false closure events.

Existing unversioned databases, including legacy databases containing `PortStates`, are refused rather than silently reinterpreted. Use a fresh database path or perform an explicitly designed migration when one becomes available.

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
- Very large CIDRs expand in memory and should be avoided.
- Lifecycle changes are reconciled and committed internally, but are not emitted until B7.
- Orphan temporary scans remain isolated and unpromotable but may consume storage until the B6-M1 cleanup policy is implemented.
- Performance claims require published, reproducible benchmarks. None are implied merely because Go contains goroutines.

## Legal and ethical use

Use TcpRecon only on infrastructure you own or have explicit permission to test. Rate limiting is for reliability, resource protection, and controlled assessment. It is not marketed as an evasion or stealth feature.

## License

See the repository license file for applicable terms.
