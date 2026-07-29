# TcpRecon Delivery Roadmap

## Current objective

Re-establish a supported Wazuh lab, correct the scanner baseline, and complete reliable service lifecycle detection before adding risk scoring and dashboards.

## Phase 0: Wazuh lab rebuild

- Install and validate Ubuntu Server 24.04 LTS.
- Validate manager, indexer, dashboard, and Filebeat independently.
- Record versions and resource usage.
- Keep previous host-local customization out of the clean baseline.

**Gate:** all core services run without red cluster health or OOM kills.

## Phase A: Repository correctness

- Normalize positional, file, stdin, URL, and environment input modes.
- Validate workers, timeouts, rates, ports, and conflicting inputs.
- Guarantee NDJSON-only stdout and diagnostic-only stderr.
- Add parser, protocol, cancellation, and stream-separation tests.
- Align README commands with actual `-h` output.
- Remove tracked binaries and local databases.

**Gate:** build, vet, unit tests, race tests, and documented examples pass.

## Phase B: Lifecycle reconciliation

- Version the event and bbolt schemas.
- Define stable scan-scope and finding identifiers.
- Store temporary current-scan observations separately.
- Commit baselines atomically only after complete scans.
- Emit opened, changed, closed, and reopened events.
- Preserve lifecycle timestamps and remediation duration.

**Gate:** incomplete scans produce no false closures and state survives restart.

## Phase C: Context and explainable risk

- Capture TLS version, cipher, validity, and verification status.
- Add a local asset inventory with exact-IP and CIDR matching.
- Implement deterministic versioned risk policy.
- Emit reason codes, points, and explanations.

**Gate:** identical inputs always produce the same score and reasons.

## Phase D: Reproducible Wazuh integration

- Commit localfile configuration, rules, fixtures, and install scripts.
- Test every fixture with `wazuh-logtest`.
- Validate live alerts before adding external notification integrations.

**Gate:** a clean host can reproduce ingestion and detection from Git.

## Phase E: OpenSearch mappings and dashboards

- Add explicit mappings for IP, numeric, date, and keyword fields.
- Build exposure, lifecycle, risk, TLS, and remediation views.
- Export and version dashboard saved objects.

**Gate:** dashboard import is repeatable and aggregations work without FieldData hacks.

## Phase F: Evaluation and release

- Run the full opened → changed → closed → reopened lab scenario.
- Record correctness, memory, scan duration, deduplication, and ingestion latency.
- Publish known limitations and reproducible benchmark methodology.
- Tag the first stable schema and release.

## Deferred work

Distributed scanning, Kafka connectors, broad vulnerability detection, and elaborate dashboards remain deferred until the scanner-to-Wazuh vertical slice is proven.
