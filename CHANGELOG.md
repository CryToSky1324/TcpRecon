# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- RFC 1035 DNS A-record query encoder and response gatekeeper for port 53.
- RFC 5905 NTPv4 client request encoder and server response gatekeeper for port 123.
- Ephemeral correlation IDs for concurrent UDP worker dispatches.
- Allocation and throughput benchmarks for hot-path binary packet validation.

### Changed
- `UDPWorker` now enforces a fixed 2048-byte allocation per read cycle.
- Replaced naive read-byte checks with protocol-specific validation gatekeepers.
- Unified static UDP payload map with dynamic builder constructors.
