# TcpRecon Event Schema

## Status

This document defines the target versioned NDJSON contract. Fields marked as required should remain stable once schema version `1.0.0` is released.

## Transport

- Encoding: UTF-8 JSON
- Framing: one complete JSON object per line
- Stream: events on `stdout`; diagnostics on `stderr`
- Timestamp format: RFC 3339 in UTC

## Example

{
  "schema_version": "1.0",
  "event_id": "019ad1be-example",
  "scan_id": "scan-example",
  "scope_id": "scope-example",
  "timestamp": "2026-07-29T07:00:00Z",
  "event_type": "service.opened",
  "scanner": {
    "name": "tcprecon",
    "version": "1.0.0"
  },
  "asset": {
    "ip": "172.20.0.10",
    "hostname": "lab-web.local",
    "environment": "production",
    "criticality": "tier-0",
    "owner": "secops"
  },
  "network": {
    "protocol": "tcp",
    "port": 443,
    "state": "open"
  },
  "change": {
    "type": "new_service",
    "previous_state": "closed"
  },
  "risk": {
    "policy_version": "1.0",
    "score": 50,
    "severity": "medium",
    "reasons": "deprecated_tls,critical_asset_tier0"
  }
}

## Event types

| Event type | Meaning |
|---|---|
| `service.opened` | Service exists in the completed current scan but not the committed previous baseline. |
| `service.changed` | Service exists in both baselines but its stable normalized observation changed. |
| `service.closed` | Service existed previously but is absent from a successfully completed current scan. |
| `service.reopened` | A previously resolved finding is observed again. |

## Required invariants

- `schema_version` is present on every event.
- `event_id` is unique.
- `scan_id` identifies one execution.
- `scope_id` is stable for the same normalized targets, ports, and protocols.
- `network.protocol`, `asset.ip`, and `network.port` jointly identify the network service.
- `service.closed` is emitted only after a complete scan.
- **Zero-Nested-Arrays Invariant:** The event envelope stringently forbids nested arrays/slices to maintain compatibility with Wazuh's `analysisd` JSON decoder[cite: 22]. Context lists (e.g., `risk.reasons`) must be formatted as comma-delimited scalar strings.

## Compatibility rules

- Adding optional fields is backward compatible.
- Renaming or deleting a field requires a schema-version change.
- Changing a field type requires a schema-version change.
- Reusing an event type with different semantics is prohibited.
- Internal Go struct names do not define the external contract.
