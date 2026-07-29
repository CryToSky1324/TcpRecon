# TcpRecon Event Schema

## Status

This document defines the target versioned NDJSON contract. Fields marked as required should remain stable once schema version `1.0.0` is released.

## Transport

- Encoding: UTF-8 JSON
- Framing: one complete JSON object per line
- Stream: events on `stdout`; diagnostics on `stderr`
- Timestamp format: RFC 3339 in UTC

## Example

```json
{
  "schema_version": "1.0.0",
  "event": {
    "id": "019ad1be-example",
    "type": "service.opened",
    "created": "2026-07-29T07:00:00Z"
  },
  "observer": {
    "name": "tcprecon",
    "version": "0.2.0"
  },
  "scan": {
    "id": "scan-example",
    "scope_id": "scope-example",
    "complete": true
  },
  "asset": {
    "name": "lab-web",
    "ip": "172.20.0.10"
  },
  "service": {
    "finding_id": "finding-example",
    "protocol": "tcp",
    "port": 443,
    "state": "open",
    "name": "https",
    "banner": "HTTP/1.1 200 OK",
    "tls": {
      "version": "TLS1.3",
      "cipher_suite": "TLS_AES_128_GCM_SHA256",
      "subject": "lab-web.local",
      "issuer": "Lab CA",
      "sans": ["lab-web.local"]
    }
  },
  "lifecycle": {
    "previous_state": "unknown",
    "current_state": "open",
    "first_seen": "2026-07-29T07:00:00Z",
    "last_seen": "2026-07-29T07:00:00Z",
    "resolved_at": null
  },
  "risk": {
    "policy_version": "unassigned",
    "score": 0,
    "severity": "informational",
    "reasons": []
  },
  "error": null
}
```

## Event types

| Event type | Meaning |
|---|---|
| `service.opened` | Service exists in the completed current scan but not the committed previous baseline. |
| `service.changed` | Service exists in both baselines but its stable normalized observation changed. |
| `service.closed` | Service existed previously but is absent from a successfully completed current scan. |
| `service.reopened` | A previously resolved finding is observed again. |
| `scan.failed` | Optional operational event for a scan that could not safely commit a baseline. |

## Required invariants

- `schema_version` is present on every event.
- `event.id` is unique.
- `scan.id` identifies one execution.
- `scan.scope_id` is stable for the same normalized targets, ports, and protocols.
- `service.finding_id` is stable across opened, changed, closed, and reopened events.
- `service.protocol`, `asset.ip`, and `service.port` jointly identify the network service.
- `service.closed` is emitted only after a complete scan.
- `error` is JSON `null` when no error exists.
- Newlines and control characters inside banners remain escaped within one JSON line.

## Compatibility rules

- Adding optional fields is backward compatible.
- Renaming or deleting a field requires a schema-version change.
- Changing a field type requires a schema-version change.
- Reusing an event type with different semantics is prohibited.
- Internal Go struct names do not define the external contract.

## Hash normalization

The comparison hash may include stable service fields but must exclude timestamps, latency, event identifiers, temporary errors, and execution settings. Hash format changes require state-schema migration or explicit database reset.
