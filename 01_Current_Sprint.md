# 01_Current_Sprint: Evaluation, Documentation & Offline Engineering

**Updated:** 2026-09-14
**Status:** ACTIVE
**Active branch:** `main` (Preparing offline feature branches)
**Current workstream:** Phase E complete — Transitioning to Phase F (Offline App Probes & Final Release)

## Sprint Goal
Execute offline engineering for stateless UDP reconnaissance and bounded Layer 7 banner parsing without relying on the lab server. Finalize project documentation and evaluation benchmarks.

---

## Verified Starting Baseline

### Phase E: OpenSearch Analytics & Dashboards
**Status:** COMPLETE (Ready for merge to `main`)

Verified work includes:
- Registered index template `tcprecon-alerts` (order 10) enforcing Doc Values on keywords and integers.
- Pinned JVM heap (-Xms2g -Xmx2g) and strictly enforced `size: 0` on all analytics queries.
- Registered three distinct visual lenses: Exposure Lifecycles (Stacked), Risk Distribution (Histogram), and Cryptographic Findings (Data Table).
- Assembled and registered `tcprecon-attack-surface-overview` master dashboard.

---

## Immediate Next Actions (Phase F / Offline Engineering)
1. **Advanced Layer 7 Banner Parsers:** Implement non-blocking extraction for SSH version strings and HTTP headers locally using `net.Pipe()`.
2. **Stateless UDP Probes:** Implement payload dispatching for DNS (port 53) and NTP (port 123) against local mocked listeners.
3. **YAML Asset Inventory:** Expand `internal/enrichment` to support strict YAML loading alongside JSON.
4. **Final Freeze:** Finalize benchmark execution and freeze all documentation.
