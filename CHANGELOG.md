# Changelog

All notable changes to Threatscope are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## [0.1.0] — 2026-07-19

First tagged release: single-node mini-SIEM with live ingestion,
detection, and dashboard, verified end to end in demo mode.

### Added
- Dashboard screenshots from a live demo-mode run, embedded in the README
  (`docs/screenshots/`).
- Real-time log ingestion with a bounded pub/sub bus, ML anomaly detection
  (Isolation Forest + DNS exfiltration classifier), and deterministic rule
  evaluation.
- dnsmasq DNS query-log parser (`agent/parsers/dns.py`): handles both
  syslog-routed and direct `log-facility` line shapes, emits `dns_query`
  events with domain/record-type/client metadata that feed the DNS
  tunneling/DGA classifier. Closes the gap where DNS was advertised as a
  data source but only demo data ever reached the classifier.
- Server-side ingestion wiring: the FastAPI lifespan now starts the file
  tailer over configurable log sources (`THREATSCOPE_LOG_SOURCES`, with
  filename-based parser routing) and a new event persister batch-writes
  every bus event to SQLite — tailed logs are now searchable via the API
  and visible on the dashboard, not just streamed to WebSocket clients.
- Demo mode replays a live attack burst (SSH brute force + tunneling/DGA
  DNS queries) through the event bus at startup, so the rule engine and
  DNS classifier fire real alerts.
- React dashboard: live WebSocket event feed, alerts table with one-click
  acknowledge, top-sources chart.
- JWT authentication and per-IP rate limiting, with a security regression
  test suite under `tests/security/` (auth, auth-disabled mode, rate
  limiting, WebSocket auth).

### Changed
- README security claims aligned with the actual implementation; Makefile
  fixed; unused dependency dropped.
- mypy now targets Python 3.12 (numpy 2.4+ stubs use PEP 695 `type`
  statements that a 3.11 target refuses to parse).
- Pruned unused dependencies from `requirements.txt` (sqlalchemy,
  aiosqlite, pandas, aiofiles) — none were imported anywhere.
- Test suite grew from 111 to 141 tests (DNS parser, parser routing,
  persistence, full-text search, demo replay contracts, config, stats
  time-window regression).

### Fixed
- Dashboard stats time windows (`events_last_hour`, 7-day heatmap) were
  computed with SQLite's `datetime('now')`, which is UTC and
  space-separated — comparing it against the stored naive-local ISO
  'T'-format timestamps both undercounted on non-UTC hosts and
  string-compared wrongly. Cutoffs are now built in Python in the same
  format as the stored timestamps.
- Full-text search: the fts5 external-content index was never populated
  (no sync triggers), so every `q=` search silently returned nothing.
  Added insert/update/delete triggers plus a guarded rebuild for
  databases created before the fix; malformed MATCH expressions now
  return `400` instead of an unhandled `500`.
- Broke the `ml`/`api` circular import so `tests/unit` collects standalone.

### Known limitations
- No prebuilt desktop binaries: the Tauri bundle declares the Python API
  as a sidecar (`externalBin`) but no pipeline step packages it yet, so
  the tag-triggered desktop builds fail at the bundling stage. v0.1.0 is
  a source release; run from source via `make dev` / `make demo`.
