# Changelog

All notable changes to Threatscope are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/); versioning follows [SemVer](https://semver.org/).

## [Unreleased] — v0.1.0 pre-release line

### Added
- Real-time log ingestion with a bounded pub/sub bus, ML anomaly detection
  (Isolation Forest + DNS exfiltration classifier), and deterministic rule
  evaluation.
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

### Fixed
- Broke the `ml`/`api` circular import so `tests/unit` collects standalone.
