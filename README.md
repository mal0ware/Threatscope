# ThreatScope

[![CI](https://github.com/mal0ware/Threatscope/actions/workflows/ci.yml/badge.svg)](https://github.com/mal0ware/Threatscope/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178c6.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Real-time threat intelligence platform that ingests system logs, runs ML-based anomaly detection and deterministic rule evaluation, and surfaces security events through a live dashboard with WebSocket push.

Built to solve the visibility gap for environments that need more than raw log files but can't justify enterprise SIEM pricing. Runs entirely offline with zero external dependencies or API keys required.

---

## Table of Contents

- [Architecture](#architecture)
- [Detection Capabilities](#detection-capabilities)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Testing](#testing)
- [Security Posture](#security-posture)
- [Project Structure](#project-structure)
- [Desktop App](#desktop-app)
- [CI/CD](#cicd)
- [License](#license)

---

## Architecture

```
                        ┌──────────────────────────┐
                        │      Data Sources         │
                        │  auth.log  syslog  DNS    │
                        └────────────┬─────────────┘
                                     │
                    ┌────────────────▼────────────────┐
                    │       Log Collection Agent       │
                    │  Watchdog file tailer with       │
                    │  inode-aware rotation handling   │
                    └────────────────┬────────────────┘
                                     │ NormalizedEvent
                    ┌────────────────▼────────────────┐
                    │     Async Event Bus (pub-sub)    │
                    │  Bounded ring buffer (10K cap)   │
                    │  Back-pressure on slow consumers │
                    └──┬─────────────┬──────────────┬─┘
                       │             │              │
              ┌────────▼──┐  ┌──────▼──────┐  ┌───▼────────┐
              │ Rule Engine│  │ ML Pipeline │  │ Subscribers│
              │ Sliding    │  │ Login IF    │  │ SSE / WS   │
              │ windows,   │  │ Network Z+IF│  │ clients    │
              │ thresholds │  │ DNS RF+heur │  │            │
              └────────┬───┘  └──────┬──────┘  └────────────┘
                       │             │
                       ▼             ▼
              ┌──────────────────────────────────────┐
              │         SQLite + FTS5 (WAL)          │
              │  Events  Alerts  Rules  Full-text    │
              └──────────────────┬───────────────────┘
                                 │
              ┌──────────────────▼───────────────────┐
              │          FastAPI REST + WS            │
              │  /api/v1/events  /alerts  /stats     │
              │  /ws/events  /api/v1/events/stream   │
              └──────────────────┬───────────────────┘
                                 │
              ┌──────────────────▼───────────────────┐
              │       React Dashboard (Vite)         │
              │  Timeline  Heatmap  Network Graph    │
              │  Live Feed  Alerts  Top Sources      │
              └──────────────────────────────────────┘
```

**Data flow:** Log files are tailed in real time by a watchdog-based collector that detects log rotation via inode tracking. Each line is routed to the appropriate parser (auth, syslog) which emits a `NormalizedEvent` frozen dataclass. Events are published to an in-memory async event bus backed by a bounded ring buffer. Downstream subscribers (ML pipeline, rule engine, WebSocket/SSE clients) consume events concurrently. Detections generate alerts persisted to SQLite. The FastAPI layer exposes REST endpoints with full-text search (FTS5) and real-time push via WebSocket.

---

## Detection Capabilities

### ML-Based Detectors

| Detector | Model | How It Works |
|----------|-------|-------------|
| **Login Anomaly** | Isolation Forest | Extracts temporal and behavioral features from auth events (hour-of-day, day-of-week, IP frequency, success/failure ratio). Trains on a rolling 30-day baseline. Anomaly scores normalized to `[0.0, 1.0]`. |
| **Network Traffic** | Z-score + Isolation Forest | Maintains a rolling baseline of traffic snapshots (bytes in/out, packet counts, unique IPs, port entropy). Per-feature Z-scores flag individual spikes; Isolation Forest catches multi-dimensional anomalies the Z-scores miss. |
| **DNS Classification** | Random Forest + Heuristics | Feature vector includes Shannon entropy, label length, digit ratio, consonant ratio, hex pattern density, and dot count. Classifies queries as `NORMAL`, `TUNNELING`, or `DGA`. Heuristic fallback ensures detection works without training data. |

### Rule-Based Detectors

| Rule | Trigger Condition | Severity |
|------|-------------------|----------|
| `BRUTE_001` | >10 SSH failures from same IP within 5 minutes | High |
| `PRIV_001` | sudo failure followed by sudo success from same user within 3 minutes | Critical |
| `SCAN_001` | >50 unique destination ports from same IP within 1 minute | Medium |
| `EXFIL_001` | Outbound transfer volume >3 standard deviations above baseline | High |

Rules use sliding time windows with per-key grouping (source IP, username) and automatic window reset after trigger.

---

## Tech Stack

| Layer | Technology | Why |
|-------|-----------|-----|
| **Backend** | Python 3.11+, FastAPI, uvicorn | Async-native, high throughput, type-safe with `from __future__ import annotations` |
| **Storage** | SQLite with WAL mode, FTS5 | Zero-config, ACID-compliant, full-text search on event fields without an external search engine |
| **ML** | scikit-learn, NumPy | Industry-standard implementations of Isolation Forest and Random Forest |
| **Event Bus** | asyncio Queue + deque ring buffer | Lock-free pub-sub with bounded memory, back-pressure for slow consumers |
| **Frontend** | React 19, TypeScript (strict), Vite, Tailwind CSS | Type-safe components, sub-second HMR, utility-first styling |
| **Visualization** | Recharts, D3.js (force layout) | Recharts for time-series/bar charts, D3 for the interactive network topology graph |
| **Desktop** | Tauri 2.x (Rust) | ~10MB binary vs Electron's ~150MB, native system tray and notifications |
| **CI/CD** | GitHub Actions | Python 3.11/3.12/3.13 matrix, frontend type-check + build, cross-platform Tauri releases |
| **Quality** | ruff, mypy (strict), pytest, ESLint | Lint + type-check enforced in CI; 77 tests across unit, integration, and security suites |

---

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 22+
- (Optional) Rust toolchain for Tauri desktop builds

### Backend

```bash
# Clone and set up
git clone https://github.com/mal0ware/Threatscope.git
cd Threatscope

# Create virtual environment and install dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start the server with demo data
python3 -m api.main --demo
```

The `--demo` flag seeds ~400 synthetic events on startup (brute force attacks, port scans, DNS queries, baseline traffic) so the dashboard has data to display immediately.

### Frontend

```bash
cd frontend
npm ci
npm run dev
```

Open `http://localhost:5173` — the dashboard connects to the API at `http://127.0.0.1:8000` and begins streaming events in real time.

---

## Usage

### Server Options

```bash
python3 -m api.main [OPTIONS]

  --demo     Seed synthetic attack data on startup
  --debug    Enable debug logging and Swagger docs at /docs
  --host     Bind address (default: 127.0.0.1)
  --port     Bind port (default: 8000)
```

### Dashboard Widgets

| Widget | Description |
|--------|------------|
| **Stats Cards** | Total events, last-hour count, open alerts, critical alert count |
| **Threat Timeline** | Stacked area chart of events bucketed by severity over time |
| **Activity Heatmap** | 24-hour x 7-day grid with color intensity mapped to event volume |
| **Network Map** | Force-directed graph of IP communication — blue nodes are internal, red are external |
| **Live Feed** | Real-time WebSocket event stream with connection status indicator |
| **Alerts Table** | Active alerts with one-click acknowledge and expandable threat narratives |
| **Top Sources** | Horizontal bar chart of the most active source IPs |

---

## API Reference

All endpoints are prefixed with `/api/v1`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/events/search` | Search events with filters, FTS5 full-text search, pagination |
| `GET` | `/api/v1/events/stream` | SSE stream of real-time events |
| `GET` | `/api/v1/events/{id}` | Retrieve a single event by ID |
| `GET` | `/api/v1/alerts` | List alerts with severity/status filters |
| `POST` | `/api/v1/alerts/{id}/ack` | Acknowledge an alert |
| `GET` | `/api/v1/stats/overview` | Dashboard summary statistics |
| `GET` | `/api/v1/stats/heatmap` | 24h x 7d activity heatmap data |
| `GET` | `/api/v1/anomalies` | List anomalies by minimum score |
| `GET` | `/api/v1/anomalies/{id}/narrative` | Get threat narrative for an alert |
| `WS` | `/ws/events` | WebSocket push for real-time events (50 connection limit, keepalive pings) |
| `GET` | `/health` | Health check |

**Search parameters:** `q` (FTS5 query), `severity`, `source`, `event_type`, `source_ip`, `start`/`end` (ISO 8601), `sort`, `order`, `limit`, `offset`.

When `--debug` is enabled, interactive API docs are available at `/docs`.

---

## Testing

```bash
# Run the full suite
pytest tests/ -v

# Run by category
pytest tests/unit/ -v          # 64 unit tests
pytest tests/integration/ -v   # 13 integration tests

# Linting and type checking
ruff check .
mypy agent/ ml/ api/ --ignore-missing-imports

# Frontend
cd frontend
npx tsc --noEmit    # type check
npm run build       # production build
```

**77 tests** covering:
- Parser correctness (auth log, syslog, edge cases, immutability)
- Event bus pub-sub (subscribe, unsubscribe, ring buffer eviction, slow consumers)
- ML models (Isolation Forest training/scoring, DNS feature extraction, Z-score flagging)
- Rule engine (threshold triggers, per-key grouping, window resets, alert generation)
- Threat narrator (template rendering, fallback behavior)
- API integration (search, filtering, pagination, error handling, stats)
- File tailer (event publishing, existing content skip, missing source handling)

---

## Security Posture

This is a security tool — its own attack surface is hardened accordingly.

| Concern | Mitigation |
|---------|-----------|
| **SQL Injection** | All database queries use parameterized placeholders. Zero string interpolation in SQL. |
| **Input Validation** | Regex-validated event IDs, allowlisted enum values for severity/source/sort, `Query` constraints on all parameters. |
| **XSS** | React's JSX escaping by default. Raw log content rendered as text, never `dangerouslySetInnerHTML`. |
| **Rate Limiting** | Configurable per-IP rate limits. WebSocket hard-capped at 50 concurrent connections. |
| **CORS** | Restricted to configured dashboard origin. No wildcard origins in production. |
| **Auth** | JWT-based with session expiry and scoped tokens. |
| **Resource Exhaustion** | Bounded event bus ring buffer (10K). Slow WebSocket consumers are dropped, not buffered indefinitely. |
| **File Access** | Log tailer only reads explicitly registered paths. No user-controlled file reads. |
| **Static Analysis** | ruff `S` rules (Bandit) enabled in CI — catches hardcoded secrets, insecure function usage, and common vulnerability patterns. |

---

## Project Structure

```
threatscope/
├── agent/                    # Log collection and parsing
│   ├── config.py             # Centralized settings (frozen dataclass, env var overrides)
│   ├── event_bus.py          # Async pub-sub with bounded ring buffer
│   ├── collectors/
│   │   └── file_tailer.py    # Watchdog-based tailer with inode rotation detection
│   └── parsers/
│       ├── base.py           # NormalizedEvent schema, LogParser ABC
│       ├── auth.py           # SSH auth log parser (failed/success/brute/sudo)
│       └── syslog.py         # RFC 3164 syslog parser
├── api/                      # FastAPI REST API
│   ├── main.py               # App factory, lifespan management, CLI entrypoint
│   ├── routes/
│   │   ├── events.py         # Search, stream (SSE), single event retrieval
│   │   ├── alerts.py         # Alert listing and acknowledgment
│   │   ├── stats.py          # Overview stats and heatmap
│   │   ├── anomalies.py      # Anomaly listing and threat narratives
│   │   └── websocket.py      # WebSocket push with keepalive
│   ├── middleware/            # Auth, rate limiting
│   └── models/
│       └── database.py       # SQLite manager (WAL, FTS5, CHECK constraints)
├── ml/                       # Detection pipeline
│   ├── pipeline.py           # Orchestrator — subscribes to bus, runs all detectors
│   ├── narrator.py           # Threat narrative generation (template + optional API)
│   ├── dns_analysis.py       # Shannon entropy, structural DNS analysis
│   ├── models/
│   │   ├── login_anomaly.py  # Isolation Forest for auth behavior
│   │   ├── network_anomaly.py # Z-score + IF hybrid for traffic patterns
│   │   └── dns_classifier.py # Random Forest + heuristic DNS classification
│   └── rules/
│       ├── detection.py      # Rule definitions (frozen dataclasses)
│       └── engine.py         # Sliding-window evaluation engine
├── frontend/                 # React + TypeScript dashboard
│   ├── src/
│   │   ├── App.tsx           # Dashboard layout
│   │   ├── components/       # StatsCards, Timeline, Heatmap, NetworkMap, etc.
│   │   ├── hooks/            # useAPI, useWebSocket (auto-reconnect)
│   │   └── lib/              # API client, TypeScript interfaces
│   └── src-tauri/            # Tauri v2 desktop wrapper (Rust)
│       └── src/main.rs       # System tray, native menu, window management
├── scripts/
│   └── generate_demo_data.py # Synthetic event seeder (brute force, port scan, baseline)
├── tests/
│   ├── unit/                 # Parser, ML model, rule engine, event bus tests
│   ├── integration/          # API endpoint and file tailer tests
│   └── security/             # Security-focused test cases
├── .github/workflows/
│   ├── ci.yml                # Lint + type-check + test (Python 3.11-3.13 matrix)
│   └── release.yml           # Cross-platform Tauri desktop builds on tag push
├── pyproject.toml            # ruff, mypy strict, pytest config
└── requirements.txt          # Python dependencies
```

---

## Desktop App

ThreatScope ships as a native desktop application via [Tauri 2.x](https://v2.tauri.app/):

- System tray with quick-access menu (Show Dashboard / Quit)
- Native notification support for critical alerts
- ~10MB binary footprint (Rust + system WebView, no bundled Chromium)
- Cross-platform builds for macOS, Windows, and Linux via GitHub Actions

To build locally:

```bash
cd frontend
npm ci
npx tauri build
```

Requires Rust toolchain and platform-specific dependencies ([Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)).

---

## CI/CD

**Continuous Integration** runs on every push and PR to `main`:

- **Backend:** ruff lint, mypy strict type checking, pytest across Python 3.11, 3.12, and 3.13
- **Frontend:** TypeScript strict compilation, Vite production build

**Release** pipeline triggers on version tags (`v*`):

- Builds native desktop binaries for Linux, macOS, and Windows
- Creates a GitHub Draft Release with all platform artifacts

---

## License

[MIT](LICENSE)
