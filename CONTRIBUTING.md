# Contributing to ThreatScope

Thanks for your interest. ThreatScope is a security tool — contributions should reflect that posture. This document covers how to set up a development environment, what's expected in PRs, and how releases are produced.

## Quick start

```bash
# Backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 -m api.main --demo --debug

# Frontend (separate terminal)
cd frontend && npm ci && npm run dev

# Desktop (Tauri)
cd frontend && npm run tauri dev
```

The frontend dev server proxies to the API at `http://127.0.0.1:8000`.

## Project layout

| Path | Purpose |
|------|---------|
| [agent/](agent/) | Log collection, parsing, async event bus |
| [api/](api/) | FastAPI REST + WebSocket layer, route handlers, auth/rate-limit middleware |
| [ml/](ml/) | Detection pipeline, ML models (login / network / DNS), rule engine, threat narrator |
| [frontend/](frontend/) | React 19 + TypeScript + Vite dashboard |
| [frontend/src-tauri/](frontend/src-tauri/) | Tauri 2.x desktop wrapper (Rust) |
| [tests/](tests/) | pytest — `unit/`, `integration/`, `security/` |
| [scripts/](scripts/) | Demo data generator and other one-shot utilities |
| [.github/workflows/](.github/workflows/) | CI and release pipelines |

For deeper architectural context, see the main [README](README.md) and [prd-threatscope.md](prd-threatscope.md).

## Branch and commit conventions

- Work on a feature branch off `main` (e.g. `feat/dns-classifier-tuning`, `fix/ws-keepalive-leak`).
- Commit messages: short imperative subject (≤72 chars). Body explains the *why* — the diff shows the *what*.
- Squash noisy WIP commits before opening a PR.
- Never push directly to `main`. Open a PR.

## Coding standards

### Python
- Format and lint with `ruff` — `ruff check .` must pass before opening a PR.
- Type-check with `mypy --strict` over `agent/`, `ml/`, `api/`. `mypy` is enforced in CI.
- Imports stay at the top of the file (E402 will fail CI).
- Prefer `from __future__ import annotations` so type hints stay cheap to evaluate.
- Use `pydantic` models at API boundaries; use frozen dataclasses for internal value objects (e.g. `NormalizedEvent`).

### TypeScript / React
- Strict mode is on (`tsconfig.app.json`). Don't add `any` to make types pass.
- Components live in [frontend/src/components/](frontend/src/components/), hooks in [frontend/src/hooks/](frontend/src/hooks/), API client in [frontend/src/lib/](frontend/src/lib/).
- Auto-reconnect logic lives in `useWebSocket` — extend that hook rather than re-implementing per-component.
- Never use `dangerouslySetInnerHTML` for user-facing log content. Raw event fields are rendered as text.

### Rust (Tauri shell)
- Keep [frontend/src-tauri/src/main.rs](frontend/src-tauri/src/main.rs) thin — system tray, window, and IPC handlers only. All business logic stays on the Python side.
- `cargo clippy --all-targets -- -D warnings` should pass before merging Tauri changes.

### Tests
- Run `pytest tests/ -v` before opening a PR.
- New API endpoints need at least one test in [tests/integration/](tests/integration/).
- New detectors (ML or rule-based) need unit tests covering: trigger threshold, no-trigger baseline, edge cases (empty input, single event, malformed input).
- Security-relevant changes (auth, rate limiting, input validation) need a test in [tests/security/](tests/security/).
- Don't mock the SQLite layer in integration tests — use the in-memory fixtures in [tests/conftest.py](tests/conftest.py).

## Pull requests

1. Open a draft PR early if you want feedback on direction.
2. Fill out the PR template — the **Test plan** and **Security impact** sections matter most.
3. CI must be green: ruff, mypy strict, pytest (Python 3.11/3.12/3.13), TypeScript type-check, frontend build.
4. Keep PRs scoped — a 600-line PR touching three subsystems is harder to review than three 200-line PRs.
5. UI changes need a screenshot or short clip in the description.
6. Detector changes (rule thresholds, ML hyperparameters, feature additions) should include the empirical evidence behind the choice — false-positive rate on demo data, ROC curve, etc.

## Releases

**Releases are production. Do not push tags casually.**

- Releases are produced by [.github/workflows/release.yml](.github/workflows/release.yml), triggered by pushing a tag matching `v*`.
- The release job builds Linux (`.AppImage` / `.deb`), macOS (`.dmg`), and Windows (`.msi` / NSIS `.exe`) artifacts via Tauri and creates a GitHub Draft Release.
- The maintainer reviews the draft, verifies the artifacts boot, then publishes.
- Contributors should not push tags directly. If your change is release-worthy, mention it in the PR description.
- `workflow_dispatch` produces artifacts but does **not** publish a release until a tag is pushed.

## Reporting bugs and requesting features

Use the issue templates at [.github/ISSUE_TEMPLATE/](.github/ISSUE_TEMPLATE/). Bug reports without reproduction steps may be closed without comment.

## Security

**Vulnerabilities must be reported privately per [SECURITY.md](SECURITY.md), never as public issues or PRs.** This is doubly important for a security tool — a public PR that lands a fix is also a disclosure.
