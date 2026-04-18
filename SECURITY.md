# Security Policy

ThreatScope is a security-monitoring tool. Vulnerabilities in this codebase have outsized impact — a flaw in a SIEM-style product can blind operators to real attacks. We treat reports accordingly.

## Supported versions

Only the latest tagged release receives security fixes. Older releases are not patched — upgrade to the current `v*` tag on the [Releases page](https://github.com/mal0ware/Threatscope/releases).

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ |
| `main` branch | Best-effort |

## Reporting a vulnerability

**Do not open a public issue, PR, or discussion thread for security reports.** A public PR with a security fix is itself a disclosure.

Email **mal0ss.network@gmail.com** with the subject prefix `[ThreatScope SECURITY]` and include:

- A clear description of the vulnerability and its impact (what can an attacker do?)
- Affected version (commit hash or release tag)
- Steps to reproduce — proof-of-concept code, sample payloads, or a minimal log fixture that triggers the issue
- Whether the issue has been disclosed elsewhere (CVE, vendor advisory, public discussion)
- (Optional) Your preferred credit attribution for the eventual advisory

You can expect:

- An acknowledgement within **5 business days**
- A triage decision (accepted / needs more info / out of scope) within **14 days**
- A coordinated disclosure timeline once a fix is in flight — typically 30–90 days depending on severity
- A GitHub Security Advisory and CVE request (where applicable) when the patch ships

## Scope

### In scope

- The Python backend (under [agent/](agent/), [api/](api/), [ml/](ml/))
- The React + TypeScript frontend ([frontend/src/](frontend/src/))
- The Tauri desktop wrapper ([frontend/src-tauri/](frontend/src-tauri/))
- Build artifacts produced by [.github/workflows/release.yml](.github/workflows/release.yml)
- Default configuration files and example secrets handling

Specifically interesting threat models:

- **Log injection** — crafted log lines that bypass parsers, trigger ReDoS, or smuggle control characters into the dashboard
- **Detection-bypass** — payloads that evade the rule engine or ML detectors when they should be flagged
- **Authn/authz** — JWT handling, scope enforcement, session expiry edge cases
- **Resource exhaustion** — unbounded memory growth in the event bus, WebSocket fan-out, FTS5 query patterns
- **Persistence layer** — SQL injection (parameterized queries are mandatory), FTS5 query parser abuse
- **Desktop sandbox escape** — Tauri IPC commands, file-system access boundaries

### Out of scope

- Third-party dependencies — report upstream first (FastAPI, scikit-learn, Tauri, etc.)
- Self-modifications to the source code or unsupported deployment topologies
- Issues that require physical access to the host machine
- Denial-of-service against a *self-hosted* backend you control where you've deliberately disabled rate limiting
- Detection coverage gaps that don't represent a regression (e.g. "you don't detect attack X" is a feature request, not a vulnerability)
- Reports against the demo data generator or example seed datasets

## Hardening notes

ThreatScope's default deployment binds to `127.0.0.1:8000` and assumes a single-operator environment. If you expose the API beyond loopback, you take responsibility for:

- TLS termination (use a reverse proxy — nginx, Caddy, traefik)
- Authentication enforcement on **all** routes (the JWT middleware is enabled by default; do not disable it)
- Rate limiting tuned for your traffic profile (the built-in per-IP limiter is a soft guardrail)
- Network segmentation between the dashboard and any privileged data sources
- Log file permissions — the tailer reads with the privileges of the process; run it as a dedicated low-privilege user

Default static analysis (ruff `S` rules / Bandit-equivalent) is enforced in CI. Don't disable rules without justification in the PR description.

## Disclosure timeline

Once a vulnerability is confirmed:

1. **Day 0** — Acknowledgement to reporter, severity assessment (CVSS 4.0)
2. **Day 1–14** — Patch development on a private branch
3. **Day 14–30** — Patch review, regression tests, coordinated disclosure window opens
4. **Patch release** — New `v*` tag, GitHub Security Advisory published, CVE assigned (if applicable), reporter credited

For critical vulnerabilities (active exploitation, RCE, auth bypass), we'll compress this timeline. For low-severity issues we may bundle the fix into the next regular release.

## Hall of fame

Credit for accepted reports will be listed here once we have any.
