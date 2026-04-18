<!--
Thanks for the contribution! Please fill in this template so reviewers can move quickly.

Releases are produced by pushing a `v*` tag — please do NOT include tag pushes in your PR.

For security fixes, see SECURITY.md before opening a public PR. A public PR with a security fix is itself a disclosure.
-->

## Summary

<!-- 1–3 bullets describing what changed and why. The "why" matters more than the "what". -->

-

## Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] New detector (rule-based or ML — include empirical evidence below)
- [ ] Breaking change (fix or feature that would cause existing behavior to change)
- [ ] Documentation only
- [ ] Build / CI / tooling
- [ ] Refactor (no behavior change)

## Linked issues

<!-- e.g. "Closes #12, related to #5" -->

## Test plan

<!-- Concrete steps a reviewer can run to verify the change works. Replace this list. -->

- [ ] `pytest tests/ -v` — all tests pass
- [ ] `ruff check . && mypy agent/ ml/ api/ --ignore-missing-imports` — clean
- [ ] `cd frontend && npx tsc --noEmit && npm run build` — type-check + build succeed
- [ ] Manual: <describe the operator path you exercised in dev>
- [ ] (UI changes only) Screenshot or short clip attached below
- [ ] (Detector changes only) False-positive measurement on demo data attached

## Security impact

<!-- Required for any change touching auth, rate limiting, input validation, parsers, the SQLite layer, or the WebSocket / Tauri IPC boundaries. -->

- [ ] No security impact — pure refactor / docs / unrelated subsystem
- [ ] Security impact — described below

<!-- If "Security impact", describe: what attack surface changes? Could the change introduce a new injection vector, bypass a rate limit, leak data across sessions, etc.? Reference the relevant SECURITY.md threat model categories. -->

## Detector evidence (if applicable)

<!-- For new or modified detectors, paste:
  - Sample log fixture (sanitized) that triggers the detector
  - False-positive rate on baseline / demo data
  - ROC curve or threshold-tuning rationale (link to notebook OK)
-->

## Screenshots / clips

<!-- For any UI change. Drag-drop into the description box. -->

## Notes for the reviewer

<!-- Tradeoffs you considered, follow-ups intentionally deferred, areas you want extra scrutiny on. Optional. -->
