# ThreatScope — Dashboard

React 19 + TypeScript + Vite SPA that powers the ThreatScope web dashboard and Tauri desktop app.

For project-wide context, architecture, and detector documentation, see the [main README](../README.md).

## Stack

- **React 19** + **TypeScript** (strict mode)
- **Vite** for dev server and production bundling
- **Tailwind CSS v4** via `@tailwindcss/vite`
- **Recharts** for time-series and bar charts (timeline, top sources, stats)
- **D3.js** force-directed layout for the network communication graph
- **lucide-react** for iconography
- **Tauri 2.x** desktop wrapper (Rust) — see [src-tauri/](src-tauri/)

## Layout

```
src/
├── App.tsx                # Dashboard layout shell
├── components/            # StatsCards, ThreatTimeline, ActivityHeatmap, NetworkMap,
│                          # LiveFeed, AlertsTable, TopSources, ConnectionIndicator, ...
├── hooks/
│   ├── useAPI.ts          # Typed REST client wrapper with error handling
│   └── useWebSocket.ts    # Auto-reconnecting WS hook (events + alerts streams)
├── lib/
│   ├── api.ts             # Endpoint URLs, fetch wrappers
│   └── types.ts           # Shared TypeScript interfaces (Event, Alert, Stats, ...)
├── index.css              # Tailwind base, theme tokens
└── main.tsx               # React root
```

## Develop

```bash
npm ci
npm run dev          # Vite dev server (default :5173)
npm run build        # Type-check + production bundle to dist/
npm run lint         # ESLint
npx tsc --noEmit     # Strict type check
```

The dev server expects the API at `http://127.0.0.1:8000`. Override with `VITE_API_URL` if running the backend elsewhere.

To run the Tauri desktop shell against the dev server:

```bash
npm run tauri dev
```

## Building the desktop app

```bash
npm run tauri build
```

Produces native installers in `src-tauri/target/release/bundle/`. Requires the Rust toolchain and platform-specific dependencies — see [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/).

The CI release pipeline at [../.github/workflows/release.yml](../.github/workflows/release.yml) builds these for Linux, macOS, and Windows on tag push.

## WebSocket reconnection

[hooks/useWebSocket.ts](src/hooks/useWebSocket.ts) implements exponential backoff reconnection (starts at 1s, caps at 30s, resets on successful connection). The connection-status indicator in the header reflects the live state — extend the hook rather than re-implementing per-component.

## Adding a chart or widget

1. Define the data shape in [src/lib/types.ts](src/lib/types.ts).
2. Add a typed fetcher in [src/lib/api.ts](src/lib/api.ts).
3. Build the component under [src/components/](src/components/) — keep it presentational, fetch via `useAPI`.
4. Register it in [src/App.tsx](src/App.tsx) where the dashboard layout is composed.

Charts use Recharts; if you need anything fancier (force-directed graph, custom interactions), reach for D3 the way [NetworkMap.tsx](src/components/NetworkMap.tsx) does.

## Type safety contract

Every API response should have a corresponding TypeScript interface in [src/lib/types.ts](src/lib/types.ts). The strict-mode TypeScript compiler will catch mismatches at build time. Don't reach for `any` — widen at the boundary or refactor.
