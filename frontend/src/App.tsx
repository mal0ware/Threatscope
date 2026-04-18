import { useCallback } from 'react';
import { Shield } from 'lucide-react';
import { getStats } from './lib/api';
import { useAPI } from './hooks/useAPI';
import { StatsCards } from './components/StatsCards';
import { LiveFeed } from './components/LiveFeed';
import { ThreatTimeline } from './components/ThreatTimeline';
import { AlertsTable } from './components/AlertsTable';
import { Heatmap } from './components/Heatmap';
import { TopSources } from './components/TopSources';
import { NetworkMap } from './components/NetworkMap';

export default function App() {
  const statsFetcher = useCallback(() => getStats(), []);
  const { data: stats, loading } = useAPI(statsFetcher, 15000);

  return (
    <div className="min-h-screen bg-[var(--color-bg)]">
      {/* Header */}
      <header className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-blue-500" />
            <h1 className="text-xl font-bold">ThreatScope</h1>
          </div>
          <span className="text-sm text-[var(--color-text-muted)]">
            Real-Time Threat Intelligence
          </span>
        </div>
      </header>

      {/* Dashboard */}
      <main className="max-w-7xl mx-auto px-6 py-6 space-y-6">
        {/* Stats */}
        {stats && !loading ? (
          <StatsCards stats={stats} />
        ) : (
          <div className="h-24 bg-[var(--color-surface)] rounded-lg animate-pulse" />
        )}

        {/* Two-column layout */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <ThreatTimeline />
          <Heatmap />
        </div>

        {/* Network Map */}
        <NetworkMap />

        {/* Live Feed */}
        <LiveFeed />

        {/* Bottom row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <AlertsTable />
          {stats && <TopSources stats={stats} />}
        </div>
      </main>
    </div>
  );
}
