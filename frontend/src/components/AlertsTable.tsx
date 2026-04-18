import { useCallback, useState } from 'react';
import { CheckCircle } from 'lucide-react';
import { acknowledgeAlert, getAlerts } from '../lib/api';
import { useAPI } from '../hooks/useAPI';
import { SeverityBadge } from './SeverityBadge';
import type { Alert, Severity } from '../lib/types';

export function AlertsTable() {
  const fetcher = useCallback(() => getAlerts(false), []);
  const { data, loading, refresh } = useAPI(fetcher, 15000);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const handleAck = async (id: number) => {
    await acknowledgeAlert(id);
    refresh();
  };

  const alerts = data?.alerts ?? [];

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
        <h2 className="text-lg font-semibold">Active Alerts</h2>
        <span className="text-sm text-[var(--color-text-muted)]">
          {data?.total ?? 0} unacknowledged
        </span>
      </div>
      {loading && !data ? (
        <div className="px-4 py-8 text-center text-[var(--color-text-muted)]">Loading...</div>
      ) : alerts.length === 0 ? (
        <div className="px-4 py-8 text-center text-[var(--color-text-muted)]">
          No active alerts
        </div>
      ) : (
        <div className="divide-y divide-[var(--color-border)]">
          {alerts.map((alert: Alert) => (
            <div key={alert.id} className="px-4 py-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={alert.severity as Severity} />
                  <span className="text-sm">
                    {alert.narrative?.slice(0, 100) ?? 'No narrative'}
                    {(alert.narrative?.length ?? 0) > 100 && '...'}
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-[var(--color-text-muted)]">
                    {new Date(alert.created_at).toLocaleString()}
                  </span>
                  <button
                    onClick={() => handleAck(alert.id)}
                    className="p-1 rounded hover:bg-[var(--color-surface-hover)] text-green-400"
                    title="Acknowledge"
                  >
                    <CheckCircle className="w-4 h-4" />
                  </button>
                </div>
              </div>
              {expandedId === alert.id && alert.narrative && (
                <p className="mt-2 text-sm text-[var(--color-text-muted)] pl-16">
                  {alert.narrative}
                </p>
              )}
              {alert.narrative && (
                <button
                  onClick={() => setExpandedId(expandedId === alert.id ? null : alert.id)}
                  className="text-xs text-[var(--color-accent)] mt-1 hover:underline"
                >
                  {expandedId === alert.id ? 'Collapse' : 'Expand narrative'}
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
