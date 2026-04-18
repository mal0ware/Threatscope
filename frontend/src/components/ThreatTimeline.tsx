import { useCallback } from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { searchEvents } from '../lib/api';
import { useAPI } from '../hooks/useAPI';

interface TimelineBucket {
  hour: string;
  info: number;
  medium: number;
  high: number;
  critical: number;
}

function bucketEvents(events: { timestamp: string; severity: string }[]): TimelineBucket[] {
  const buckets = new Map<string, TimelineBucket>();
  for (const event of events) {
    const hour = event.timestamp.slice(0, 13) + ':00';
    if (!buckets.has(hour)) {
      buckets.set(hour, { hour, info: 0, medium: 0, high: 0, critical: 0 });
    }
    const b = buckets.get(hour)!;
    const sev = event.severity as keyof Omit<TimelineBucket, 'hour'>;
    if (sev in b) {
      b[sev]++;
    }
  }
  return Array.from(buckets.values()).sort((a, b) => a.hour.localeCompare(b.hour));
}

export function ThreatTimeline() {
  const fetcher = useCallback(() => searchEvents({ limit: 500 }), []);
  const { data, loading } = useAPI(fetcher, 30000);
  const buckets = data ? bucketEvents(data.events) : [];

  if (loading && !data) {
    return (
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 h-64 flex items-center justify-center text-[var(--color-text-muted)]">
        Loading timeline...
      </div>
    );
  }

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-4">Threat Timeline</h2>
      <ResponsiveContainer width="100%" height={240}>
        <AreaChart data={buckets}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
          <XAxis
            dataKey="hour"
            tick={{ fill: '#9ca3af', fontSize: 11 }}
            tickFormatter={(v: string) => v.slice(11, 16)}
          />
          <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
          <Tooltip
            contentStyle={{ background: '#111827', border: '1px solid #1f2937' }}
            labelStyle={{ color: '#e5e7eb' }}
          />
          <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef444433" />
          <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="#f9731633" />
          <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="#eab30833" />
          <Area type="monotone" dataKey="info" stackId="1" stroke="#6b7280" fill="#6b728033" />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
