import { Activity, AlertTriangle, Clock, Shield } from 'lucide-react';
import type { StatsOverview } from '../lib/types';

interface Props {
  stats: StatsOverview;
}

export function StatsCards({ stats }: Props) {
  const cards = [
    {
      label: 'Total Events',
      value: stats.total_events.toLocaleString(),
      icon: Activity,
      color: 'text-blue-400',
    },
    {
      label: 'Last Hour',
      value: stats.events_last_hour.toLocaleString(),
      icon: Clock,
      color: 'text-cyan-400',
    },
    {
      label: 'Open Alerts',
      value: stats.open_alerts.toLocaleString(),
      icon: AlertTriangle,
      color: stats.open_alerts > 0 ? 'text-red-400' : 'text-green-400',
    },
    {
      label: 'Critical',
      value: (stats.severity_breakdown.critical ?? 0).toLocaleString(),
      icon: Shield,
      color: 'text-red-400',
    },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {cards.map((card) => (
        <div
          key={card.label}
          className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm text-[var(--color-text-muted)]">{card.label}</span>
            <card.icon className={`w-4 h-4 ${card.color}`} />
          </div>
          <div className="text-2xl font-semibold">{card.value}</div>
        </div>
      ))}
    </div>
  );
}
