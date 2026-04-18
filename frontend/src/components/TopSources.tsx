import type { StatsOverview } from '../lib/types';

interface Props {
  stats: StatsOverview;
}

export function TopSources({ stats }: Props) {
  const maxCount = Math.max(...stats.top_source_ips.map((s) => s.count), 1);

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-4">Top Source IPs</h2>
      <div className="space-y-2">
        {stats.top_source_ips.length === 0 ? (
          <p className="text-sm text-[var(--color-text-muted)]">No data</p>
        ) : (
          stats.top_source_ips.map((entry) => (
            <div key={entry.ip} className="flex items-center gap-3">
              <span className="text-sm font-mono w-36 shrink-0">{entry.ip}</span>
              <div className="flex-1 bg-gray-800 rounded-full h-2">
                <div
                  className="bg-blue-500 h-2 rounded-full transition-all"
                  style={{ width: `${(entry.count / maxCount) * 100}%` }}
                />
              </div>
              <span className="text-sm text-[var(--color-text-muted)] w-12 text-right">
                {entry.count}
              </span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
