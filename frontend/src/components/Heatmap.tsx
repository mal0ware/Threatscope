import { useCallback } from 'react';
import { getHeatmap } from '../lib/api';
import { useAPI } from '../hooks/useAPI';

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
const HOURS = Array.from({ length: 24 }, (_, i) => i);

function getColor(count: number, max: number): string {
  if (count === 0) return 'bg-gray-800';
  const intensity = count / Math.max(max, 1);
  if (intensity > 0.75) return 'bg-red-500';
  if (intensity > 0.5) return 'bg-orange-500';
  if (intensity > 0.25) return 'bg-yellow-500/60';
  return 'bg-blue-500/30';
}

export function Heatmap() {
  const fetcher = useCallback(() => getHeatmap(), []);
  const { data, loading } = useAPI(fetcher, 60000);

  if (loading && !data) {
    return (
      <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4 h-48 flex items-center justify-center text-[var(--color-text-muted)]">
        Loading heatmap...
      </div>
    );
  }

  const buckets = data?.buckets ?? [];
  const countMap = new Map<string, number>();
  let maxCount = 0;
  for (const b of buckets) {
    const key = `${b.day}-${b.hour}`;
    countMap.set(key, b.count);
    if (b.count > maxCount) maxCount = b.count;
  }

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-4">Event Heatmap (7 days)</h2>
      <div className="overflow-x-auto">
        <div className="min-w-[600px]">
          {/* Hour labels */}
          <div className="flex gap-1 mb-1 ml-10">
            {HOURS.filter((h) => h % 3 === 0).map((h) => (
              <span
                key={h}
                className="text-xs text-[var(--color-text-muted)]"
                style={{ width: `${(3 / 24) * 100}%` }}
              >
                {String(h).padStart(2, '0')}
              </span>
            ))}
          </div>
          {/* Grid */}
          {DAYS.map((day, dayIdx) => (
            <div key={day} className="flex items-center gap-1 mb-1">
              <span className="text-xs text-[var(--color-text-muted)] w-8">{day}</span>
              <div className="flex gap-0.5 flex-1">
                {HOURS.map((hour) => {
                  const count = countMap.get(`${dayIdx}-${hour}`) ?? 0;
                  return (
                    <div
                      key={hour}
                      className={`flex-1 h-4 rounded-sm ${getColor(count, maxCount)} transition-colors`}
                      title={`${day} ${String(hour).padStart(2, '0')}:00 — ${count} events`}
                    />
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
