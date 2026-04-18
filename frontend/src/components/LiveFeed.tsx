import { useWebSocket } from '../hooks/useWebSocket';
import { SeverityBadge } from './SeverityBadge';
import type { SecurityEvent, Severity } from '../lib/types';

function formatTime(ts: string) {
  return new Date(ts).toLocaleTimeString();
}

function EventRow({ event }: { event: SecurityEvent }) {
  return (
    <div className="flex items-center gap-3 px-4 py-2 border-b border-[var(--color-border)] hover:bg-[var(--color-surface-hover)] transition-colors">
      <span className="text-xs text-[var(--color-text-muted)] w-20 shrink-0 font-mono">
        {formatTime(event.timestamp)}
      </span>
      <SeverityBadge severity={event.severity as Severity} />
      <span className="text-sm font-medium w-32 shrink-0">{event.event_type}</span>
      <span className="text-sm text-[var(--color-text-muted)] w-28 shrink-0 font-mono">
        {event.source_ip ?? '—'}
      </span>
      <span className="text-sm text-[var(--color-text-muted)] truncate">
        {event.raw_message}
      </span>
    </div>
  );
}

export function LiveFeed() {
  const { events, connected } = useWebSocket();

  return (
    <div className="bg-[var(--color-surface)] border border-[var(--color-border)] rounded-lg overflow-hidden">
      <div className="flex items-center justify-between px-4 py-3 border-b border-[var(--color-border)]">
        <h2 className="text-lg font-semibold">Live Event Feed</h2>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-xs text-[var(--color-text-muted)]">
            {connected ? 'Connected' : 'Reconnecting...'}
          </span>
        </div>
      </div>
      <div className="max-h-96 overflow-y-auto">
        {events.length === 0 ? (
          <div className="px-4 py-8 text-center text-[var(--color-text-muted)]">
            Waiting for events...
          </div>
        ) : (
          events.map((event, i) => <EventRow key={`${event.timestamp}-${i}`} event={event} />)
        )}
      </div>
    </div>
  );
}
