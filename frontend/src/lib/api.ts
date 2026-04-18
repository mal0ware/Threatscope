import type { Alert, HeatmapBucket, SearchParams, SecurityEvent, StatsOverview } from './types';

const BASE = '/api/v1';

async function fetchJSON<T>(url: string): Promise<T> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json() as Promise<T>;
}

export async function searchEvents(params: SearchParams = {}) {
  const qs = new URLSearchParams();
  if (params.q) qs.set('q', params.q);
  if (params.severity) qs.set('severity', params.severity);
  if (params.source) qs.set('source', params.source);
  if (params.limit) qs.set('limit', String(params.limit));
  if (params.offset) qs.set('offset', String(params.offset));
  return fetchJSON<{ total: number; events: SecurityEvent[] }>(
    `${BASE}/events/search?${qs}`,
  );
}

export async function getStats() {
  return fetchJSON<StatsOverview>(`${BASE}/stats/overview`);
}

export async function getHeatmap() {
  return fetchJSON<{ period_days: number; buckets: HeatmapBucket[] }>(
    `${BASE}/stats/heatmap`,
  );
}

export async function getAlerts(acknowledged?: boolean) {
  const qs = acknowledged !== undefined ? `?acknowledged=${acknowledged}` : '';
  return fetchJSON<{ total: number; alerts: Alert[] }>(`${BASE}/alerts${qs}`);
}

export async function acknowledgeAlert(id: number) {
  const res = await fetch(`${BASE}/alerts/${id}/acknowledge`, { method: 'POST' });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json() as Promise<{ status: string }>;
}

export async function getNarrative(alertId: number) {
  return fetchJSON<{ alert_id: number; severity: string; narrative: string }>(
    `${BASE}/anomalies/${alertId}/narrative`,
  );
}
