export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  id: number;
  timestamp: string;
  source: string;
  event_type: string;
  severity: Severity;
  source_ip: string | null;
  dest_ip: string | null;
  dest_port: number | null;
  raw_message: string;
  anomaly_score: number;
  metadata: string | null;
}

export interface Alert {
  id: number;
  event_cluster: string;
  severity: Severity;
  narrative: string | null;
  acknowledged: number;
  created_at: string;
}

export interface StatsOverview {
  total_events: number;
  events_last_hour: number;
  severity_breakdown: Record<string, number>;
  open_alerts: number;
  top_source_ips: { ip: string; count: number }[];
  top_event_types: { type: string; count: number }[];
}

export interface HeatmapBucket {
  day: number;
  hour: number;
  count: number;
}

export interface SearchParams {
  q?: string;
  severity?: Severity;
  source?: string;
  limit?: number;
  offset?: number;
}
