/**
 * ThreatIQ API Client Service
 * Connects React frontend to FastAPI backend endpoints.
 */

const API_BASE = '/api/v1';

export async function fetchHealth() {
  const response = await fetch(`${API_BASE}/health`);
  if (!response.ok) {
    throw new Error(`Health check failed with status: ${response.status}`);
  }
  return response.json();
}

export async function fetchSystemStatus() {
  const response = await fetch(`${API_BASE}/system/status`);
  if (!response.ok) {
    throw new Error(`Failed to fetch system status: ${response.status}`);
  }
  return response.json();
}

export async function fetchModules() {
  const response = await fetch(`${API_BASE}/system/modules`);
  if (!response.ok) {
    throw new Error(`Failed to fetch modules status: ${response.status}`);
  }
  return response.json();
}

export async function sendTelemetryPing(sampleData = {}) {
  const response = await fetch(`${API_BASE}/events/test-ping`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(sampleData),
  });
  if (!response.ok) {
    throw new Error(`Telemetry ping failed: ${response.status}`);
  }
  return response.json();
}

function eventQuery(params = {}, { includeLimit = false } = {}) {
  const query = new URLSearchParams();
  if (includeLimit && params.limit) query.set('limit', String(params.limit));
  if (params.severity) query.set('severity', params.severity);
  if (params.eventType) query.set('event_type', params.eventType);
  if (params.sourceIp) query.set('source_ip', params.sourceIp);
  if (params.q) query.set('q', params.q);
  const text = query.toString();
  return text ? `?${text}` : '';
}

export async function fetchRecentEvents(params = {}) {
  const response = await fetch(`${API_BASE}/events/recent${eventQuery(params, { includeLimit: true })}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch recent events: ${response.status}`);
  }
  return response.json();
}

export async function fetchEventSummary(params = {}) {
  const response = await fetch(`${API_BASE}/events/summary${eventQuery(params)}`);
  if (!response.ok) {
    throw new Error(`Failed to fetch event summary: ${response.status}`);
  }
  return response.json();
}

