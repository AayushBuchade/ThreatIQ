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

export async function fetchRecentEvents() {
  const response = await fetch(`${API_BASE}/events/recent`);
  if (!response.ok) {
    throw new Error(`Failed to fetch recent events: ${response.status}`);
  }
  return response.json();
}
