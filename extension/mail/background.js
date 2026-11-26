importScripts("lib/mail.js");

const DEFAULT_BACKEND = ThreatIQMail.DEFAULT_BACKEND;

async function backendOrigin() {
  const stored = await chrome.storage.local.get({ backendUrl: DEFAULT_BACKEND });
  return ThreatIQMail.normalizeBackendUrl(stored.backendUrl) || DEFAULT_BACKEND;
}

async function readJson(response) {
  try {
    return await response.json();
  } catch (_error) {
    return {};
  }
}

async function checkHealth() {
  const origin = await backendOrigin();
  try {
    const response = await fetch(`${origin}/api/v1/health`);
    const data = await readJson(response);
    if (!response.ok || data.status !== "ok") {
      return { connected: false, origin, detail: "ThreatIQ health check failed. No email was scored." };
    }
    return { connected: true, origin, version: data.version || "" };
  } catch (_error) {
    return { connected: false, origin, detail: "ThreatIQ is unreachable. No email was scored." };
  }
}

async function analyze(message, record) {
  const origin = await backendOrigin();
  const payload = ThreatIQMail.buildAnalysisPayload(message, record);
  if (!payload.body) {
    return { ok: false, detail: "The open message has no body text. No prediction was made." };
  }
  try {
    const response = await fetch(`${origin}/api/v1/email/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        subject: payload.subject,
        sender: payload.sender,
        body: payload.body,
        record: payload.record,
      }),
    });
    const data = await readJson(response);
    if (!response.ok) {
      const detail = typeof data.detail === "string" ? data.detail : "Email analysis failed. No prediction was made.";
      return { ok: false, detail };
    }
    return {
      ok: true,
      truncated: payload.truncated,
      prediction: data.prediction,
      phishing_probability: data.phishing_probability,
      model_version: data.model_version,
      suspicious_urls: Array.isArray(data.suspicious_urls) ? data.suspicious_urls : [],
      recorded: Boolean(data.recorded),
      duplicate: Boolean(data.duplicate),
      event_id: data.event_id || "",
      record_error: data.record_error || "",
    };
  } catch (_error) {
    return { ok: false, detail: "ThreatIQ is unreachable. No prediction was made." };
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const task = message?.type === "health"
    ? checkHealth()
    : message?.type === "analyze"
      ? analyze(message.message || {}, message.record)
      : Promise.resolve({ ok: false, detail: "Unknown extension request." });
  task.then(sendResponse);
  return true;
});
