/**
 * Shared mail-scan helpers for the ThreatIQ extension.
 * URL rules follow PHISHGUARD's passive inspector. No URL is fetched.
 */
(function (root, factory) {
  const api = factory();
  root.ThreatIQMail = api;
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const MAX_BODY_CHARS = 20000;
  const DEFAULT_BACKEND = "http://127.0.0.1:8000";
  const SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".tk", ".pw", ".buzz", ".ru", ".cn", ".club", ".work",
    ".support", ".live", ".stream", ".icu", ".monster", ".gq", ".ga", ".ml", ".cf",
  ];
  const URL_REGEX = /https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi;
  const IP_REGEX = /^(?:\d{1,3}\.){3}\d{1,3}$/;

  function defangUrl(url) {
    return url.replace(/https:\/\//gi, "hxxps://").replace(/http:\/\//gi, "hxxp://").replace(/\./g, "[.]");
  }

  function extractSuspiciousUrls(text, limit = 10) {
    if (!text) return [];
    const found = [];
    const seen = new Set();
    const matches = String(text).match(URL_REGEX) || [];
    for (const raw of matches) {
      const url = raw.replace(/[.,;)>'"]+$/g, "");
      if (seen.has(url)) continue;
      seen.add(url);
      let host = "";
      try {
        host = new URL(url.includes("://") ? url : `http://${url}`).hostname.toLowerCase();
      } catch (_error) {
        host = "";
      }
      let reason = "";
      if (host && IP_REGEX.test(host)) reason = "Direct IP-address host";
      else if (host && SUSPICIOUS_TLDS.some((tld) => host.endsWith(tld))) reason = `High-risk top-level domain: ${host}`;
      else if (url.includes("@")) reason = "URL contains an @ sign";
      if (reason) found.push({ defanged: defangUrl(url), reason });
      if (found.length >= limit) break;
    }
    return found;
  }

  function normalizeBackendUrl(value) {
    if (!value || typeof value !== "string") return "";
    let parsed;
    try {
      parsed = new URL(value.trim());
    } catch (_error) {
      return "";
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "";
    if (parsed.username || parsed.password) return "";
    return parsed.origin;
  }

  function buildAnalysisPayload(message, record) {
    const body = String(message.body || "").trim();
    const truncated = body.length > MAX_BODY_CHARS;
    return {
      subject: String(message.subject || "").trim().slice(0, 998),
      sender: String(message.sender || "").trim().slice(0, 320),
      body: truncated ? body.slice(0, MAX_BODY_CHARS) : body,
      record: Boolean(record),
      truncated,
      provider: message.provider || "",
    };
  }

  function messageKey(message) {
    const body = String(message.body || "").trim().slice(0, 500);
    return [message.provider || "", message.subject || "", message.sender || "", body].join("\n");
  }

  return {
    MAX_BODY_CHARS,
    DEFAULT_BACKEND,
    defangUrl,
    extractSuspiciousUrls,
    normalizeBackendUrl,
    buildAnalysisPayload,
    messageKey,
  };
});
