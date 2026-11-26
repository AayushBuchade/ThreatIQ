const BANNER_ID = "threatiq-mail-banner";
let lastKey = "";
let scanTimer = 0;

function textOf(node) {
  return (node?.innerText || node?.textContent || "").trim();
}

function readOpenMessage() {
  const host = location.hostname;
  if (host === "mail.google.com") {
    const body = document.querySelector("div.a3s.aiL") || document.querySelector("div.a3s");
    if (!body) return null;
    const senderNode = document.querySelector("span.gD[email]") || document.querySelector("span.gD");
    return {
      provider: "gmail",
      subject: textOf(document.querySelector("h2.hP")),
      sender: senderNode?.getAttribute("email") || textOf(senderNode),
      body: textOf(body),
      anchor: body,
    };
  }
  if (host.endsWith("outlook.office.com") || host === "outlook.office365.com" || host === "outlook.live.com") {
    const body = document.querySelector('[aria-label="Message body"]') || document.querySelector('div[role="document"]');
    if (!body) return null;
    const subject = document.querySelector('div[role="main"] [role="heading"]') || document.querySelector('[role="heading"]');
    const sender = document.querySelector('[aria-label^="From"]') || document.querySelector('span[title*="@"]');
    return {
      provider: "outlook",
      subject: textOf(subject),
      sender: sender?.getAttribute("title") || textOf(sender),
      body: textOf(body),
      anchor: body,
    };
  }
  return null;
}

function clearBanner() {
  document.getElementById(BANNER_ID)?.remove();
}

function line(parent, value, className) {
  const node = document.createElement("p");
  node.className = className || "";
  node.textContent = value;
  parent.appendChild(node);
  return node;
}

function renderBanner(anchor, result) {
  clearBanner();
  const banner = document.createElement("aside");
  banner.id = BANNER_ID;
  const phishing = result.ok && result.prediction === "phishing";
  banner.dataset.state = phishing ? "phishing" : result.ok ? "scanned" : "error";
  line(banner, "ThreatIQ", "threatiq-label");
  if (!result.ok) {
    line(banner, result.detail || "Email analysis failed. No prediction was made.");
  } else {
    line(banner, `${result.prediction} · probability ${result.phishing_probability}`);
    line(banner, result.model_version || "", "threatiq-meta");
    if (result.truncated) line(banner, "Only the first 20000 characters were sent.", "threatiq-meta");
    const urls = result.suspicious_urls || [];
    if (urls.length) {
      const list = document.createElement("ul");
      urls.forEach((item) => {
        const row = document.createElement("li");
        row.textContent = `${item.defanged} — ${item.reason}`;
        list.appendChild(row);
      });
      banner.appendChild(list);
    }
    if (result.event_id) {
      line(
        banner,
        result.duplicate ? `Already recorded as ${result.event_id}.` : `Recorded as ${result.event_id}.`,
        "threatiq-meta"
      );
    }
    if (result.record_error) line(banner, result.record_error);
    const report = document.createElement("button");
    report.type = "button";
    report.textContent = "Report to ThreatIQ";
    report.addEventListener("click", () => reportMessage(anchor, banner));
    banner.appendChild(report);
  }
  anchor.parentNode?.insertBefore(banner, anchor);
}

function reportMessage(anchor, banner) {
  const message = readOpenMessage();
  if (!message) return;
  const button = banner.querySelector("button");
  if (button) button.disabled = true;
  chrome.runtime.sendMessage({ type: "analyze", message, record: true }, (result) => {
    if (chrome.runtime.lastError) {
      renderBanner(anchor, { ok: false, detail: "Extension could not reach its background worker. No prediction was made." });
      return;
    }
    renderBanner(message.anchor || anchor, result || { ok: false, detail: "No response from ThreatIQ." });
  });
}

function scanOpenMessage() {
  const message = readOpenMessage();
  if (!message || !message.body) {
    clearBanner();
    lastKey = "";
    return;
  }
  const key = ThreatIQMail.messageKey(message);
  if (key === lastKey) return;
  lastKey = key;
  chrome.runtime.sendMessage({ type: "analyze", message, record: false }, (result) => {
    if (chrome.runtime.lastError) {
      renderBanner(message.anchor, { ok: false, detail: "Extension could not reach its background worker. No prediction was made." });
      return;
    }
    const current = readOpenMessage();
    if (!current || ThreatIQMail.messageKey(current) !== key) return;
    renderBanner(current.anchor, result || { ok: false, detail: "No response from ThreatIQ." });
  });
}

function scheduleScan() {
  window.clearTimeout(scanTimer);
  scanTimer = window.setTimeout(scanOpenMessage, 700);
}

scheduleScan();
window.addEventListener("hashchange", () => {
  lastKey = "";
  scheduleScan();
});
window.addEventListener("popstate", () => {
  lastKey = "";
  scheduleScan();
});
const observer = new MutationObserver(scheduleScan);
observer.observe(document.documentElement, { childList: true, subtree: true });
