const backendInput = document.getElementById("backend");
const statusNode = document.getElementById("status");

function showStatus(text, tone) {
  statusNode.textContent = text;
  statusNode.className = tone || "";
}

async function load() {
  const stored = await chrome.storage.local.get({ backendUrl: "http://127.0.0.1:8000" });
  backendInput.value = stored.backendUrl;
}

async function ensurePermission(origin) {
  const current = await chrome.permissions.contains({ origins: [`${origin}/*`] });
  if (current) return true;
  return chrome.permissions.request({ origins: [`${origin}/*`] });
}

document.getElementById("save").addEventListener("click", async () => {
  const origin = ThreatIQMail.normalizeBackendUrl(backendInput.value);
  if (!origin) {
    showStatus("Enter an http or https URL without credentials.", "bad");
    return;
  }
  const allowed = await ensurePermission(origin);
  if (!allowed) {
    showStatus("Browser permission for that backend was not granted.", "bad");
    return;
  }
  await chrome.storage.local.set({ backendUrl: origin });
  backendInput.value = origin;
  showStatus(`Saved ${origin}.`, "ok");
});

document.getElementById("check").addEventListener("click", () => {
  showStatus("Checking…");
  chrome.runtime.sendMessage({ type: "health" }, (result) => {
    if (chrome.runtime.lastError || !result) {
      showStatus("Could not check the connection.", "bad");
      return;
    }
    if (result.connected) {
      showStatus(`Connected to ${result.origin}${result.version ? ` · ${result.version}` : ""}.`, "ok");
    } else {
      showStatus(result.detail || "Not connected.", "bad");
    }
  });
});

load();
