// src/api/tracex-client.ts
var LOCAL_API_BASE = "http://localhost:8000/api/v1";
var PROD_API_BASE = "https://anveshak-xi.vercel.app/api/v1";
async function checkLocalhostRunning() {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 800);
    const res = await fetch("http://localhost:8000/health", { method: "GET", signal: controller.signal });
    clearTimeout(timeoutId);
    if (res.ok) return true;
  } catch {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 800);
      await fetch("http://localhost:5173", { method: "HEAD", mode: "no-cors", signal: controller.signal });
      clearTimeout(timeoutId);
      return true;
    } catch {
      return false;
    }
  }
  return false;
}
var TraceXClient = class {
  apiBase;
  constructor(apiBase = LOCAL_API_BASE) {
    this.apiBase = apiBase;
  }
  async getWorkingApiBases() {
    const isLocal = await checkLocalhostRunning();
    if (isLocal) {
      return [LOCAL_API_BASE, PROD_API_BASE];
    } else {
      return [PROD_API_BASE, LOCAL_API_BASE];
    }
  }
  async analyzeEmail(email) {
    const bases = await this.getWorkingApiBases();
    let lastError = null;
    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 12e3);
      try {
        const response = await fetch(`${base}/extension/analyze`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({
            source: email.source,
            sender: email.sender,
            recipients: email.recipients,
            subject: email.subject,
            timestamp: email.timestamp,
            body_text: email.bodyText,
            raw_headers: email.rawHeaders,
            urls: email.urls,
            message_id: email.messageId
          }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!response.ok) {
          if (response.status === 429) {
            throw new Error("Rate limit exceeded. Please wait a moment before analyzing again.");
          }
          throw new Error(`Server returned error status (${response.status})`);
        }
        const data = await response.json();
        return data;
      } catch (err) {
        clearTimeout(timeoutId);
        if (err.name === "AbortError") {
          lastError = new Error("Analysis timed out. Anveshak investigation engine did not respond in time.");
        } else {
          lastError = err;
        }
      }
    }
    throw lastError || new Error("Unable to connect to Anveshak forensic backend.");
  }
  async traceLink(url) {
    const bases = await this.getWorkingApiBases();
    let lastError = null;
    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8e3);
      try {
        const response = await fetch(`${base}/extension/trace-link`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ url }),
          signal: controller.signal
        });
        clearTimeout(timeoutId);
        if (!response.ok) {
          throw new Error(`Link trace failed (${response.status})`);
        }
        return await response.json();
      } catch (err) {
        clearTimeout(timeoutId);
        lastError = err;
      }
    }
    throw lastError || new Error("Failed to analyze URL intelligence.");
  }
  async checkHealth() {
    return checkLocalhostRunning();
  }
};
var tracexClient = new TraceXClient();

// src/background/service-worker.ts
var verdictCache = /* @__PURE__ */ new Map();
var currentActiveEmail = null;
var BADGE_COLORS = {
  CRITICAL: "#E10600",
  HIGH: "#E10600",
  WARNING: "#F59E0B",
  MEDIUM: "#F59E0B",
  LOW: "#22C55E",
  SAFE: "#22C55E",
  UNVERIFIED: "#6B7280"
};
chrome.runtime.onInstalled.addListener(() => {
  console.log("[Anveshak] Background Service Worker initialized.");
});
if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: false }).catch(() => {
  });
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "EMAIL_EXTRACTED") {
    currentActiveEmail = message.payload;
    chrome.storage.local.set({ tracex_last_email: currentActiveEmail }).catch(() => {
    });
    const cacheKey = `${currentActiveEmail.sender}|${currentActiveEmail.subject}`;
    if (verdictCache.has(cacheKey)) {
      const verdict = verdictCache.get(cacheKey);
      updateBadge(verdict.severity, verdict.risk_score, sender.tab?.id);
      sendResponse({ status: "CACHED", verdict });
      return true;
    }
    sendResponse({ status: "DETECTED", email: currentActiveEmail });
    return true;
  }
  if (message.type === "GET_CURRENT_EMAIL") {
    if (currentActiveEmail) {
      const cacheKey = `${currentActiveEmail.sender}|${currentActiveEmail.subject}`;
      const verdict = verdictCache.get(cacheKey) || null;
      sendResponse({ email: currentActiveEmail, verdict });
    } else {
      chrome.storage.local.get(["tracex_last_email"], (result) => {
        const stored = result.tracex_last_email || null;
        if (stored) currentActiveEmail = stored;
        const cacheKey = stored ? `${stored.sender}|${stored.subject}` : "";
        const verdict = cacheKey ? verdictCache.get(cacheKey) || null : null;
        sendResponse({ email: stored, verdict });
      });
    }
    return true;
  }
  if (message.type === "REQUEST_ANALYSIS") {
    const emailToAnalyze = message.payload || currentActiveEmail;
    if (!emailToAnalyze) {
      sendResponse({ error: "No active email detected to analyze." });
      return true;
    }
    tracexClient.analyzeEmail(emailToAnalyze).then((verdict) => {
      const cacheKey = `${emailToAnalyze.sender}|${emailToAnalyze.subject}`;
      verdictCache.set(cacheKey, verdict);
      updateBadge(verdict.severity, verdict.risk_score, sender.tab?.id);
      sendResponse({ success: true, verdict });
    }).catch((err) => {
      sendResponse({ error: err.message || "Analysis failed" });
    });
    return true;
  }
  if (message.type === "OPEN_SIDE_PANEL") {
    if (sender.tab?.id && chrome.sidePanel && chrome.sidePanel.open) {
      chrome.sidePanel.open({ tabId: sender.tab.id }).catch((err) => {
        console.warn("Could not open side panel:", err);
      });
    }
    sendResponse({ ok: true });
    return true;
  }
  if (message.type === "TRACE_LINK") {
    tracexClient.traceLink(message.url).then((res) => sendResponse({ success: true, data: res })).catch((err) => sendResponse({ error: err.message }));
    return true;
  }
});
function updateBadge(severity, score, tabId) {
  const badgeText = severity === "SAFE" ? "SAFE" : `${Math.round(score)}`;
  const badgeColor = BADGE_COLORS[severity] || "#6B7280";
  chrome.action.setBadgeText({ text: badgeText, tabId });
  chrome.action.setBadgeBackgroundColor({ color: badgeColor, tabId });
}
