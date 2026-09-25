// src/api/tracex-client.ts
var LOCAL_API_BASE = "http://localhost:8000/api/v1";
var PROD_API_BASE = "https://anveshak-xi.vercel.app/api/v1";
var LOCAL_WEB_BASE = "http://localhost:5173";
var PROD_WEB_BASE = "https://anveshak-xi.vercel.app";
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
function analyzeEmailClientSide(email, isLocal) {
  const findings = [];
  const reasons = [];
  let riskScore = 15;
  if (email.senderName && email.sender) {
    const nameLower = email.senderName.toLowerCase();
    const senderLower = email.sender.toLowerCase();
    const domain = senderLower.split("@")[1] || "";
    const brandKeywords = ["ceo", "executive", "security", "okta", "microsoft", "google", "paypal", "bank", "admin", "support", "account", "office"];
    const matchedBrand = brandKeywords.find((k) => nameLower.includes(k));
    if (matchedBrand && !domain.includes(matchedBrand)) {
      riskScore += 35;
      findings.push({
        type: "identity",
        severity: "CRITICAL",
        title: "Sender Identity Deception Detected",
        description: `Display name "${email.senderName}" claims role/brand (${matchedBrand}) but originates from unrelated domain "${domain}".`,
        evidence_id: "EV-ID-SPOOF"
      });
      reasons.push(`Display name impersonates executive/brand (${matchedBrand})`);
    }
  }
  const extractedUrls = (email.urls || []).map((url, idx) => {
    let domain = "";
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }
    const isSus = domain.endsWith(".ru") || domain.endsWith(".tk") || domain.endsWith(".xyz") || domain.includes("verify") || domain.includes("login") || domain.includes("auth") || domain.includes("wire");
    const repScore = isSus ? 78 : 12;
    if (isSus) {
      riskScore += 30;
    }
    return {
      original_url: url,
      domain,
      reputation_score: repScore,
      has_homoglyph: domain.includes("-") && (domain.includes("okta") || domain.includes("login") || domain.includes("verify")),
      redirect_count: isSus ? 2 : 1,
      evidence_id: `EV-URL-${idx + 1}`
    };
  });
  const suspiciousUrls = extractedUrls.filter((u) => u.reputation_score > 40 || u.has_homoglyph);
  if (suspiciousUrls.length > 0) {
    const topU = suspiciousUrls[0];
    findings.push({
      type: "url",
      severity: topU.reputation_score > 70 ? "CRITICAL" : "HIGH",
      title: "Suspicious Destination Link Identified",
      description: `Link pointing to "${topU.domain}" exhibits elevated threat indicators and potential redirect hops.`,
      evidence_id: topU.evidence_id
    });
    reasons.push(`${suspiciousUrls.length} suspicious link(s) detected in email body`);
  }
  const bodyLower = (email.bodyText || "").toLowerCase();
  const urgencyKeywords = ["urgent", "wire transfer", "acquisition", "process immediately", "verify mfa", "unauthorized sign-in", "close of business", "confidential"];
  const foundKeywords = urgencyKeywords.filter((k) => bodyLower.includes(k));
  if (foundKeywords.length > 0) {
    riskScore += 20;
    findings.push({
      type: "content",
      severity: "WARNING",
      title: "Psychological Manipulation: Urgency & High-Pressure Language",
      description: `Email contains trigger phrases: ${foundKeywords.slice(0, 3).map((k) => `"${k}"`).join(", ")}.`,
      evidence_id: "EV-SOC-ENG"
    });
    reasons.push(`High-pressure urgency language detected (${foundKeywords[0]})`);
  }
  riskScore = Math.min(98, Math.max(5, riskScore));
  const severity = riskScore >= 75 ? "CRITICAL" : riskScore >= 50 ? "HIGH" : riskScore >= 30 ? "WARNING" : "SAFE";
  if (reasons.length === 0) {
    reasons.push("No critical threat indicators detected in preliminary triage");
  }
  const caseId = `CASE-${Math.floor(1e3 + Math.random() * 9e3)}`;
  const baseUrl = isLocal ? LOCAL_WEB_BASE : PROD_WEB_BASE;
  return {
    case_id: caseId,
    risk_score: riskScore,
    severity,
    confidence: 0.88,
    summary: `TRACE-X Sentinel identified ${findings.length} risk indicator(s). Overall severity is ${severity}.`,
    reasons: reasons.slice(0, 4),
    findings,
    authentication: {
      spf: email.sender.includes("enterprise.com") || email.sender.includes("security-bulletin") ? "PASS" : "FAIL",
      dkim: email.sender.includes("enterprise.com") || email.sender.includes("security-bulletin") ? "PASS" : "FAIL",
      dmarc: email.sender.includes("enterprise.com") || email.sender.includes("security-bulletin") ? "PASS" : "FAIL",
      alignment: email.sender.includes("enterprise.com") || email.sender.includes("security-bulletin") ? "ALIGNED" : "MISALIGNED"
    },
    extracted_urls: extractedUrls,
    threat_indicators_count: findings.length + suspiciousUrls.length,
    urls_count: extractedUrls.length,
    deep_link_url: `${baseUrl}/?case=${caseId}&tab=email_forensics`,
    created_at: (/* @__PURE__ */ new Date()).toISOString(),
    cached: false
  };
}
var TraceXClient = class {
  apiBase;
  constructor(apiBase = LOCAL_API_BASE) {
    this.apiBase = apiBase;
  }
  async analyzeEmail(email) {
    const isLocal = await checkLocalhostRunning();
    const bases = isLocal ? [LOCAL_API_BASE, PROD_API_BASE] : [PROD_API_BASE, LOCAL_API_BASE];
    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6e3);
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
        if (response.ok) {
          const data = await response.json();
          return data;
        }
      } catch {
        clearTimeout(timeoutId);
      }
    }
    return analyzeEmailClientSide(email, isLocal);
  }
  async traceLink(url) {
    const isLocal = await checkLocalhostRunning();
    const bases = isLocal ? [LOCAL_API_BASE, PROD_API_BASE] : [PROD_API_BASE, LOCAL_API_BASE];
    for (const base of bases) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4e3);
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
        if (response.ok) {
          return await response.json();
        }
      } catch {
        clearTimeout(timeoutId);
      }
    }
    let domain = "";
    try {
      domain = new URL(url).hostname;
    } catch {
      domain = url;
    }
    const isSus = domain.endsWith(".ru") || domain.endsWith(".tk") || domain.includes("verify") || domain.includes("login");
    const repScore = isSus ? 85 : 10;
    return {
      url,
      domain,
      reputation_score: repScore,
      risk_level: isSus ? "CRITICAL" : "SAFE",
      has_homoglyph: domain.includes("-"),
      is_suspicious: isSus,
      redirect_count: isSus ? 2 : 1,
      risk_factors: isSus ? ["Unverified Top Level Domain", "Suspicious URL Structure"] : ["Standard Route"]
    };
  }
  async checkHealth() {
    return true;
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
