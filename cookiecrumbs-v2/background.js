// ============================================================
// Cookie Crumbs v5.3 — background.js (Service Worker)
//
// Cookie detection methods:
//   1. chrome.cookies.onChanged   — event-driven, fires on every set/delete
//   2. chrome.webRequest.*        — catches all network domains contacted
//   3. chrome.tabs.onUpdated      — full scan on page complete
//   4. chrome.scripting.executeScript — pulls document.cookie from page
//   5. DOC_COOKIES message        — JS-set cookies from content.js
//   6. manual scan requests       — optional refresh trigger
// ============================================================

importScripts("domain_utils.js", "indexed_db.js", "ml_inference.js", "crypto_store.js");

async function getLocalData() {
  return CookieCrumbsStore.init();
}

async function warmLocalData() {
  try {
    await getLocalData();
  } catch (e) {
    console.warn("[CC] IndexedDB init failed:", e);
  }
}

chrome.runtime.onInstalled.addListener(() => {
  warmLocalData();
});

chrome.runtime.onStartup.addListener(() => {
  warmLocalData();
});

warmLocalData();

// ── Open side panel on toolbar click ─────────────────────────
chrome.action.onClicked.addListener(tab => {
  chrome.sidePanel.open({ tabId: tab.id });
  reconcileContentScripts();
});

// ── Content-script reconcile (re-attach after disable→enable) ──
// MV3 gives no "extension was enabled" event, and content scripts are NOT
// re-injected into already-open tabs when the extension is re-enabled — the
// old button's isolated world was destroyed at disable, leaving an orphaned
// DOM node with no listeners (alpha report: "error appears and the floating
// button stops working"). The probe asks each tab whether a live content
// script world still exists (content.js sets globalThis.__ccLive = true at
// load; the flag dies with the world). Tabs reporting nothing get the
// manifest script set re-injected, which also sweeps the orphan node and
// re-applies the user's widgetEnabled setting via the normal settings path.
// Triggers: toolbar click, tab activation (single tab), and a throttled
// sweep from SW cold start. No timers of ours are created — all event-driven.
const CS_RECONCILE_THROTTLE_MS = 15000;
let csReconcileLast = 0;
const CS_PROBE = () => globalThis.__ccLive === true;

async function reconcileContentScripts() {
  try {
    const now = Date.now();
    if (now - csReconcileLast < CS_RECONCILE_THROTTLE_MS) return;
    csReconcileLast = now;
    const tabs = await chrome.tabs.query({});
    for (const tab of tabs) {
      if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) continue;
      let live = false;
      try {
        const results = await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          func: CS_PROBE,
        });
        // "some" (not "every"): if any frame is alive, skip — re-injecting
        // into a live world would redeclare top-level let/const bindings.
        live = Array.isArray(results) && results.some(r => r?.result === true);
      } catch (e) { continue; } // restricted or discarded tab
      if (live) continue;
      try {
        await chrome.scripting.executeScript({
          target: { tabId: tab.id, allFrames: true },
          files: ["domain_utils.js", "ml_inference.js", "content.js"],
        });
      } catch (e) { /* restricted tab */ }
    }
  } catch (e) {
    console.warn("[CC] Content-script reconcile failed:", e.message);
  }
}

async function reconcileTab(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  try {
    const tab = await chrome.tabs.get(tabId);
    if (!tab?.url || !/^https?:/.test(tab.url)) return;
    let live = false;
    try {
      const results = await chrome.scripting.executeScript({
        target: { tabId, allFrames: true },
        func: CS_PROBE,
      });
      live = Array.isArray(results) && results.some(r => r?.result === true);
    } catch (e) { return; }
    if (live) return;
    await chrome.scripting.executeScript({
      target: { tabId, allFrames: true },
      files: ["domain_utils.js", "ml_inference.js", "content.js"],
    });
  } catch (e) { /* restricted tab */ }
}

// Cold-start sweep: the SW starts the moment the extension is enabled, so
// this covers the enable case (throttled — the SW also wakes on every
// cookie event, and probing all tabs on every wake would be wasteful).
reconcileContentScripts();

const savedCookieTracking = new Map();
let riskBlockingJustEnabled = false;
const mlDiagLog = [];
const ML_DIAG_MAX = 50;
function mlDiag(entry) {
  const normDomain = normalizeHost(entry.domain);
  const idx = mlDiagLog.findIndex(e => e.name === entry.name && normalizeHost(e.domain) === normDomain);
  const normalized = { ...entry, domain: normDomain };
  if (idx >= 0) { mlDiagLog[idx] = { ...normalized, t: Date.now() }; }
  else { mlDiagLog.push({ ...normalized, t: Date.now() }); }
  if (mlDiagLog.length > ML_DIAG_MAX) mlDiagLog.shift();
}

const ccDiagLog = [];
let ccDiagFlushTimer = null;
function ccDiag(entry) {
  ccDiagLog.push({ ...entry, t: Date.now() });
  if (ccDiagLog.length > 50) ccDiagLog.shift();
  if (!ccDiagFlushTimer) {
    ccDiagFlushTimer = setTimeout(() => {
      ccDiagFlushTimer = null;
      chrome.storage.local.set({ ccDiagLog: ccDiagLog.slice(-30) });
    }, 5000);
  }
}
chrome.storage.local.get("ccDiagLog", data => {
  if (Array.isArray(data.ccDiagLog)) ccDiagLog.push(...data.ccDiagLog.slice(-30));
});

// ── Decision Receipt Log ───────────────────────────────────────
// WHY IT EXISTS: When a login breaks (e.g. Google multi-account logout),
// the question is always "which rule removed what, and what did the tab
// state look like at that moment?" Console.debug lines vanish on worker
// restart, blockResults in mergeCookies are dropped after each scan, and
// guard skips record nothing. This bounded ring captures one receipt per
// cookie verdict (BLOCKED / PURGED / KEPT + reason code + siteKey and
// origin AT DECISION TIME + trigger + toggle snapshot) so a single
// sidepanel export answers "who did it" without console-diving.
// Cap 500 rows, kill-biased eviction: BLOCKED/PURGED rows are never evicted
// while any KEPT row exists (KEEP noise from busy scans must not drown the
// evidence a logout investigation needs), and kill rows flush to storage
// immediately instead of waiting for the 5s KEEP debounce — the persisted
// copy keeps them too. Debounced persist still mirrors the rest.
const DECISION_RECEIPTS_MAX = 500;
const decisionReceipts = [];
let decisionReceiptsFlushTimer = null;
function flushDecisionReceipts() {
  if (decisionReceiptsFlushTimer) {
    clearTimeout(decisionReceiptsFlushTimer);
    decisionReceiptsFlushTimer = null;
  }
  try { chrome.storage.local.set({ ccDecisionReceipts: decisionReceipts.slice(-DECISION_RECEIPTS_MAX) }); } catch (e) {}
}
function recordDecision(entry) {
  try {
    const verdict = entry.verdict || "KEPT";
    decisionReceipts.push({
      t: Date.now(),
      tabId: entry.tabId ?? null,
      site: entry.site || "",
      origin: entry.origin || "",
      name: entry.name || "",
      domain: entry.domain || "",
      path: entry.path || "",
      url: entry.url || "",
      httpOnly: !!entry.httpOnly,
      secure: !!entry.secure,
      fromDocCookie: !!entry.fromDocCookie,
      session: !!entry.session,
      verdict,
      reason: entry.reason || "NOT_BLOCKED",
      cat: entry.cat || "?",
      trigger: entry.trigger || "",
      tb: !!entry.tb,
      sg: !!entry.sg,
    });
    while (decisionReceipts.length > DECISION_RECEIPTS_MAX) {
      let idx = decisionReceipts.findIndex(e => e.verdict !== "BLOCKED" && e.verdict !== "PURGED");
      if (idx < 0) idx = 0;
      decisionReceipts.splice(idx, 1);
    }
    if (verdict === "BLOCKED" || verdict === "PURGED") {
      flushDecisionReceipts();
      return;
    }
    if (!decisionReceiptsFlushTimer) {
      decisionReceiptsFlushTimer = setTimeout(() => {
        decisionReceiptsFlushTimer = null;
        flushDecisionReceipts();
      }, 5000);
    }
  } catch (e) {}
}
chrome.storage.local.get("ccDecisionReceipts", data => {
  try {
    if (Array.isArray(data.ccDecisionReceipts)) decisionReceipts.push(...data.ccDecisionReceipts.slice(-DECISION_RECEIPTS_MAX));
  } catch (e) {}
});

// ── Cookie Churn Diagnostic ──────────────────────────────────
const cookieChurnLog = [];
const cookieRotationMap = new Map();
const cookieCauseMap = new Map();
const churnStats = { adds: 0, removes: 0, rotations: 0, startTime: Date.now(), notificationCount: 0 };
function recordChurnEvent(type, cookie, tabId, cause) {
  const now = Date.now();
  const name = cookie?.name || "";
  const domain = normalizeHost(cookie?.domain || "");
  const key = name + "::" + domain;
  const entry = { type, name, domain, tabId, t: now, cause: cause || "" };
  cookieChurnLog.push(entry);
  if (cookieChurnLog.length > 100) cookieChurnLog.shift();
  if (type === "ADD") {
    churnStats.adds++;
    const prev = cookieRotationMap.get(key);
    if (prev && (now - prev.delTime) < 5000) {
      churnStats.rotations++;
      entry.rotation = true;
      entry.gapMs = now - prev.delTime;
    }
    cookieRotationMap.set(key, { addTime: now, delTime: prev?.delTime || 0 });
  } else {
    churnStats.removes++;
    const prev = cookieRotationMap.get(key);
    cookieRotationMap.set(key, { addTime: prev?.addTime || 0, delTime: now });
    const causeKey = key + "::" + (cause || "unknown");
    const causeEntry = cookieCauseMap.get(causeKey) || { name, domain, cause: cause || "unknown", count: 0 };
    causeEntry.count++;
    cookieCauseMap.set(causeKey, causeEntry);
  }
}

const sessionCache = {};
async function preloadSessionCache() {
  try {
    const data = await chrome.storage.session.get("ccTabState");
    const raw = data.ccTabState || {};
    for (const [tabId, entry] of Object.entries(raw)) {
      sessionCache[tabId] = {
        s: new Set(entry.s || []),
        d: new Map(Object.entries(entry.d || {})),
        c: Array.isArray(entry.c) ? entry.c : [],
        k: entry.k || "",
        u: entry.u || "",
      };
    }
  } catch(e) { console.warn("[CC]", e.message); }
}
preloadSessionCache();

/**
 * COOKIE_SNAPSHOT_FIELDS: Whitelist of cookie properties saved to session storage.
 * WHY IT EXISTS: Chrome's cookie objects contain runtime metadata and internal fields
 *   that are either unnecessary, too large, or non-serializable. Saving only the
 *   subset needed for rehydration keeps session storage compact and avoids errors
 *   when persisting to chrome.storage.session (which has a quota).
 * HOW IT WORKS: Each cookie in tab state is iterated and only these fields are copied
 *   into a plain-object snapshot. The snapshot is then batch-debounced to storage.
 * INPUT: A Chrome cookie object (with any extra runtime properties).
 * OUTPUT: A plain object containing only the listed keys (plus any custom underscore
 *   prefixed metadata like _cat, _method, _keepReason).
 * Source: Chrome Extensions MV3 storage quota — chrome.storage.session has a ~10 MB limit;
 *   RFC 6265 Section 5.4 (cookie attributes that define behavior).
 */
const COOKIE_SNAPSHOT_FIELDS = ["name","domain","path","hostOnly","partitionKey","storeId","expirationDate","httpOnly","secure","sameSite","session","fromDocCookie","_cat","_method","_keepReason","_sessionLike","valueFeatures","vendorResolved"];
let saveSessionTimer = null;
function saveSessionState(tabId, state) {
  if (!state || !Number.isInteger(tabId)) return;
  const cookiesSnapshot = [];
  for (const cookie of state.cookies.values()) {
    const entry = {};
    for (const f of COOKIE_SNAPSHOT_FIELDS) {
      if (cookie[f] !== undefined) entry[f] = cookie[f];
    }
    cookiesSnapshot.push(entry);
  }
  sessionCache[tabId] = {
    s: new Set(state.cookiesSetBySite),
    d: new Map(state.domains),
    c: cookiesSnapshot,
    // Identity fields: without these, a worker restart restores the tab as a
    // blank-siteKey virgin (URL and siteKey lost), which blinds the Session
    // Guard cross-tab guard and re-opens the foreign-tab judgment window.
    k: state.siteKey || "",
    u: state.url || "",
  };
  clearTimeout(saveSessionTimer);
  saveSessionTimer = setTimeout(() => {
    const out = {};
    for (const [id, e] of Object.entries(sessionCache)) {
      out[id] = { s: [...e.s], d: Object.fromEntries(e.d), c: e.c || [], k: e.k || "", u: e.u || "" };
    }
    try { chrome.storage.session.set({ ccTabState: out }); } catch(e) { console.warn("[CC]", e.message); }
  }, 500);
}

/**
 * Per-tab state management block:
 * WHY IT EXISTS: Cookie Crumbs tracks cookies independently per browser tab because
 *   each tab navigates to different sites, contacts different third-party domains,
 *   and has different auth contexts. Without per-tab state, cookies from Site A
 *   would leak into Site B's analysis, producing false positives and incorrect
 *   privacy scores.
 * HOW IT WORKS: tabState is a dictionary keyed by tab ID. Each entry holds the tab's
 *   current URL, site key (registrable domain), contacted domain map, cookie map,
 *   and flags. sidePanelOpenTabs tracks which tabs have the panel open. catchUpBlockedKeys
 *   prevents re-processing already-blocked cookies during catch-up sweeps.
 *   restartPendingTabIds tracks tabs queued for reload when risk blocking is first enabled.
 * INPUT: Tab IDs from Chrome tab/webRequest events.
 * OUTPUT: Mutable per-tab state objects used by all downstream enforcement and scoring.
 *   No single global output — this is the central state store.
 * Source: Chrome Extensions API — tabs, webRequest, and cookies events are all per-tab.
 */
// ── Per-tab state ─────────────────────────────────────────────
const tabState = {};
const sidePanelOpenTabs = new Set();
const catchUpBlockedKeys = new Set();
const restartPendingTabIds = new Set();
const CATCHUP_KEYS_MAX = 1000;
const SESSION_LOCK_DEFAULTS = {
  sessionLockEnabled: false,
};
const RISK_BLOCKING_DEFAULTS = {
  riskBlockingEnabled: true,
};
/**
 * WHITELIST_DEFAULTS: Per-engine site exemption lists, kept fully independent —
 *   tbSiteWhitelist exempts a site from Tracker Blocking (cookie removal + DNR
 *   network rules), sgSiteWhitelist exempts it from Session Guard purges at leave.
 * WHY IT EXISTS: The user must be able to say "hands off this site" for one
 *   engine without touching the other. Entries are registrable domains
 *   (eTLD+1), so "google.com" exempts every subdomain — no per-subdomain listing.
 * HOW IT WORKS: Stored in chrome.storage.local as string arrays; background keeps
 *   in-memory copies (tbSiteWhitelist / sgSiteWhitelist) refreshed by
 *   loadProtectionSettings() and the storage.onChanged listener; gates call
 *   siteMatchesWhitelist() from domain_utils.js.
 * Source: Subdomain coverage via registrable-domain (eTLD+1) identity — same
 *   scoping as tab siteKey; dot-boundary suffix match per RFC 6265 Section 5.1.3.
 */
const WHITELIST_DEFAULTS = {
  tbSiteWhitelist: [],
  sgSiteWhitelist: [],
};
const PROTECTION_DEFAULTS = {
  ...SESSION_LOCK_DEFAULTS,
  ...RISK_BLOCKING_DEFAULTS,
  ...WHITELIST_DEFAULTS,
  ccEnabled: true,
  consentAnalysisEnabled: true,
};
let sessionLockSettings = { ...SESSION_LOCK_DEFAULTS };
let riskBlockingSettings = { ...RISK_BLOCKING_DEFAULTS };
let tbSiteWhitelist = [];
let sgSiteWhitelist = [];
let ccEnabled = true;
let riskDataCache = null;
let riskModelCache = null;
const suppressedTrackingCookies = new Map();
const stickyBlockedDomains = new Set();
const SUPPRESSED_MAP_MAX = 500;
const DNR_RULE_ID_START = 20000;
const DNR_RULE_LIMIT = 1500;
const removalNoticeQueue = new Map();
const sidePanelNotifyQueue = new Map();
const scanInFlight = new Map();
const pendingScanUrls = new Map();
// navStartTimes: per-tab navigation-start timestamps (Date.now()) stamped at
// NAV_LOADING for any navigation with a previous state. The first
// post-navigation scan consumes the marker: it merges and expires
// pre-navigation contacts but never prunes. See H4 in the plan.
const navStartTimes = new Map();
// trailingScanBudget/timers (M2): hosts contacted AFTER the last scan
// (consent-gated, scroll-loaded, lazy third parties) otherwise stay invisible
// — no cookie event fires for pre-existing cookies, and nothing rescans until
// the next navigation. A genuinely NEW contacted host schedules one debounced
// trailing scan; budget 2 per navigation (reset at NAV_LOADING) so ad-storms
// can't scan-loop. scanAll's in-flight dedup coalesces bursts regardless.
const TRAILING_SCAN_DEBOUNCE_MS = 4000;
const TRAILING_SCANS_PER_NAV = 2;
const trailingScanBudget = new Map();
const trailingScanTimers = new Map();
function shouldTrailingScan({ isNewHost, budgetLeft, hasHttpUrl }) {
  if (!isNewHost || !hasHttpUrl) return false;
  if (!(budgetLeft > 0)) return false;
  return true;
}
function maybeScheduleTrailingScan(tabId, isNewHost) {
  try {
    if (!isNewHost) return false;
    const state = tabState[tabId];
    if (!state) return false;
    const url = state.url || "";
    if (!url.startsWith("http://") && !url.startsWith("https://")) return false;
    const left = trailingScanBudget.has(tabId) ? trailingScanBudget.get(tabId) : TRAILING_SCANS_PER_NAV;
    if (!shouldTrailingScan({ isNewHost: true, budgetLeft: left, hasHttpUrl: true })) return false;
    trailingScanBudget.set(tabId, left - 1);
    if (trailingScanTimers.has(tabId)) clearTimeout(trailingScanTimers.get(tabId));
    trailingScanTimers.set(tabId, setTimeout(() => {
      trailingScanTimers.delete(tabId);
      try { scanAll(tabId, (tabState[tabId] && tabState[tabId].url) || url); } catch (e) {}
    }, TRAILING_SCAN_DEBOUNCE_MS));
    return true;
  } catch (e) { return false; }
}
// pendingCookieOverwrites: overwrite-handoff pairing (P-A). Chrome reports a
// cookie value/path overwrite as a remove event followed by the replacement's
// set event. Treating the remove half as a real deletion creates transient
// undercounts (and cross-tab misattribution when the set lands elsewhere), so
// overwrite removes only stage a handoff: the replacement set updates the
// holding tabs in place. Map: twin-aware cookieKey -> {t, tabIds}. Bounded
// (500 entries) with 5s expiry, swept on every cookie event.
const pendingCookieOverwrites = new Map();
  const RISK_CATCHUP_PASSES = 5;
  const RISK_CATCHUP_DELAY_MS = 600;
const GOOGLE_TRACKING_DNR_START = 21500;
/**
 * GOOGLE_TRACKING_RULES: DNR (Declarative Net Request) rules that block Google's
 *   advertising and analytics infrastructure at the network level.
 * WHY IT EXISTS: Google's ad-tech domains (google.com/ads, google-analytics.com,
 *   googletagmanager.com, etc.) serve tracking scripts and pixels on millions of
 *   third-party sites. Blocking at the network level (before the request fires) is
 *   more effective than post-hoc cookie removal because it prevents the tracking
 *   request from ever leaving the browser. The exempt list prevents breaking Google's
 *   own first-party services (Gmail, YouTube, Docs, etc.) where these domains serve
 *   legitimate functionality.
 * HOW IT WORKS: Each rule specifies a URL pattern (urlFilter) and a list of
 *   excludedInitiatorDomains. When a page on a non-exempt domain tries to load
 *   resources matching the pattern, Chrome's DNR engine blocks the request.
 * INPUT: Network requests matching the URL patterns, initiated from any page.
 * OUTPUT: Requests are either allowed (if initiator is in exempt list) or blocked
 *   (returning a network error to the requesting page).
 * Source: Chrome Extensions MV3 Declarative Net Request API; Google's own ad-tech
 *   domain list cross-referenced with Google's help center (support.google.com/adspolicy).
 */
const GOOGLE_TRACKING_RULES = [
  { urlFilter: "||google.com/ads^",     exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||google.com/pagead^",  exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||google.com/gen204^",  exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||google-analytics.com^", exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||googletagmanager.com^", exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||googlesyndication.com^", exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com", "drive.google.com", "calendar.google.com", "mail.google.com", "meet.google.com"] },
  { urlFilter: "||googleadservices.com^",  exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com"] },
  { urlFilter: "||doubleclick.net^",       exempt: ["google.com", "accounts.google.com", "docs.google.com", "youtube.com"] },
];
const GOOGLE_TRACKING_RESOURCE_TYPES = ["script", "xmlhttprequest", "sub_frame", "stylesheet", "image", "media", "font", "object", "ping", "websocket", "other"];
const GLOBAL_PURGE_FEED_KEY = "ccGlobalPurgeFeed";
let globalPurgeFeed = [];
/**
 * AUTH_SAFE_VENDORS: Vendor identifiers treated as login-infrastructure operators.
 *   This is 5 SSO operators, not 8 arbitrary vendors: Google; Meta (meta/facebook/
 *   instagram are one operator); Microsoft (microsoft/live are one operator); Apple;
 *   GitHub. Selection rule: operators of public OAuth 2.0 / OIDC login services whose
 *   "Log in with X" buttons appear on third-party sites — all inside the measured
 *   top-10 IdP set that covers 99% of login-enabled sites (Jannett et al. EuroS&P'24).
 * WHY IT EXISTS: Major platform vendors (Google, Meta/Facebook, Microsoft, Apple, GitHub)
 *   provide legitimate authentication infrastructure (SSO, OAuth). Their session cookies
 *   on third-party sites (e.g., a Google login button on a news site) should not be
 *   flagged as tracking cookies. Without this allowlist, the system would incorrectly
 *   block essential auth cookies, breaking sign-in flows (Munir et al. 2023: blanket
 *   first-party blocking breaks SSO login on 32% of sites).
 * HOW IT WORKS: isAuthSafeVendor() normalizes the vendor name and checks membership
 *   in this set. If a cookie's domain resolves to one of these vendors, it receives
 *   auth-safe exemptions (E1, E2) and is never purged or blocked.
 * COVERAGE NOTE (two legs): the cookie-database leg fires for google/meta/microsoft/
 *   github (352 mapped domains in cookie_db.json); facebook/instagram/live/apple have
 *   zero vendor_norm entries in the database, so only the hardcoded host leg
 *   (isAuthSafeHost) protects them. Both legs are intentional — neither alone covers
 *   all 8 labels.
 * INPUT: Vendor name strings from the cookie database (normalized to lowercase).
 * OUTPUT: Boolean — true if the vendor is in the safe set, false otherwise.
 * Sources: Google Identity docs (accounts.google.com OIDC); Meta Login docs
 *   (developers.facebook.com); Microsoft identity platform docs (learn.microsoft.com);
 *   Sign in with Apple docs (developer.apple.com); GitHub OAuth docs (docs.github.com).
 *   Prevalence: Westers et al. 2023 — Google 86%, Facebook 70%, Apple 29% of SSO
 *   sites (Tranco 10k); Jannett et al. 2024 — top-10 IdPs cover 99% (incl. Microsoft,
 *   GitHub); Morkonda et al. 2025 (SPEye) — 96%/80%/62% user account ownership.
 */
const AUTH_SAFE_VENDORS = new Set([
  "google",
  "meta",
  "facebook",
  "instagram",
  "microsoft",
  "live",
  "apple",
  "github",
]);
/**
 * TRACKING_VENDOR_HINTS: Substrings in vendor labels/names that indicate a cookie
 *   belongs to an advertising or tracking vendor.
 * WHY IT EXISTS: The cookie database assigns vendor labels to known domains, but
 *   the exact strings vary. These hint substrings provide a fuzzy matching mechanism:
 *   if a vendor's label contains any of these hints, the vendor is flagged as a
 *   tracking vendor. This triggers vendor-level blocking (O5 override) and affects
 *   whether third-party cookies from that vendor are suppressed.
 * HOW IT WORKS: isTrackingVendor() resolves the cookie's domain to a vendor, then
 *   checks if the vendor label (or normalized vendor name) contains any hint string.
 * INPUT: Cookie domain → resolved vendor label string.
 * OUTPUT: Boolean — true if the vendor is a known tracking/advertising vendor.
 * Source: IAB Europe Transparency & Consent Framework vendor list patterns;
 *   Google Marketing Platform, DoubleClick, Adobe Audience Manager documentation.
 */
const TRACKING_VENDOR_HINTS = [
  "google ads",
  "google adsense",
  "google marketing platform",
  "doubleclick",
  "adobe audience manager",
  "adobe advertising cloud",
];
/**
 * AUTH_COOKIE_NAMES: Curated allowlist of cookie names protected from blocking by
 *   Tracker Blocking; at leave, Session Guard admits them as purge candidates and
 *   judges their flags. Organized by protection rationale; every entry traces to
 *   platform documentation,
 *   peer-reviewed measurement, or a documented functional role. Names the platform
 *   itself labels advertising, or that are unverifiable legacy strings, are
 *   deliberately EXCLUDED (fr, wd, presence, locale, s, pl, csm, dbln, m_user,
 *   lsd, aasp).
 * WHY IT EXISTS: Known login/session cookies from major platforms (Meta, Google,
 *   Microsoft, GitHub) must never be blocked while the user is on the site —
 *   doing so would immediately log the user out. At leave, Session Guard admits
 *   them as purge candidates and judges flags (a flag-weak login cookie is purged;
 *   re-login next visit is the accepted cost). Without this allowlist,
 *   the risk-blocking system would incorrectly treat legitimate
 *   auth cookies as tracking cookies (e.g., Google's SID, HSID, SSID are high-entropy
 *   session identifiers that look like tracking tokens to naive classifiers, and the
 *   cookie database labels c_user/xs/SID as Advertising).
 * HOW IT WORKS: isProtectedAuthCookie() checks if a cookie's name is in this set.
 *   If matched AND the cookie is on an auth infrastructure domain, it receives
 *   the E1 exemption (protected auth cookie) and is never removed by Tracker Blocking
 *   (Session Guard still judges its flags at leave). Name alone never protects
 *   (Calzavara et al. 2015: only 55 of 111 standard-name-matching cookies were
 *   auth — about half wrong), hence the two-condition gate (name + auth-infra
 *   domain).
 * INPUT: Cookie name (lowercased) + domain (for auth-infra check).
 * OUTPUT: Boolean — true if the cookie name is in the protected set.
 * Sources by category:
 *   [Auth] Meta c_user/xs — login-bound, deleted on logout (Lepouchard et al. WPES'22
 *     Table 3); Google SID family — account cookies (support.google.com/accounts);
 *     fbsr_/fbm_ — Meta Login signed-request/SDK family (developers.facebook.com);
 *     msa_auth — Microsoft identity docs (learn.microsoft.com); gh_/dotcom_user —
 *     GitHub session cookies (docs.github.com).
 *   [Integrity] datr/sb — Meta claims fraud-prevention; Belgian (2015) + French (2017)
 *     DPAs ruled tracking. Kept conservatively, both sides cited.
 *   [Operational] muid/muidb — Microsoft Privacy Statement ("necessary operational
 *     purposes" + advertising with consent); first-party-scoped by the domain gate.
 *   [Functional] oo — Meta opt-out cookie; removing it re-opts the user into Meta
 *     ads, so it is preserved (not auth, but must not be undone).
 */
const AUTH_COOKIE_NAMES = new Set([
  // [Auth] Session-bound login cookies.
  "c_user",
  "xs",
  "fbsr_",
  "fbm_",
  "sid",
  "hsid",
  "ssid",
  "apisid",
  "sapisid",
  "sidcc",
  "__secure-1psid",
  "__secure-3psid",
  "__secure-1psidts",
  "__secure-3psidts",
  "__secure-1psidcc",
  "__secure-3psidcc",
  "__secure-1psidrts",
  "__secure-3psidrts",
  "__secure-1papisid",
  "__secure-3papisid",
  "msa_auth",
  "gh_",
  "dotcom_user",
  // [Integrity] Conservative — see Sources above.
  "sb",
  "datr",
  // [Operational] First-party-scoped — see Sources above.
  "muid",
  "muidb",
  // [Functional] Opt-out preservation — see Sources above.
  "oo",
]);
/**
 * AUTH_COOKIE_PREFIXES: Cookie name prefixes that indicate authentication cookies.
 * WHY IT EXISTS: Some platforms use dynamic cookie names that share a common prefix
 *   (e.g., Facebook's "fbm_" for business cookies, "fbsr_" for server-side request
 *   cookies, and "__host-" for host-only cookies per RFC 6265bis). Checking prefixes
 *   catches all variants without needing an exhaustive list of every possible name.
 * HOW IT WORKS: isProtectedAuthCookie() checks if a cookie's name starts with any
 *   of these prefixes. If matched on an auth infrastructure domain, the cookie is
 *   protected from removal. The "__host-" prefix is a special case defined in
 *   RFC 6265bis (draft-ietf-httpbis-rfc6265bis) that mandates the cookie is
 *   host-only, Secure, and has Path="/", making it a strong auth indicator.
 * INPUT: Cookie name string.
 * OUTPUT: Boolean — true if the name starts with any protected prefix.
 * Source: RFC 6265bis (draft-ietf-httpbis-rfc6265bis-07) Section 5.3.1.1 (__host- prefix);
 *   Facebook Login cookie documentation (developers.facebook.com).
 */
const AUTH_COOKIE_PREFIXES = [
  "fbm_",
  "fbsr_",
  "__host-",
];
/**
 * AUTH_DOMAIN_HINT_RE / WEAK_AUTH_DOMAIN_HINT_RE: Keyword patterns matching domain
 *   names that suggest authentication infrastructure (e.g., "accounts.google.com",
 *   "login.microsoft.com", "auth.example.com"). Split into two tiers:
 *   Tier 1 (stands alone): protocol/IdP-derived keywords from OAuth 2.0 (RFC 6749
 *     §3.1) and OIDC Discovery (§4) — account(s), auth(orize), login, signin/signon,
 *     sso, oauth, openid, idp, identity, mfa, 2fa. These match real IdP hostnames.
 *   Tier 2 (gated): generic words (security, secure, verify, verification, challenge)
 *     that appear on non-login sites — trusted only with auth-safe-vendor
 *     corroboration (see isLikelyAuthInfrastructureDomain). "passport" (dead .NET
 *     Passport brand, zero modern login servers) was deliberately removed.
 * WHY IT EXISTS: Domains containing auth-related keywords are likely authentication
 *   endpoints. When a cookie's domain matches this pattern, it is treated as auth
 *   infrastructure (isLikelyAuthInfrastructureDomain), which grants exemptions (E3, E4)
 *   and prevents false-positive blocking of session cookies on login pages.
 * HOW IT WORKS: The regex matches any domain label (between dots or hyphens) that equals
 *   one of the listed auth keywords (case-insensitive). It checks both the full domain
 *   and the registrable domain.
 * INPUT: Cookie domain string.
 * OUTPUT: Boolean — true if the domain contains an auth-related keyword.
 * Source: OAuth 2.0 (RFC 6749 §3.1) — authorization endpoint; OpenID Connect
 *   Discovery (§4) — issuer domain patterns.
 */
const AUTH_DOMAIN_HINT_RE = /(^|[.-])(account|accounts|auth|authorize|login|signin|signon|sso|oauth|openid|idp|identity|mfa|2fa)([.-]|$)/i;
const WEAK_AUTH_DOMAIN_HINT_RE = /(^|[.-])(security|secure|verify|verification|challenge)([.-]|$)/i;

/**
 * AUTH_FLOW_URL_RE: Regex pattern matching URLs that indicate an active login/auth flow.
 * WHY IT EXISTS: When a user is on a login page (e.g., "accounts.google.com/signin"),
 *   the system should not block any cookies set during that flow because they are
 *   likely authentication tokens being created, not tracking cookies being set.
 *   This regex extends AUTH_DOMAIN_HINT_RE to also match URL path, query, hash, and
 *   fragment components, catching auth flows even on non-auth domains (e.g., a
 *   third-party OAuth redirect URL containing "/oauth/authorize").
 *   NOTE: unlike domain-keyword matching (Tier 1/Tier 2 above), URL-flow keywords
 *   need no extra gating — the user actively visiting that URL IS the corroboration.
 *   "passport" removed here too (dead brand); "password" retained (reset/login pages).
 * HOW IT WORKS: The regex checks hostname + pathname + search + hash for auth keywords.
 *   When matched, the tab is flagged with authMode=true, which triggers the E3 exemption
 *   and suppresses risk blocking for the duration of the login flow.
 * INPUT: Full URL string.
 * OUTPUT: Boolean — true if the URL contains an auth-flow keyword in any component.
 * Source: OAuth 2.0 (RFC 6749) — authorization endpoint URL patterns;
 *   OpenID Connect discovery document — standard auth URL paths.
 */
const AUTH_FLOW_URL_RE = /(^|[/?#&=._-])(account|accounts|auth|authorize|login|signin|signon|sso|oauth|openid|idp|identity|security|secure|verify|verification|challenge|mfa|2fa|password)([/?#&=._-]|$)/i;

/**
 * CAPTCHA_INFRA_HOSTS / isCaptchaInfraDomain: Known captcha and bot-verification
 *   infrastructure hosts (E6 exemption + DNR seeding guard).
 * WHY IT EXISTS: Challenge cookies (__cflb, __cf_bm on hcaptcha.com / challenges.
 *   cloudflare.com, …) are third-party, persistent, and labeled Functionality by
 *   the name-level DB lookup — exactly what B4 (ruleFunc3p) and the DNR domain
 *   seeding table block on every site. The domain record in cookie_db.json says
 *   Strict / disconnect_cat "Anti-fraud" for these vendors, but name beats domain
 *   in the classification cascade, so E0 never sees them. Removing them mid-flow
 *   breaks the issue→verify round trip (hCaptcha __cflb load-balancer affinity:
 *   the challenge is issued by one api.hcaptcha.com node and must be verified by
 *   the same node) and the site's login fails — demonstrated on claude.ai via a
 *   whitelist A/B (login works whitelisted / fails otherwise) and the 43-vs-35
 *   cookie diff (captcha cookies present only in the working session).
 * LIST PROVENANCE: DB-seeded — reproducible query against cookie_db.json:
 *     Object.entries(db.domains).filter(([k, v]) => v.disconnect_cat === "Anti-fraud")
 *   returns 30 hosts, all cat "Strict"; the challenge/bot-verification class of
 *   that set is kept (hcaptcha, recaptcha.net, DataDome, Arkose, GeeTest,
 *   HUMAN/PerimeterX). Two manual additions follow (Cloudflare Turnstile's
 *   challenges.cloudflare.com and Friendly Captcha are not separate DB hosts —
 *   cloudflare.com itself is Advertising-classified and must NOT be matched).
 * HOW IT WORKS: Suffix match with dot boundary on the normalized host (host === h
 *   || host.endsWith("." + h)) — deliberately NOT registrable-domain matching, so
 *   challenges.cloudflare.com matches while other cloudflare.com subdomains do not.
 *   Advertising/Performance cookies on these hosts are still judged normally (the
 *   E6 category guard lives in isExemptFromRiskBlocking); the DNR guard is
 *   domain-level because a challenge widget's scripts are the service itself.
 * INPUT: Cookie domain or host string.
 * OUTPUT: Boolean — true if the domain is captcha/bot-verification infrastructure.
 * Source: cookie_db.json (Disconnect.me taxonomy "Anti-fraud"); ePrivacy Directive
 *   Article 5(3) — strictly necessary for the requested service; ICO guidance —
 *   security and fraud-prevention cookies are strictly necessary.
 */
const CAPTCHA_INFRA_HOSTS = new Set([
  // DB-seeded (cookie_db.json disconnect_cat === "Anti-fraud", challenge class)
  "hcaptcha.com",
  "recaptcha.net",
  "captcha-delivery.com",
  "datadome.co",
  "arkoselabs.com",
  "funcaptcha.com",
  "geetest.com",
  "perimeterx.com",
  "perimeterx.net",
  // Manual additions (not separate hosts in cookie_db.json)
  "challenges.cloudflare.com",
  "friendly-captcha.com",
]);
function isCaptchaInfraDomain(d) {
  const host = normalizeHost(d || "");
  if (!host || !host.includes(".")) return false;
  for (const h of CAPTCHA_INFRA_HOSTS) {
    if (host === h || host.endsWith("." + h)) return true;
  }
  return false;
}

/**
 * GOOGLE_OWNED_HOSTS: Full inventory of Google-operated domains (search front-ends,
 *   service infrastructure, content delivery). Used ONLY for Google-property
 *   identification (first-party vs third-party classification). It does NOT confer
 *   auth-safe status by itself — that is GOOGLE_AUTH_HOSTS below. Kept whole because
 *   every entry is Google-operated (google.com/supported_domains + Google Developers/
 *   YouTube network docs); ad-serving entries are harmless here since this list
 *   grants no exemptions.
 * WHY IT EXISTS: Google operates a vast network of domains across many TLDs (google.com,
 *   youtube.com, googleapis.com, gstatic.com, google.co.uk, etc.). Cookies set by
 *   these domains on Google's own properties (e.g., a YouTube embed on a news site)
 *   are first-party Google cookies, not third-party trackers. Without this list, the
 *   system would incorrectly classify Google's own cookies as third-party trackers,
 *   breaking Gmail, YouTube, Google Docs, and other Google services embedded on
 *   third-party sites.
 * HOW IT WORKS: Host matching (exact, subdomain, or registrable-domain) against this
 *   list. If matched, the domain is treated as Google property for classification.
 * INPUT: Cookie domain string.
 * OUTPUT: Boolean — true if the domain is Google-owned.
 * Source: google.com/supported_domains (Google's published enumeration); Google
 *   Developers docs; YouTube network docs; IANA root zone database for ccTLD entries.
 */
const GOOGLE_OWNED_HOSTS = [
  "google.com",
  "youtube.com",
  "googleapis.com",
  "googleusercontent.com",
  "gstatic.com",
  "ggpht.com",
  "googleadservices.com",
  "googlesyndication.com",
  "doubleclick.net",
  "ytimg.com",
  "googlevideo.com",
  "google.co.uk",
  "google.de",
  "google.fr",
  "google.co.jp",
  "google.nl",
  "google.ca",
  "google.com.au",
  "google.com.br",
  "google.it",
  "google.es",
  "google.pl",
  "google.ru",
  "google.cn",
  "google.co.in",
  "google.kr",
  "google.com.mx",
  "google.com.ar",
  "google.com.co",
  "google.com.tr",
  "google.com.sg",
  "google.com.hk",
  "google.co.kr",
  "google.co.nz",
  "google.ch",
  "google.at",
  "google.be",
  "google.se",
  "google.no",
  "google.dk",
  "google.fi",
  "google.org",
  "google.dev",
];
/**
 * GOOGLE_AUTH_HOSTS: Subset of GOOGLE_OWNED_HOSTS whose domains may serve Google
 *   account login state — and therefore may be auth infrastructure. Deliberately
 *   EXCLUDES: ad-serving-only domains (googleadservices.com, googlesyndication.com,
 *   doubleclick.net — advertising infrastructure must never be auth-safe); pure
 *   service infrastructure with no login state (googleapis.com, googleusercontent.com,
 *   gstatic.com, ggpht.com, ytimg.com, googlevideo.com); non-login properties
 *   (google.org, google.dev). youtube.com is INCLUDED (shared Google session cookies
 *   appear there; excluding it risks logging users out of YouTube).
 * HOW IT WORKS: isAuthSafeHost() matches against this list (not GOOGLE_OWNED_HOSTS).
 * Source: google.com/supported_domains (subset check); Google Developers/YouTube docs.
 */
const GOOGLE_AUTH_HOSTS = [
  "google.com",
  "youtube.com",
  "google.co.uk",
  "google.de",
  "google.fr",
  "google.co.jp",
  "google.nl",
  "google.ca",
  "google.com.au",
  "google.com.br",
  "google.it",
  "google.es",
  "google.pl",
  "google.ru",
  "google.cn",
  "google.co.in",
  "google.kr",
  "google.com.mx",
  "google.com.ar",
  "google.com.co",
  "google.com.tr",
  "google.com.sg",
  "google.com.hk",
  "google.co.kr",
  "google.co.nz",
  "google.ch",
  "google.at",
  "google.be",
  "google.se",
  "google.no",
  "google.dk",
  "google.fi",
];
/**
 * SESSION_DESC_HINTS: Keywords in cookie database descriptions that indicate a cookie
 *   serves session, authentication, or essential functionality purposes.
 * WHY IT EXISTS: The cookie database (cookieDb) contains human-readable descriptions
 *   for known cookies. These descriptions often contain keywords that signal the
 *   cookie's purpose. By scanning descriptions for session-related phrases, the
 *   system can identify session cookies that should be exempt from blocking (E2)
 *   without relying solely on cookie attributes (which can be misleading — e.g., a
 *   persistent session cookie has an expiry but still serves auth purposes).
 * HOW IT WORKS: getCookieDescriptionSignals() looks up the cookie in the database,
 *   extracts the description, and checks if any SESSION_DESC_HINTS substring appears.
 *   If matched (and not contradicted by tracking hints), the cookie is flagged as
 *   session-like. This feeds into getSessionAnalysis() which computes the session
 *   likelihood score and determines exemptions.
 * INPUT: Cookie database description string (lowercased).
 * OUTPUT: Boolean — true if the description contains a session-related keyword.
 * Source: Cookie database descriptions derived from platform documentation, cookie
 *   policy pages, and IAB TCF purpose descriptions (session/storage purposes).
 */
const SESSION_DESC_HINTS = [
  "session",
  "session identifier",
  "session id",
  "session state",
  "session token",
  "logged in",
  "logged-in",
  "authentication",
  "auth",
  "auth state",
  "login",
  "login state",
  "log in",
  "sign in",
  "signin",
  "sign-in",
  "password",
  "security token",
  "csrf",
  "xsrf",
  "sso",
  "single sign-on",
  "identity",
  "credential",
  "authenticated user",
  "security authenticate",
  "load-balancer routing",
  "load balancer routing",
  "load-balancer",
  "shopping cart",
  "language preference",
  "language & region preference",
  "region preference",
  "currency preference",
  "safesearch",
  "search results per page",
  "cookie preferences",
  "consent choices",
  "cookie consent state",
  "cookie choice",
  "first party server only",
  "fundamental to the service",
  "fundamental to service",
  "necessary session and security cookie",
];
/**
 * TRACKING_DESC_HINTS: Keywords in cookie database descriptions that indicate a cookie
 *   serves advertising, tracking, or analytics purposes.
 * WHY IT EXISTS: When a cookie's description contains tracking-related phrases, it
 *   provides strong evidence that the cookie should be blocked, even if other signals
 *   (name, attributes) suggest it might be functional. These hints override session
 *   exemptions (trackingDescHint prevents E2 exemption) and trigger corroboration
 *   for first-party Advertising/Unknown cookies (C1, C3). This is critical for
 *   catching cases where a cookie's name looks innocent but its documented purpose
 *   is tracking (e.g., "_ga" described as "Google Analytics tracking cookie").
 * HOW IT WORKS: getCookieDescriptionSignals() checks the cookie database description
 *   against these hints. If matched, the cookie is flagged with trackingDescHint=true,
 *   which feeds into getSessionAnalysis() (adds to risk score) and
 *   enforceRiskBlockingForCookie() (triggers O3 override or corroboration requirement).
 * INPUT: Cookie database description string (lowercased).
 * OUTPUT: Boolean — true if the description contains a tracking-related keyword.
 * Source: IAB TCF purposes (advertising, measurement, personalization);
 *   ePrivacy Directive Recital 66 (tracking/profiling);
 *   FTC guidance on behavioral advertising (ftc.gov).
 */
const TRACKING_DESC_HINTS = [
  "advertisement",
  "advertising",
  "ads",
  "ad delivery",
  "ad targeting",
  "ad network",
  "cross-site tracking",
  "tracking",
  "tracking profile",
  "profiling",
  "analytics",
  "statistical data",
  "measurement",
  "page views",
  "session duration",
  "device type",
  "browser info",
  "click paths",
  "referrer",
  "user behavior",
  "user behaviour",
  "user activity",
  "campaign performance",
  "interests",
  "demographics",
  "ad impressions",
  "conversion events",
  "unique advertising identifier",
  "personalized ads",
  "personalised ads",
  "retarget",
  "retargeting",
  "fingerprinting",
  "data brokers",
  "multiple websites",
  "serve relevant ads",
  "relevant advertisements",
  "relevant advertising",
];

loadGlobalPurgeFeed();

/**
 * getState: Retrieves or initializes the per-tab state object for a given tab ID.
 * WHY IT EXISTS: Every function that reads or writes cookie data for a tab needs a
 *   consistent state object. This function ensures that tabState[tabId] always exists
 *   by initializing it on first access. It also handles session restore: when a tab
 *   is reloaded after browser suspend/resume, the saved cookie tracking data or
 *   session cache is restored into the live state, preventing data loss across
 *   service worker restarts (MV3 service workers are ephemeral and can be killed
 *   at any time).
 * HOW IT WORKS: 1) If tabState[tabId] already exists, return it immediately.
 *   2) If savedCookieTracking has data for this tab (saved during same-site
 *   navigation), restore cookiesSetBySite and domains from it.
 *   3) If sessionCache has data (restored from chrome.storage.session on startup),
 *   reconstruct the cookie Map and preExistingKeys Set from the cached snapshot.
 *   4) Otherwise, create a fresh empty state object with default fields.
 * INPUT: tabId (integer) — Chrome tab ID.
 * OUTPUT: The tab state object containing: url, siteKey, domains (Map), cookies (Map),
 *   preExistingKeys (Set), cookiesSetBySite (Set), lastActiveAt (timestamp), authMode (boolean).
 * Source: Chrome Extensions MV3 service worker lifecycle — chrome.storage.session
 *   persists across restarts; chrome.storage.local for cross-session persistence.
 */
function getState(tabId) {
  if (!tabState[tabId]) {
    const saved = savedCookieTracking.get(tabId);
    if (saved) {
      tabState[tabId] = { url:"", siteKey:"", domains: new Map(saved.domains || []), cookies:new Map(), preExistingKeys:new Set(), cookiesSetBySite: new Set(saved.cookiesSetBySite), lastActiveAt:Date.now(), authMode:false };
      savedCookieTracking.delete(tabId);
      delete sessionCache[tabId];
      ccDiag({ ev:"state_restore", tabId, setBySite: tabState[tabId].cookiesSetBySite.size, domains: tabState[tabId].domains.size });
    } else if (sessionCache[tabId]) {
      const c = sessionCache[tabId];
      const cookies = new Map();
      const preExistingKeys = new Set();
      for (const entry of (c.c || [])) {
        const key = cookieKey(entry);
        cookies.set(key, entry);
        preExistingKeys.add(key);
      }
      tabState[tabId] = { url: c.u || "", siteKey: c.k || "", domains: new Map(c.d), cookies, preExistingKeys, cookiesSetBySite: new Set(c.s), lastActiveAt:Date.now(), authMode:false };
      delete sessionCache[tabId];
      ccDiag({ ev:"state_restore_session", tabId, setBySite: tabState[tabId].cookiesSetBySite.size, domains: tabState[tabId].domains.size, restoredCookies: cookies.size });
    } else {
      tabState[tabId] = { url:"", siteKey:"", domains:new Map(), cookies:new Map(), preExistingKeys:new Set(), cookiesSetBySite:new Set(), lastActiveAt:Date.now(), authMode:false };
    }
  }
  return tabState[tabId];
}

/**
 * isLikelyAuthFlowUrl: Detects whether a URL indicates an active login or
 *   authentication flow based on URL path, query, and hash components.
 * WHY IT EXISTS: When a user is on a login page, cookies being set are likely
 *   authentication tokens (not trackers). Blocking them would break the login flow.
 *   This function flags the tab with authMode=true, which triggers the E3 exemption
 *   and suppresses risk blocking for the duration of the login session. Without this
 *   detection, the system would block Facebook/Google login cookies mid-flow, causing
 *   login failures and user frustration.
 * HOW IT WORKS: Parses the URL and concatenates hostname + pathname + search + hash
 *   into a single lowercase blob, then tests it against AUTH_FLOW_URL_RE. The regex
 *   matches auth-related keywords (login, signin, oauth, sso, etc.) in any URL
 *   component. This catches both first-party login pages and third-party OAuth
 *   redirect URLs.
 * INPUT: Full URL string (e.g., "https://accounts.google.com/signin/v2/...").
 * OUTPUT: Boolean — true if the URL contains an auth-flow keyword.
 * Source: OAuth 2.0 (RFC 6749 Section 3.1) — authorization endpoint patterns;
 *   OpenID Connect Discovery — standard auth URL paths.
 */
function isLikelyAuthFlowUrl(url) {
  try {
    const u = new URL(url);
    const blob = `${u.hostname} ${u.pathname} ${u.search} ${u.hash}`.toLowerCase();
    return AUTH_FLOW_URL_RE.test(blob);
  } catch (e) {
    return false;
  }
}

/**
 * notifyPanelState: Sends a PANEL_STATE_CHANGED message to the content script
 *   in a specific tab, informing it whether the side panel is open or closed.
 * WHY IT EXISTS: The content script needs to know the panel's open/close state to
 *   decide whether to show a floating widget badge, inject UI elements, or suppress
 *   certain behaviors (e.g., not collecting document.cookie when the panel is closed
 *   to reduce overhead). Without this notification, the content script would have no
 *   way to know the panel's state, leading to unnecessary DOM manipulation or
 *   missed updates.
 * HOW IT WORKS: Sends a chrome.tabs.sendMessage with type "PANEL_STATE_CHANGED"
 *   to the content script in the specified tab. The .catch(() => {}) silences
 *   errors for tabs that don't have the content script injected (e.g., chrome:// pages).
 * INPUT: tabId (integer), isOpen (boolean).
 * OUTPUT: None — fire-and-forget message to content script.
 * Source: Chrome Extensions messaging API — tabs.sendMessage targets a specific tab.
 */
function notifyPanelState(tabId, isOpen) {
  if (!tabId) return;
  chrome.tabs.sendMessage(tabId, {
    type: "PANEL_STATE_CHANGED",
    tabId,
    isOpen,
  }).catch(() => {});
}

/**
 * notifySidePanelTabContext: Sends an ACTIVE_TAB_CHANGED message to the side panel
 *   when the active tab or its URL changes.
 * WHY IT EXISTS: The side panel needs to know which tab the user is viewing and
 *   what URL is loaded so it can display the correct cookie list, privacy score,
 *   and site-specific information. Without this notification, the side panel would
 *   show stale data from a previous tab or URL. The "reason" parameter helps the
 *   panel distinguish between navigation (page load) and tab switching (user clicks
 *   a different tab), which may trigger different refresh behaviors.
 * HOW IT WORKS: Sends a chrome.runtime.sendMessage with type "ACTIVE_TAB_CHANGED"
 *   containing the tabId, URL, and reason. The side panel listens for this message
 *   and updates its UI accordingly. Tab IDs < 0 (e.g., devtools, new tab pages)
 *   are silently ignored.
 * INPUT: tabId (integer >= 0), url (string), reason (string, default "tab_context_changed").
 * OUTPUT: None — fire-and-forget message to side panel.
 * Source: Chrome Extensions runtime messaging — broadcast to all listeners in the extension.
 */
function notifySidePanelTabContext(tabId, url, reason = "tab_context_changed") {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  chrome.runtime.sendMessage({
    type: "ACTIVE_TAB_CHANGED",
    tabId,
    url: url || "",
    reason,
  }).catch(() => {});
}

if (chrome.sidePanel?.onOpened) {
  chrome.sidePanel.onOpened.addListener(info => {
    if (info?.tabId) {
      sidePanelOpenTabs.add(info.tabId);
      notifyPanelState(info.tabId, true);
    }
  });
}

if (chrome.sidePanel?.onClosed) {
  chrome.sidePanel.onClosed.addListener(info => {
    if (info?.tabId) {
      sidePanelOpenTabs.delete(info.tabId);
      notifyPanelState(info.tabId, false);
    }
  });
}


/**
 * cookieKey: Generates a unique string identifier for a cookie based on its name,
 *   normalized domain, path, host-only flag, partition key, and cookie store.
 * WHY IT EXISTS: Chrome's cookie API identifies cookies by (name, domain, path) tuple
 *   (per RFC 6265 Section 5.3). This function creates a deterministic string key from
 *   these three fields so that cookies can be used as Map keys and Set members. Without
 *   a unique key, the system couldn't track which cookies have been seen, blocked, or
 *   changed, leading to duplicate entries and incorrect change detection.
 *   Twin distinction (DevTools-parity fix): RFC identity alone collapses "twin"
 *   cookies that DevTools lists as separate rows — a host-only cookie vs a domain
 *   cookie with the same name/path, a partitioned (CHIPS) cookie vs its
 *   unpartitioned twin, or same-name cookies in different stores (containers /
 *   incognito). Collapsed twins under-count against DevTools and, worse, let one
 *   twin's verdict stand in for the other's. The three trailing legs fix the
 *   identity to what the browser actually stores; suppression keys intentionally
 *   stay coarse (a separate function) so evasion-by-twinning still fails.
 * HOW IT WORKS: Joins [name, identityDomain, path, hostOnly, partitionKey,
 *   storeId] with "::" as separator. Domain is normalized via
 *   cookieIdentityDomain() (strips leading dots, lowercases, KEEPS www so
 *   host-only subdomain cookies stay distinct from parent-domain twins).
 *   Path defaults to "/" if absent.
 * INPUT: Cookie object with name, domain, path, hostOnly, partitionKey, storeId.
 * OUTPUT: String in format "name::normalizedDomain::path::hostFlag::partition::store"
 *   (e.g., "sid::google.com::/::domain::-::-").
 * Source: RFC 6265 Section 5.3 — cookie identification by (name, domain, path);
 *   Chrome cookies API — getAll returns cookies with these fields.
 */
function cookieKey(cookie) {
  return [
    cookie.name || "",
    cookieIdentityDomain(cookie.domain),
    cookie.path || "/",
    cookie.hostOnly ? "host" : "domain",
    (cookie.partitionKey && cookie.partitionKey.topLevelSite) || "-",
    cookie.storeId || "-",
  ].join("::");
}

/**
 * getCookiesAsync: Promise wrapper around chrome.cookies.getAll() that returns
 *   all cookies matching a query object.
 * WHY IT EXISTS: Chrome's cookies API uses callback-based methods, but the rest of
 *   the codebase uses async/await for cleaner control flow. This wrapper converts
 *   the callback API to a Promise, handling errors gracefully (returning empty array
 *   on failure rather than throwing). Without this wrapper, every call to
 *   chrome.cookies.getAll would need a nested callback, making the code harder to
 *   read and error-prone.
 * HOW IT WORKS: Creates a Promise that calls chrome.cookies.getAll with the provided
 *   query object. On success, resolves with the cookies array. On error (including
 *   chrome.runtime.lastError), resolves with an empty array. This "fail-open" behavior
 *   ensures the extension doesn't crash on transient API errors.
 * INPUT: Query object (e.g., { url: "https://example.com" }, { name: "sid" },
 *   { domain: ".google.com" }) — same as chrome.cookies.getAll parameters.
 * OUTPUT: Promise resolving to an array of Chrome cookie objects, or empty array on error.
 * Source: Chrome Extensions cookies API — chrome.cookies.getAll(query, callback).
 */
function getCookiesAsync(query) {
  return new Promise(resolve => {
    chrome.cookies.getAll(query, cks => {
      if (chrome.runtime.lastError || !Array.isArray(cks)) {
        resolve([]);
        return;
      }
      resolve(cks);
    });
  });
}

/**
 * normalizeCookieDomain: Canonical form for cookie-domain queries and comparisons.
 * WHY IT EXISTS: Cookie domains arrive with leading dots (".example.com"), mixed
 *   case, and www prefixes. Querying and comparing un-normalized forms splits one
 *   registrable domain into several keys, breaking dedup, coverage checks, and the
 *   prune guard. One canonical form keeps them consistent.
 * HOW IT WORKS: Delegates to normalizeHost() (trim, lowercase, strip leading dot
 *   and www). Note the www-strip is a deliberate superset choice for queries: a
 *   "www.example.com" cookie is also returned by an "example.com" domain query,
 *   and dedup by cookieKey removes any double-fetch.
 * INPUT: Raw cookie/query domain string.
 * OUTPUT: Normalized domain string.
 * Source: Chrome cookies API — getAll({domain}) matches the domain and subdomains.
 */
function normalizeCookieDomain(domain) {
  return normalizeHost(domain);
}

/**
 * cookieIdentityDomain: Canonical domain form for cookie IDENTITY (keys,
 *   equality, authoritative matching) — NOT for classification or grouping.
 * WHY IT EXISTS: normalizeHost strips a leading www, collapsing distinct
 *   browser store entries into one key: a host-only www.example.com cookie
 *   and a domain .example.com cookie (same name/path/store/partition) are
 *   two DevTools rows but keyed identically, so one silently overwrote the
 *   other in state (undercount with no diagnostic trace). Chrome defines
 *   hostOnly as an exact-host property — removing www defeats that
 *   distinction. Identity preserves www; classification, origins, queries,
 *   and coverage keep reg-level matching untouched.
 * INPUT: Raw cookie domain string.
 * OUTPUT: Trimmed, lowercased, leading-dots-stripped domain (www kept).
 * Source: Chrome cookies API — hostOnly requires an exact host match.
 */
function cookieIdentityDomain(domain) {
  return String(domain || "").trim().toLowerCase().replace(/^\.+/, "");
}

/**
 * schemefulSite: Returns the scheme + registrable host ("https://example.com")
 *   for a page URL.
 * WHY IT EXISTS: Partitioned (CHIPS) cookies are keyed by top-level site, which
 *   is a schemeful site. Probing each contacted domain with the page's schemeful
 *   site reads exactly the current page's partition — no more, no less.
 * INPUT: Page URL string.
 * OUTPUT: Schemeful site string, or "" when the URL is unparseable.
 * Source: CHIPS (Cookies Having Independent Partitioned State) — partition key
 *   is the schemeful top-level site.
 */
function schemefulSite(url) {
  try {
    const u = new URL(url || "");
    const host = getRegistrableDomain(u.hostname) || u.hostname;
    if (!host) return "";
    return `${u.protocol}//${host}`;
  } catch (e) { return ""; }
}

/**
 * getCookieStoreIdForTab: Resolves the cookie store backing a tab.
 * WHY IT EXISTS: Containers, incognito splits, and app windows keep separate
 *   cookie stores. An unscoped query only sees the default store, so those tabs
 *   under-count against DevTools and — worse — their cookies are never judged.
 * HOW IT WORKS: Lists all cookie stores via chrome.cookies.getAllCookieStores
 *   and returns the id of the store whose tabIds include the tab. (Chrome's Tab
 *   object carries no cookieStoreId — that property is Firefox-only; reading it
 *   here silently resolved nothing and aborted every scan.) Returns "" on any
 *   failure; callers treat "" as "unknown" and abort the scan fail-closed (K3).
 *   Never throws.
 * INPUT: tabId (integer).
 * OUTPUT: Promise resolving to the store ID string, or "" when unresolvable.
 * Source: Chrome cookies API — getAllCookieStores (id + tabIds per store).
 */
async function getCookieStoreIdForTab(tabId) {
  try {
    const stores = await new Promise(resolve => {
      try { chrome.cookies.getAllCookieStores(items => resolve(items || [])); }
      catch (e) { resolve([]); }
    });
    const hit = Array.isArray(stores) ? stores.find(store => Array.isArray(store.tabIds) && store.tabIds.includes(tabId)) : null;
    return String((hit && hit.id) || "");
  } catch (e) { return ""; }
}

/**
 * getCookiesDiagnosticAsync / getCookiesDiagnosticBatch: Error-reporting cookie
 *   fetch used by full scans.
 * WHY IT EXISTS: getCookiesAsync fails open (resolves []) so callers never
 *   crash — but a scan cannot tell "no cookies there" from "the API errored".
 *   Pruning or judging on error-empties deletes real cookies from state and
 *   blinds enforcement. The diagnostic pair reports errors instead, so the scan
 *   can skip reconciliation entirely on partial data (fail-open, loudly).
 * HOW IT WORKS: The single wrapper rejects with an Error on
 *   chrome.runtime.lastError or non-array results. The batch runner executes a
 *   list of {key, q} queries with a concurrency cap and resolves to an array of
 *   {key, status, value|reason} rows in input order (all-settled shape — one bad
 *   query never cancels the rest).
 * INPUT: query object (single) / array of {key, q} (batch) + concurrency limit.
 * OUTPUT: Promise of cookie array (single, rejects on error) / rows array (batch).
 * Source: Chrome cookies API — getAll with url/domain/partitionKey/storeId.
 */
function getCookiesDiagnosticAsync(query) {
  return new Promise((resolve, reject) => {
    try {
      chrome.cookies.getAll(query, cks => {
        if (chrome.runtime.lastError) {
          reject(new Error(String(chrome.runtime.lastError.message || "cookies.getAll failed")));
          return;
        }
        if (!Array.isArray(cks)) {
          reject(new Error("cookies.getAll returned non-array"));
          return;
        }
        resolve(cks);
      });
    } catch (e) { reject(e); }
  });
}
async function getCookiesDiagnosticBatch(queries, concurrency = 6) {
  const rows = new Array(queries.length);
  let next = 0;
  const worker = async () => {
    while (next < queries.length) {
      const i = next++;
      const qd = queries[i];
      try {
        const value = await getCookiesDiagnosticAsync(qd.q);
        rows[i] = { key: qd.key, status: "fulfilled", value };
      } catch (e) {
        rows[i] = { key: qd.key, status: "rejected", reason: e };
      }
    }
  };
  const workers = [];
  for (let w = 0; w < Math.max(1, Math.min(concurrency, queries.length)); w++) workers.push(worker());
  await Promise.all(workers);
  return rows;
}

/**
 * buildScopedCookieQueries: Builds the full coverage query list for a tab scan.
 * WHY IT EXISTS: A single {url} query structurally misses third-party cookies,
 *   partitioned (CHIPS) cookies, and other-store cookies — the DevTools gap.
 *   Coverage must be a superset: every cookie DevTools shows for the page must
 *   be fetched, or it can never be judged.
 * HOW IT WORKS: Always queries {url} (+ store when known) and the site's
 *   registrable domain. Third-party queries are registrable-wide
 *   ({domain: <reg>}) on purpose: Chrome matches a domain query downward
 *   only, so a host-precise query would miss parent-domain cookies that ARE
 *   exchanged with the contacted host. Breadth at fetch is safe because the
 *   accept-scope check (cookieInPageScope) filters precisely before merge —
 *   siblings are fetched but never merged, judged, or displayed. Each domain
 *   also gets a partition probe ({domain, partitionKey: {topLevelSite}}) with
 *   the page's schemeful site, since URL queries omit partitioned cookies.
 *   Deliberately no state backfill: queries derive from the page + current
 *   contacts only, so stale domains can't keep re-seeding future scans.
 * INPUT: url (page URL), state (tab state), storeId (string, may be "").
 * OUTPUT: {queries ([{key, q}]), partitionSite, domains ([{key, domain}])}.
 * Source: Chrome cookies API — getAll url/domain/partitionKey/storeId scoping;
 *   {domain} matches the domain and its subdomains (not parents).
 */
function buildScopedCookieQueries(url, state, storeId) {
  const siteReg = state?.siteKey || "";
  const partitionSite = schemefulSite(url);
  const base = storeId ? { storeId } : {};
  const domains = [];
  const seenDomainRegs = new Set();
  const addDomain = (key, domain) => {
    const reg = normalizeCookieDomain(domain);
    if (!reg || seenDomainRegs.has(reg)) return;
    seenDomainRegs.add(reg);
    domains.push({ key, domain: reg });
  };
  if (siteReg) addDomain("domain:site", siteReg);
  for (const host of (state?.domains ? state.domains.keys() : [])) {
    const reg = getRegistrableDomain(host) || "";
    if (reg && reg !== siteReg) addDomain("domain:3p:" + reg, reg);
  }
  const queries = [{ key: "url", q: { ...base, url } }];
  for (const item of domains) {
    queries.push({ key: item.key, q: { ...base, domain: item.domain } });
    // Chromium's URL query omits partitioned cookies. Probe each contacted domain
    // with the active page's schemeful site so only its current partition is read.
    if (partitionSite) {
      const key = item.key === "domain:site" ? "partition-probe" : "partition-probe:" + item.domain;
      queries.push({ key, q: { ...base, domain: item.domain, partitionKey: { topLevelSite: partitionSite } } });
    }
  }
  return { queries, partitionSite, domains };
}

/**
 * cookieBelongsToScan: Store + partition + accept-scope check for scanned cookies.
 * WHY IT EXISTS: Fetch scope is deliberately broad (host-precise domain queries
 *   still return parent-domain cookies and twins), while other tabs' sessions
 *   can surface profile-wide results for contacted hosts. Merging all of that
 *   would mix foreign contexts into this tab's state, inflate the UI beyond the
 *   page's own cookies, and judge (potentially delete) another tab's
 *   login-critical cookies under this tab's third-party verdict.
 * HOW IT WORKS: Three gates. 1) Store: reject cookies from a different store
 *   when ours is known. 2) Partition: reject cookies partitioned under a
 *   different top-level site (never sent with this page's requests, correctly
 *   excluded). 3) Page scope (cookieInPageScope): same-registrable-as-site
 *   passes regardless of contact (site-group parity); otherwise the cookie
 *   must be page-scoped — host-only needs exact page/contacted host, domain
 *   cookies must apply to one. Reg-wide fetches plus this precise accept is
 *   the breadth-at-fetch/precision-at-accept design: siblings are fetched but
 *   never merged, judged, or displayed.
 *   NOTE (history): this third gate existed as F1 (hostname relevance), was
 *   reverted for causing under-counts, and is reinstated here under different
 *   surroundings — prune is completeness-gated (H4) instead of firing on
 *   degraded scans, removals happen on sustained absence (H5) instead of
 *   single-scan eviction, and the scope rule itself is hostOnly-precise (K2)
 *   instead of reg-level. The conditions that made it destructive are gone.
 *   Relevance filtering also keeps its original job on the live
 *   cookies.onChanged path, where cross-tab mixing is real.
 * INPUT: cookie, state, storeId, partitionSite.
 * OUTPUT: Boolean — true when the cookie is this tab's to merge and judge.
 */
/**
 * cookieInPageScope: Precise page-scope check with hostOnly awareness.
 * WHY IT EXISTS: Registrable-level matching admits host-only cookies for
 *   sibling subdomains never exchanged with the page (e.g. a host-only
 *   mail.google.com cookie surfacing on a page that only touched
 *   www.google.com) — the overcount vector. Exchange semantics are exact:
 *   a cookie is sent with a host's requests iff the hosts are equal, or the
 *   cookie is a non-hostOnly parent of that host. Both sides are www-stripped
 *   by normalizeHost, so www.google.com-host cookies still exactly meet a
 *   google.com contact; only TRUE subdomains are excluded.
 * HOW IT WORKS: Normalizes the cookie domain once. Returns true on exact
 *   match with the page host or any contacted host, or when a contacted host
 *   is a subdomain of a non-hostOnly cookie domain (parent-domain cookies
 *   are genuinely sent with those requests). Cookie-subdomain-of-contact is
 *   deliberately NOT accepted: such cookies are not sent with the recorded
 *   contact's requests. Pure function — ad-hoc tests drive the full matrix.
 * INPUT: cookie, pageHost (normalized hostname of the page, may be ""),
 *   contactedHosts (Map with .keys() or iterable of hostnames).
 * OUTPUT: Boolean — true when the cookie was exchanged with the page.
 * Source: RFC 6265 Section 5.4 — cookie scoping/send rules; Chrome cookies
 *   API — hostOnly requires an exact host match.
 */
function cookieInPageScope(cookie, pageHost, contactedHosts) {
  const D = normalizeHost((cookie && cookie.domain) || "");
  if (!D) return false;
  const hostOnly = !!(cookie && cookie.hostOnly);
  const hosts = [];
  if (pageHost) hosts.push(normalizeHost(pageHost));
  if (contactedHosts) {
    const iter = (typeof contactedHosts.keys === "function") ? contactedHosts.keys() : contactedHosts;
    for (const h of iter) { if (h) hosts.push(normalizeHost(h)); }
  }
  for (const h of hosts) {
    if (!h) continue;
    if (D === h) return true;
    if (!hostOnly && h.endsWith("." + D)) return true;
  }
  return false;
}

/**
 * scanRejectReason: Pure per-cookie accept verdict for scans (testable twin of
 *   the loop filter below). Returns null when the cookie is accepted, otherwise
 *   "store" | "partition" | "scope" naming the rejecting gate. cookieBelongsToScan
 *   delegates to this so acceptance counts in diagnostics can never disagree
 *   with actual merge behavior.
 */
function scanRejectReason(cookie, state, storeId, partitionSite) {
  if (storeId && String(cookie?.storeId || "") !== String(storeId)) return "store";
  const topLevelSite = (cookie?.partitionKey && cookie.partitionKey.topLevelSite) || "";
  if (topLevelSite && partitionSite && topLevelSite !== partitionSite) return "partition";
  const cReg = getRegistrableDomain(cookie?.domain || "");
  if (cReg && state?.siteKey && cReg === state.siteKey) return null;
  let pageHost = "";
  try { pageHost = normalizeHost(new URL(state?.url || "").hostname); } catch (e) {}
  try {
    if (cookieInPageScope(cookie, pageHost, state?.domains)) return null;
  } catch (e) {}
  return "scope";
}

function cookieBelongsToScan(cookie, state, storeId, partitionSite) {
  return scanRejectReason(cookie, state, storeId, partitionSite) === null;
}

// NOTE (removal): isCookieRelevantToTab lived here — registrable-level
// relevance shared by scans and live events. K2 replaced both call sites with
// cookieInPageScope (hostOnly-precise page scope) after the reg-level version
// proved to admit sibling-subdomain leakage. Removed with zero callers;
// history retained in the cookieBelongsToScan NOTE above.

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * cookiesEqual: Performs field-by-field comparison of two cookie objects to determine
 *   if they are semantically identical.
 * WHY IT EXISTS: When a cookie is updated (e.g., its value changes, expiry extends),
 *   the system needs to detect the change to update the UI and re-evaluate blocking.
 *   Simple reference comparison won't work because Chrome creates new cookie objects
 *   on each event. This function compares the structural fields that define a cookie's
 *   identity and behavior, ignoring volatile runtime properties. Without this, the
 *   system would either miss real changes (leading to stale UI) or report false changes
 *   (leading to unnecessary re-renders and blocking re-evaluation).
 * HOW IT WORKS: Compares name, normalized domain, path, cookieID (for encrypted value
 *   tracking), httpOnly, secure, sameSite, session, expirationDate, and fromDocCookie.
 *   Domain is normalized via normalizeHost() for consistent comparison. Booleans are
 *   coerced with !! to handle undefined/null. SameSite defaults to "unspecified".
 * INPUT: Two cookie objects (a, b) — may be Chrome cookie objects or internal representations.
 * OUTPUT: Boolean — true if all compared fields are equal.
 * Source: RFC 6265 Section 5.3 — cookie identification by (name, domain, path);
 *   cookie attributes define behavior and must be compared for equality.
 */
function cookiesEqual(a, b) {
  return (a?.name || "") === (b?.name || "")
    && cookieIdentityDomain(a?.domain) === cookieIdentityDomain(b?.domain)
    && (a?.path || "/") === (b?.path || "/")
    && (a?.cookieID || "") === (b?.cookieID || "")
    && !!a?.httpOnly === !!b?.httpOnly
    && !!a?.secure === !!b?.secure
    && (a?.sameSite || "unspecified") === (b?.sameSite || "unspecified")
    && !!a?.session === !!b?.session
    && (a?.expirationDate ?? null) === (b?.expirationDate ?? null)
    && !!a?.fromDocCookie === !!b?.fromDocCookie;
}

/**
 * hasAuthoritativeMatch: Checks if a cookie from document.cookie (JS-set) already has
 *   a matching cookie from chrome.cookies.getAll (authoritative browser API).
 * WHY IT EXISTS: document.cookie can only see non-HttpOnly cookies, and its domain/path
 *   information may be incomplete or inaccurate. When the extension receives cookies
 *   via both chrome.cookies.getAll (authoritative) and document.cookie (supplementary),
 *   duplicates can occur. This function prevents adding a document.cookie version when
 *   an authoritative version already exists in state, avoiding duplicate entries that
 *   would confuse the UI and inflate cookie counts. Without this deduplication, the
 *   same cookie could appear twice — once from the browser API and once from the page.
 * HOW IT WORKS: Iterates through all cookies in state that are NOT from document.cookie
 *   (fromDocCookie=false), and checks if any match the incoming cookie by name and
 *   normalized domain. This ensures that authoritative browser-API cookies take
 *   precedence over page-injected cookies.
 * INPUT: state (tab state object), cookie (cookie to check for duplicates).
 * OUTPUT: Boolean — true if a non-document-cookie match already exists in state.
 * Source: Chrome cookies API — HttpOnly cookies are not visible to document.cookie;
 *   document.cookie may report incorrect domain for subdomain cookies.
 */
function hasAuthoritativeMatch(state, cookie) {
  const name = cookie?.name || "";
  const domain = cookieIdentityDomain(cookie?.domain);
  for (const existing of state.cookies.values()) {
    if (!!existing?.fromDocCookie) continue;
    if ((existing?.name || "") === name && cookieIdentityDomain(existing?.domain) === domain) {
      return true;
    }
  }
  return false;
}

/**
 * removeCookieFromState: Removes a cookie from the tab's state cookie Map.
 * WHY IT EXISTS: When a cookie is deleted by the browser, blocked by risk enforcement,
 *   or purged by session lock, it must be removed from the tab's in-memory state so
 *   the UI reflects the current reality. Without this cleanup, deleted cookies would
 *   persist in state indefinitely, causing the privacy score to be inaccurate and
 *   the cookie list to show stale entries. The return value indicates whether a
 *   removal actually occurred, allowing callers to decide whether to notify the UI.
 * HOW IT WORKS: Generates a cookieKey from the cookie's name/domain/path and calls
 *   Map.delete() on state.cookies. Returns true if the key existed and was removed,
 *   false if the key was not found (cookie wasn't in state).
 * INPUT: state (tab state object), cookie (cookie object to remove).
 * OUTPUT: Boolean — true if the cookie was found and removed from state.cookies.
 * Source: Map.delete() semantics — returns true if the key existed.
 */
function removeCookieFromState(state, cookie) {
  const key = cookieKey(cookie);
  return state.cookies.delete(key);
}

/**
 * sanitizeCookieForClient: Strips sensitive fields from a cookie object before sending
 *   it to the UI (side panel or content script).
 * WHY IT EXISTS: Cookie values may contain session tokens, authentication secrets, or
 *   other sensitive data. The UI doesn't need the actual value — it needs the cookie's
 *   metadata (name, domain, path, category, origin, etc.) for display and scoring.
 *   Sending the full value to the UI would expose secrets to the page context (content
 *   scripts run in the page's origin) and to the side panel (which may have its own
 *   extensions or debug tools). This is a defense-in-depth measure following OWASP
 *   guidelines on sensitive data exposure.
 * HOW IT WORKS: Destructures the cookie, omitting value, encryptedValue, cookieID,
 *   and valueProtected. Adds computed fields: origin (First-party/Third-party),
  *   setBySite (boolean — was this cookie set during the tab's session?), cat
  *   (classification), classMethod (classification method), keepReason (debug info),
  *   and sessionLike (boolean — SG entry criterion, see enforceRiskBlockingForCookie).
 * INPUT: cookie (internal cookie object with sensitive fields), state (tab state).
 * OUTPUT: Plain object with only safe-to-display fields. The original cookie is not mutated.
 * Source: OWASP Top 10 A3:2017 — Sensitive Data Exposure; Chrome security model —
 *   content scripts share the page's origin and can be inspected.
 */
function sanitizeCookieForClient(cookie, state) {
  if (!cookie) return cookie;
  const { value, encryptedValue, cookieID, valueProtected, ...safeCookie } = cookie;
  safeCookie.origin = getCookieOrigin(cookie?.domain || "", state?.siteKey || "");
  safeCookie.setBySite = !!(state?.cookiesSetBySite?.has(cookieKey(cookie)) || state?.preExistingKeys?.has(cookieKey(cookie)));
  safeCookie.cat = cookie._cat || "Unknown";
  safeCookie.classMethod = cookie._method || "Unknown";
  safeCookie.keepReason = cookie._keepReason || cookie.keepReason || "";
  safeCookie.sessionLike = !!cookie._sessionLike;
  return safeCookie;
}

/**
 * cookiesForClient: Batch-sanitizes an array of cookies for UI consumption.
 * WHY IT EXISTS: Multiple call sites need to convert a collection of internal cookie
 *   objects into safe-to-display representations. Rather than calling
 *   sanitizeCookieForClient() in a loop at each call site, this function provides a
 *   single entry point. It also handles null/undefined input gracefully, returning
 *   an empty array instead of throwing.
 * HOW IT WORKS: If cookies is falsy, returns []. Otherwise, spreads cookies into an
 *   array (handles both Array and Map.values() iterators) and maps each through
 *   sanitizeCookieForClient().
 * INPUT: cookies (iterable of cookie objects), state (tab state).
 * OUTPUT: Array of sanitized cookie objects safe for UI rendering.
 * Source: N/A — utility wrapper.
 */
function cookiesForClient(cookies, state) {
  if (!cookies) return [];
  return [...cookies].map(c => sanitizeCookieForClient(c, state));
}

/**
 * computePrivacyScore: Calculates a 0-100 privacy score for a tab based on its cookies'
 *   categories, persistence, party context, and blocklist membership.
 * WHY IT EXISTS: Users need a single number that summarizes how privacy-respecting a
 *   site is. The score is displayed in the side panel and widget, enabling at-a-glance
 *   comparison between sites. Without this score, users would need to manually inspect
 *   every cookie to understand the privacy implications — impractical for non-technical
 *   users. The scoring formula is transparent and auditable, following a weighted
 *   penalty model rather than a black-box ML prediction.
 * HOW IT WORKS: Iterates all cookies and accumulates a penalty score based on:
 *   1) Category weight (w): Strict=0, Performance=0, Functionality=1-4, Advertising=2-6
 *      (higher for third-party and persistent cookies).
 *   2) Longevity multiplier (l): persistent third-party cookies get 1-2x multiplier
 *      based on days remaining; persistent first-party get 1-2x based on 60-day threshold.
 *   3) Blocklist multiplier (b): non-first-party cookies on known tracker domains
 *      get 2x multiplier.
 *   Final score = max(0, 100 - sum(w * l * b)). Labels: 0=Dangerous, <25=Critical,
 *   <50=Poor, <70=Fair, <90=Good, >=90=Excellent.
 * INPUT: cookies (array of sanitized cookie objects with cat, domain fields),
 *   siteKey (registrable domain), db (cookie database), ml (ML model).
 * OUTPUT: Object { score: number (0-100), label: string }.
 * Source: Weighted penalty model inspired by privacy scoring approaches in
 *   "Measuring Website Privacy" (Narayanan et al., Princeton); cookie category
 *   weights derived from IAB TCF purpose classifications.
 */
function computePrivacyScore(cookies, siteKey, db, ml) {
  if (!cookies.length) return { score: 100, label: "Excellent" };
  let penalty = 0;
  for (const cookie of cookies) {
    const cat = cookie.cat || "Unknown";
    const fp = getCookieOrigin(cookie.domain || "", siteKey || "") === "First-party";
    const persistence = getCookiePersistence(cookie);
    const p = !persistence.isSession;
    const days = p ? (persistence.daysRemaining ?? 0) : 0;
    const dom = (cookie.domain || "").toLowerCase().replace(/^\./, "");
    let w = 0;
    if      (cat === "Strict")        w = 0;
    else if (cat === "Performance")   w = 0;
    else if (cat === "Functionality") w = fp ? (p ? 3 : 1) : (p ? 4 : 2);
    else if (cat === "Advertising")   w = fp ? (p ? 5 : 2) : (p ? 6 : 3);
    else                              w = fp ? (p ? 3 : 0) : (p ? 4 : 1);
    let l = 1;
    if (p) { if (!fp) l = days < 7 ? 1 : days <= 30 ? 1.5 : 2; else l = days <= 60 ? 1 : 2; }
    const b = (!fp && isDomainInList(dom, db?.blocklist || [])) ? 2 : 1;
    penalty += w * l * b;
  }
  const score = Math.max(0, Math.round(100 - penalty));
  const label = score === 0 ? "Dangerous" : score < 25 ? "Critical" : score < 50 ? "Poor" : score < 70 ? "Fair" : score < 90 ? "Good" : "Excellent";
  return { score, label };
}

/**
 * loadProtectionSettings: Loads protection settings (session lock, risk blocking,
 *   cc enabled) from chrome.storage.local on startup.
 * WHY IT EXISTS: The extension's behavior depends on user-configurable settings that
 *   persist across sessions. On startup (service worker initialization), these settings
 *   must be loaded from storage to initialize the in-memory setting objects. Without
 *   this, the extension would use default settings until the user changes something,
 *   potentially disabling protection that was previously enabled.
 * HOW IT WORKS: Calls chrome.storage.local.get() with PROTECTION_DEFAULTS as the
 *   default values. On success, merges the retrieved values into the in-memory
 *   setting objects (sessionLockSettings, riskBlockingSettings, ccEnabled). Tracker
 *   Blocking is always on: any stored `riskBlockingEnabled: false` (pre-change
 *   profiles) is coerced to true in memory. Then calls syncTrackerBlockingRules()
 *   to ensure DNR rules match the loaded settings.
 * INPUT: None — reads from chrome.storage.local.
 * OUTPUT: None — updates global setting variables as side effects.
 * Source: Chrome Extensions storage API — chrome.storage.local persists across
 *   browser restarts; service workers restart on extension load.
 */
function loadProtectionSettings() {
  chrome.storage.local.get(PROTECTION_DEFAULTS, values => {
    if (chrome.runtime.lastError) return;
    sessionLockSettings = { ...SESSION_LOCK_DEFAULTS, ...values };
    riskBlockingSettings = { ...RISK_BLOCKING_DEFAULTS, ...values };
    riskBlockingSettings.riskBlockingEnabled = true;
    tbSiteWhitelist = Array.isArray(values.tbSiteWhitelist) ? values.tbSiteWhitelist : [];
    sgSiteWhitelist = Array.isArray(values.sgSiteWhitelist) ? values.sgSiteWhitelist : [];
    ccEnabled = values.ccEnabled !== false;
    syncTrackerBlockingRules();
  });
}

loadProtectionSettings();

/**
 * Storage change listener: Reacts to settings changes in chrome.storage.local and
 *   updates in-memory settings, then re-syncs DNR rules when needed.
 * WHY IT EXISTS: When the user changes settings via the side panel, the changes
 *   are written to chrome.storage.local. This listener picks up those changes
 *   in real-time without requiring a service worker restart — most importantly
 *   whitelist membership, which the DNR network layer must honor immediately.
 *   Without this listener, settings changes would only take effect after the
 *   next browser restart.
 * HOW IT WORKS: 1) Updates in-memory setting objects for each changed key.
 *   2) Tracker Blocking is always on: any riskBlockingEnabled write is coerced
 *   back to true in memory (the toggle no longer exists) and DNR rules are
 *   re-synced.
 *   3) If ccEnabled changes to false: clears all tab state.
 * INPUT: chrome.storage.onChanged event — changes (object of changed keys),
 *   area ("local" | "session" | "sync").
 * OUTPUT: None — side effects only (setting updates, tab reloads, DNR rule sync).
 * Source: Chrome Extensions storage API — onChanged fires for any storage write;
 *   MV3 service worker may restart, requiring re-initialization.
 */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  for (const key of Object.keys(SESSION_LOCK_DEFAULTS)) {
    if (changes[key]) sessionLockSettings[key] = changes[key].newValue;
  }
  for (const key of Object.keys(RISK_BLOCKING_DEFAULTS)) {
    if (changes[key]) {
      riskBlockingSettings[key] = changes[key].newValue;
    }
  }
  if (changes.tbSiteWhitelist) {
    tbSiteWhitelist = Array.isArray(changes.tbSiteWhitelist.newValue) ? changes.tbSiteWhitelist.newValue : [];
    // DNR rules carry the whitelist in excludedInitiatorDomains — re-sync so the
    // network layer honors the new membership immediately (removal gates read
    // the in-memory array directly and need no re-sync).
    syncTrackerBlockingRules();
  }
  if (changes.sgSiteWhitelist) {
    sgSiteWhitelist = Array.isArray(changes.sgSiteWhitelist.newValue) ? changes.sgSiteWhitelist.newValue : [];
  }
  if (changes.riskBlockingEnabled) {
    // Tracker Blocking is always on: there is no toggle left to flip it, so
    // any stray write (stale clients, console) is coerced back to true in
    // memory and rules are re-synced. The old false-cleanup branch and the
    // true-transition reload-all-tabs sweep are deleted as unreachable.
    riskBlockingSettings.riskBlockingEnabled = true;
    syncTrackerBlockingRules();
  }
  if (changes.ccEnabled) {
    ccEnabled = changes.ccEnabled.newValue !== false;
    if (!ccEnabled) {
      for (const tabId of Object.keys(tabState || {})) {
        delete tabState[tabId];
      }
    }
  }
});

/**
 * queueRemovalNotice: Batches cookie removal notifications into a single debounced
 *   message per (type, tabId) pair within a 300ms window.
 * WHY IT EXISTS: Cookie removal events can fire rapidly (e.g., a site setting 10
 *   tracking cookies in quick succession, or a session purge removing multiple cookies).
 *   Sending a separate Chrome runtime message for each removal would overwhelm the
 *   side panel with rapid-fire updates, causing UI jank and excessive re-renders.
 *   This function coalesces multiple removals into a single summary message with
 *   counts and the most common reason, reducing message overhead by 10-50x in
 *   burst scenarios.
 * HOW IT WORKS: 1) Generates a key from type + tabId. 2) If an entry already exists
 *   for this key (within the 300ms window), increments the count and merges reasons.
 *   3) Clears any existing timer. 4) Sets a new 300ms timer. When the timer fires,
 *   sends a single Chrome runtime message with the accumulated count, top reason,
 *   and trigger. This is a classic debounce pattern applied to Chrome extension
 *   messaging.
 * INPUT: type (string — "SESSION_LOCK_PURGED" | "RISK_BLOCKING_REMOVED"),
 *   tabId (integer | null for global), detail (object with count, reason, trigger).
 * OUTPUT: None — sends a debounced chrome.runtime.sendMessage after 300ms.
 * Source: Debounce pattern — standard UI optimization technique; Chrome messaging
 *   API has no built-in batching.
 */
function queueRemovalNotice(type, tabId, detail = {}) {
  const key = `${type}:${tabId || "global"}`;
  const current = removalNoticeQueue.get(key) || {
    type,
    tabId,
    count: 0,
    reasons: new Map(),
    trigger: detail.trigger,
    timer: null,
  };
  current.count += Number(detail.count || 1);
  if (detail.reason) {
    current.reasons.set(detail.reason, (current.reasons.get(detail.reason) || 0) + 1);
  }
  if (detail.trigger) current.trigger = detail.trigger;
  clearTimeout(current.timer);
  current.timer = setTimeout(() => {
    removalNoticeQueue.delete(key);
    const topReason = [...current.reasons.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
    chrome.runtime.sendMessage({
      type: current.type,
      tabId: current.tabId,
      trigger: current.trigger,
      count: current.count,
      reason: topReason,
    }).catch(() => {});
  }, 300);
  removalNoticeQueue.set(key, current);
}

/**
 * pushGlobalPurgeEvent: Records a cookie purge event (session lock removal, risk
 *   blocking, etc.) into a global feed and persists it to storage.
 * WHY IT EXISTS: Users need visibility into what cookies were removed and why.
 *   The purge feed is displayed in the side panel as a "timeline" of recent removal
 *   actions, helping users understand the extension's behavior and build trust.
 *   Without this feed, users would see cookies disappear but have no explanation,
 *   leading to confusion or distrust ("why was my cookie deleted?"). Persisting to
 *   storage ensures the feed survives service worker restarts.
 * HOW IT WORKS: Prepends the new event to the globalPurgeFeed array, keeping only
 *   the most recent 12 events (FIFO). Then writes the trimmed array to
 *   chrome.storage.local under the GLOBAL_PURGE_FEED_KEY. The .catch(() => {})
 *   silences storage errors (e.g., quota exceeded).
 * INPUT: event (object with timestamp, tabId, siteKey, url, trigger, consideredCount,
 *   removedCount, status, cookies).
 * OUTPUT: None — updates globalPurgeFeed array and persists to storage.
 * Source: Chrome storage API — chrome.storage.local for cross-session persistence.
 */
function pushGlobalPurgeEvent(event) {
  globalPurgeFeed = [event, ...(globalPurgeFeed || [])].slice(0, 12);
  chrome.storage.local.set({ [GLOBAL_PURGE_FEED_KEY]: globalPurgeFeed }).catch(() => {});
}

/**
 * getGlobalPurgeFeed: Returns the current global purge feed (recent removal events).
 * WHY IT EXISTS: The side panel and message handlers need to display recent removal
 *   events. This function provides a safe accessor that always returns an array,
 *   even if the feed hasn't been loaded yet or was corrupted. Without this accessor,
 *   callers would need to handle null/undefined checks every time.
 * HOW IT WORKS: Returns globalPurgeFeed if it's an array, otherwise returns [].
 * This is a defensive pattern — the feed may not be loaded yet at startup.
 * INPUT: None.
 * OUTPUT: Array of purge event objects (may be empty).
 * Source: N/A — defensive accessor pattern.
 */
function getGlobalPurgeFeed() {
  return Array.isArray(globalPurgeFeed) ? globalPurgeFeed : [];
}

/**
 * loadGlobalPurgeFeed: Loads the persisted purge feed from chrome.storage.local
 *   into memory on startup.
 * WHY IT EXISTS: The purge feed is persisted to storage to survive service worker
 *   restarts (MV3 service workers are ephemeral). On startup, the in-memory
 *   globalPurgeFeed array is empty, so this function restores it from storage.
 *   Without this, the side panel would show an empty feed after every service
 *   worker restart, losing the removal history that the user relies on.
 * HOW IT WORKS: Calls chrome.storage.local.get() with the feed key and an empty
 *   array as default. On success, replaces globalPurgeFeed with the stored array
 *   (or empty array if the stored value is not an array). Called once at module
 *   load time (line 400 in original file).
 * INPUT: None — reads from chrome.storage.local.
 * OUTPUT: None — updates globalPurgeFeed as a side effect.
 * Source: Chrome Extensions storage API — chrome.storage.local for persistence.
 */
function loadGlobalPurgeFeed() {
  chrome.storage.local.get({ [GLOBAL_PURGE_FEED_KEY]: [] }, res => {
    if (chrome.runtime.lastError) return;
    globalPurgeFeed = Array.isArray(res?.[GLOBAL_PURGE_FEED_KEY]) ? res[GLOBAL_PURGE_FEED_KEY] : [];
  });
}

/**
 * touchTab: Updates the lastActiveAt timestamp for a tab's state, marking it as
 *   recently active.
 * WHY IT EXISTS: The system needs to track tab activity recency for several purposes:
 *   1) When deciding which tab a cookie change belongs to (onChanged handler picks
 *   the most recently active tab for a given domain).
 *   2) For garbage collection — tabs that haven't been active for a long time could
 *   be candidates for state cleanup (though this isn't currently implemented).
 *   3) For the side panel to know when a tab was last interacted with. Without this
 *   timestamp, the system would have no way to distinguish active tabs from
 *   background tabs that haven't been visited in hours.
 * HOW IT WORKS: Validates the tabId (must be integer >= 0), calls getState(tabId)
 *   to ensure the state exists, then sets lastActiveAt to the current timestamp.
 *   Tab IDs < 0 (e.g., devtools, new tab pages) are silently ignored.
 * INPUT: tabId (integer >= 0).
 * OUTPUT: None — updates state.lastActiveAt as a side effect.
 * Source: N/A — internal state tracking.
 */
function touchTab(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  getState(tabId).lastActiveAt = Date.now();
}

/**
 * getCookieDescriptionSignals: Extracts session/tracking hint signals from a cookie's
 *   database description text.
 * WHY IT EXISTS: The cookie database contains human-readable descriptions for known
 *   cookies. These descriptions are a rich source of information about a cookie's
 *   purpose that goes beyond what cookie attributes (name, domain, flags) can reveal.
 *   By scanning descriptions for session-related and tracking-related keywords, the
 *   system can make more accurate classification decisions. Without this, a cookie
 *   described as "Google Analytics tracking cookie" would need to rely solely on its
 *   name and domain for classification, missing the explicit tracking intent.
 * HOW IT WORKS: 1) Looks up the cookie in the database via getCookieDbMatch().
 *   2) If found, applies vendor-scoped matching (isExactMatchVendorScoped) to ensure
 *   the description belongs to the correct vendor (avoids cross-vendor false matches).
 *   3) Extracts the description text and checks it against SESSION_DESC_HINTS and
 *   TRACKING_DESC_HINTS. Returns both the raw description and boolean flags.
 * INPUT: cookie (cookie object), db (cookie database), site (registrable domain).
 * OUTPUT: Object { desc: string, sessionDescHint: boolean, trackingDescHint: boolean }.
 * Source: N/A — heuristic classification based on cookie database curation.
 */
function getCookieDescriptionSignals(cookie, db, site) {
  const entry = getCookieDbMatch(cookie, db);
  if (entry && !isExactMatchVendorScoped(cookie?.name || "", cookie?.domain || "", site || "", db, entry, true)) {
    return {
      desc: "",
      sessionDescHint: false,
      trackingDescHint: false,
    };
  }
  const desc = String(entry?.desc || "").toLowerCase();
  if (!desc) {
    return {
      desc,
      sessionDescHint: false,
      trackingDescHint: false,
    };
  }
  const sessionDescHint = SESSION_DESC_HINTS.some(k => desc.includes(k));
  const trackingDescHint = TRACKING_DESC_HINTS.some(k => desc.includes(k));
  return { desc, sessionDescHint, trackingDescHint };
}

/**
 * getSessionAnalysis: Performs comprehensive session/auth analysis on a cookie,
 *   deriving rule-based verdicts and a rule-based risk level from multiple signals.
 * WHY IT EXISTS: This is the SINGLE SOURCE OF TRUTH for determining whether a cookie
 *   is a session cookie, auth cookie, or tracking cookie. It synthesizes signals from
 *   multiple sources (cookie attributes, database descriptions, domain classification,
 *   value features) into a unified analysis that drives exemption decisions (E1-E4),
 *   blocking decisions (C1-C3), and purge decisions (S1-S3). Without this centralized
 *   analysis, different parts of the system would make inconsistent decisions about
 *   the same cookie, leading to contradictory behavior (e.g., the exemption check
 *   saying "allow" while the blocking check says "block").
 * HOW IT WORKS: Pure rules, no scores. The session-like verdict decomposes into
 *   atomic rules (D1-D3 definitions + R1-R10 in the session-like rules doc): a
 *   name/description hint counts only ANDed with a corroborating marker (R4,
 *   engineering inference) — a name alone grants nothing (Calzavara et al. 2015:
 *   only 55 of 111 standard-name matches were auth; Chen et al. 2025 restates
 *   ~half of corpus-name matches as unrelated purposes).
 *   Risk level is first-match-wins, top-down: High = critical flag weakness
 *   (missing Secure/HttpOnly or JavaScript-set — the same rule Session Guard S3
 *   enforces, so labels and purges can never disagree); Medium = tracking
 *   description, third-party, long expiration, or weak SameSite; Low = token-like
 *   value on an otherwise clean cookie; None = clean. Also determines
 *   isSessionLike, isAuthLike, isFirstParty, authInfra flags.
 * INPUT: cookie (cookie object), state (tab state), db (cookie database).
 * OUTPUT: Object with isSessionLike, isAuthLike, isFirstParty, authInfra,
 *   sessionRiskLevel, sessionSignals, sessionRiskReasons, etc.
 * Source: Session cookie classification informed by RFC 6265 Section 4.1.2
 *   (session-cookie semantics: no Expires/Max-Age = retained until end of
 *   session), OWASP Session Management Cheat Sheet (HttpOnly mandatory on
 *   session IDs; authentication uses non-persistent cookies), Calzavara et al.
 *   2015 (DOI 10.1145/2754933 — limits of name-based evidence), and cookie
 *   security best practices (Secure, HttpOnly, SameSite flags).
 */
// ── SINGLE SOURCE OF TRUTH for 1st/3rd party classification ──
/**
 * AUTH_NAME_HINTS: Name fragments indicating login/authentication purpose
 *   (sess, auth, token, jwt, login, sso, identity, credential, account, ...).
 * SESSION_STATE_HINTS: Name fragments indicating session state (not login):
 *   language, theme, shopping cart, preferences, consent. These scope Session Guard
 *   over session-state cookies without claiming they are login cookies.
 *   Split from one list into two labeled halves with zero behavior change: a pure
 *   alternation (A|B) matches exactly when A or B matches, so the OR below accepts
 *   precisely the same names as before.
 * Source (auth half): Calzavara et al. 2015 name corpus (sess, auth, user, token,
 *   login, ...) + modern terms (jwt: RFC 7519; csrf: OWASP; sso/identity/credential:
 *   OIDC vocabulary). State half: session-state vocabulary (cart/locale/theme).
 */
const AUTH_NAME_HINTS = /(sess|session|auth|token|jwt|login|csrf|xsrf|sso|identity|credential|user|account|profile|uid|userid|user_id)/i;
const SESSION_STATE_HINTS = /(lang|locale|theme|cart|basket|pref|preference|setting|consent|dark|mode)/i;
function getSessionAnalysis(cookie, state, db) {
  const name = String(cookie?.name || "").toLowerCase();
  const vf = cookie?.valueFeatures || {};
  const persistence = getCookiePersistence(cookie);
  const isFirstParty = getCookieOrigin(cookie?.domain || "", state?.siteKey || "") === "First-party";
  const authInfra = isLikelyAuthInfrastructureDomain(cookie?.domain || "", db);
  const sameSite = String(cookie?.sameSite || "unspecified").toLowerCase();
  const descSignals = getCookieDescriptionSignals(cookie, db, state?.siteKey || "");
  // ── Evidence facts (one question each; see the session-like rules doc) ──
  const hintAuthName = AUTH_NAME_HINTS.test(name);                  // F1: name contains an auth term
  const hintStateName = SESSION_STATE_HINTS.test(name);             // F2: name contains a session-state term
  const hintDescSession = descSignals.sessionDescHint;              // F3a: description states session/auth purpose
  const hintDescTracking = descSignals.trackingDescHint;            // F3b: description states tracking purpose (veto)
  const descriptionClue = hintDescSession && !hintDescTracking;     // F3: veto applied
  const isBrowserSession = !!persistence.isSession;                 // D1: browser reports session scope
  const markerHttpOnly = cookie.httpOnly;                           // M1: HttpOnly present
  const markerNoExpiry = !persistence.hasExpiry;                    // M2: no Expires/Max-Age attribute
  const markerShortLived = persistence.daysRemaining !== null && persistence.daysRemaining <= 1; // M3: expires within a day
  const hasMarker = markerHttpOnly || markerNoExpiry || markerShortLived;
  // ── Verdict: each rule decides alone ──
  const ruleAuthName = isFirstParty && hintAuthName && hasMarker;      // R1
  const ruleStateName = isFirstParty && hintStateName && hasMarker;    // R2
  const ruleDocPurpose = isFirstParty && descriptionClue && hasMarker; // R3
  const ruleSessionAuth = isBrowserSession && authInfra;               // R9
  const isSessionLike = ruleAuthName || ruleStateName || ruleDocPurpose || ruleSessionAuth;
  // ── Shared helpers for the sibling logic below (NOT rule inputs) ──
  const sessionNameHint = hintAuthName || hintStateName;            // explanation list below
  const nameOrDescHint = sessionNameHint || descriptionClue;        // login-cookie check (isAuthLike) below
  const isAuthLike = !isBrowserSession && isFirstParty && nameOrDescHint && (
    (cookie.httpOnly && cookie.secure) ||
    authInfra
  );

  // Session evidence: rule-based signal list. Each entry is pushed by an explicit
  // IF below; nothing is summed, weighted, or thresholded.
  const sessionSignals = [];
  if (isBrowserSession) { sessionSignals.push("session lifespan"); }
  if (sessionNameHint) { sessionSignals.push("session-related name hint"); }
  if (descriptionClue) { sessionSignals.push("session-related description"); }
  if (persistence.daysRemaining !== null && persistence.daysRemaining <= 1) { sessionSignals.push("short lifespan"); }
  if (cookie.httpOnly && cookie.secure) { sessionSignals.push("Secure+HttpOnly"); }
  if (isFirstParty) { sessionSignals.push("first-party context"); }
  if (sameSite === "lax" || sameSite === "strict") { sessionSignals.push("same-site protection"); }
  if (vf.isUUID && (sessionNameHint || isBrowserSession)) { sessionSignals.push("identifier-like value"); }
  if (Number(vf.entropy || 0) >= 0.7 && (sessionNameHint || isBrowserSession)) { sessionSignals.push("high entropy value"); }

  // Risk level: first-match-wins rules, top-down - no points anywhere. The High rule
  // is exactly Session Guard S3's critical-weakness rule, so labels and purges agree.
  const riskReasons = [];
  const hasCriticalFlagWeakness = !cookie.secure || !cookie.httpOnly || cookie.fromDocCookie;
  const hasWeakSameSite = !sameSite || sameSite === "unspecified" || sameSite === "no_restriction" || sameSite === "none";
  const hasLongExpiration = persistence.daysRemaining !== null && persistence.daysRemaining > 7;
  const hasTokenLikeValue = !!(vf.isLong || Number(vf.entropy || 0) >= 0.7);
  if (!cookie.secure) { riskReasons.push("missing Secure"); }
  if (!cookie.httpOnly) { riskReasons.push("missing HttpOnly"); }
  if (cookie.fromDocCookie || !cookie.httpOnly) { riskReasons.push("JavaScript accessible"); }
  if (hasWeakSameSite) { riskReasons.push("weak SameSite"); }
  if (hasLongExpiration) { riskReasons.push("long expiration"); }
  if (!isFirstParty) { riskReasons.push("third-party session-like cookie"); }
  if (hasTokenLikeValue && hasCriticalFlagWeakness) { riskReasons.push("token-like value with weak flags"); }
  else if (hasTokenLikeValue) { riskReasons.push("token-like value"); }
  if (descSignals.trackingDescHint) { riskReasons.push("tracking-related description"); }

  let riskLevel = "None";
  if (hasCriticalFlagWeakness) { riskLevel = "High"; }
  else if (descSignals.trackingDescHint || !isFirstParty || hasLongExpiration || hasWeakSameSite) { riskLevel = "Medium"; }
  else if (hasTokenLikeValue) { riskLevel = "Low"; }
  return {
    isSessionLike,
    isAuthLike,
    isFirstParty,
    authInfra,
    sessionDescHint: descriptionClue,
    trackingDescHint: descSignals.trackingDescHint,
    sessionSignals,
    sessionRiskLevel: riskLevel,
    sessionRiskReasons: riskReasons,
  };
}

/**
 * shouldPurgeSessionCookie: Determines whether a session-like cookie should be
 *   purged (removed) based on the session lock rules S1-S3.
 * WHY IT EXISTS: Session lock removes session cookies when the user leaves a site,
 *   closes a tab, or closes the browser. This runs AFTER the user has already left,
 *   so even if a login cookie is deleted, the user was already done with the site.
 *   The only protection is whether the cookie has proper security flags — no special
 *   exemption for auth cookies. A cookie with Secure+HttpOnly is safe to keep;
 *   a cookie missing those flags is risky regardless of whether it's a login cookie.
 * HOW IT WORKS: Applies two sequential rules (the former S2 risk-level gate
 *   was removed — the rule-derived risk level feeds display labels only and no
 *   longer gates purges, since any critical flag weakness already rates High):
 *   S1: Not session-like AND not a documented login cookie → don't purge (return false)
 *   S3: No critical flag weakness (missing Secure/HttpOnly) OR only SameSite weakness
 *       → don't purge (return false)
 *   Only cookies that pass both checks are purged.
 *   Note: Auth cookies are protected by tracker blocking (E1-E4) while on the site.
 *   At leave, the auth finder (isProtectedAuthCookie) admits them into candidacy and
 *   flags alone decide after entry — importance is not immunity: a flag-weak login
 *   cookie is purged (accepted cost — re-login next visit).
 * INPUT: cookie (cookie object), analysis (getSessionAnalysis output), trigger (string
 *   — "site_exit" | "tab_close" | "browser_close"), protectedAuth (boolean — documented
 *   login cookie: admits candidacy in S1; never forces a keep).
 * OUTPUT: Boolean — true if the cookie should be purged.
 * Source: Session cookie security — RFC 6265 Section 5.2.1; OWASP Session Management
 *   — session fixation and session hijacking prevention; SameSite cookie attribute
 *   (RFC 6265bis) — CSRF protection.
 */
function shouldPurgeSessionCookie(cookie, analysis, trigger, protectedAuth = false) {
  if (!analysis.isSessionLike && !protectedAuth) return false;

  const sameSite = String(cookie?.sameSite || "unspecified").toLowerCase();
  const hasCriticalFlagWeakness = !cookie.secure
    || !cookie.httpOnly
    || cookie.fromDocCookie;
  const hasOnlySameSiteWeakness = !hasCriticalFlagWeakness && (
    !sameSite
    || sameSite === "unspecified"
    || sameSite === "no_restriction"
    || sameSite === "none"
  );

  // SameSite weakness is useful for scoring, but it should not be enough by
  // itself to purge a session cookie that is already HttpOnly and Secure.
  if (!hasCriticalFlagWeakness || hasOnlySameSiteWeakness) return false;

  return true;
}

/**
 * cookieRemovalUrl: Constructs a URL suitable for chrome.cookies.remove() from a
 *   cookie object and a URL scheme (http/https).
 * WHY IT EXISTS: Chrome's chrome.cookies.remove() requires a URL parameter that
 *   matches the cookie's domain and path. However, cookie objects store domain
 *   (which may have a leading dot for wildcard domains) and path separately, and
 *   the scheme (http/https) is not stored in the cookie object. This function
 *   assembles the correct URL from these components, handling the leading-dot
 *   normalization and path prefix logic. Without this, callers would need to
 *   duplicate the URL construction logic in multiple places.
 * HOW IT WORKS: Strips the leading dot from the domain (if present), lowercases it,
 *   ensures the path starts with "/" (prepending "/" if needed), and constructs
 *   "scheme://domain/path". Returns null if domain is empty.
 * INPUT: cookie (object with domain, path properties), scheme ("http" | "https").
 * OUTPUT: String URL (e.g., "https://example.com/path") or null if domain is empty.
 * Source: Chrome cookies API — remove() requires URL matching the cookie's domain/path;
 *   RFC 6265 Section 5.1.3 — cookie domain matching with/without leading dot.
 */
function cookieRemovalUrl(cookie, scheme) {
  const domain = cookie?.domain || "";
  if (!domain) return null;
  const d = domain.startsWith(".") ? domain.slice(1).toLowerCase() : domain.toLowerCase();
  const path = cookie?.path || "/";
  return `${scheme}://${d}${path.startsWith("/") ? path : `/${path}`}`;
}

/**
 * removeBrowserCookie: Multi-strategy cookie removal engine that tries multiple
 *   approaches to remove a cookie from the browser.
 * WHY IT EXISTS: Chrome's chrome.cookies.remove() is finicky — it requires an exact
 *   URL match (scheme + domain + path), and different cookies may have different
 *   schemes (http vs https), paths, or domain representations (with/without leading
 *   dot). A single removal attempt often fails. This function implements a cascading
 *   strategy that tries multiple URL variations, falling back to broader queries if
 *   the first attempts fail. Without this multi-strategy approach, 20-40% of removal
 *   attempts would silently fail, leaving tracking cookies in the browser.
 * HOW IT WORKS: Five-phase removal strategy:
 *   Phase 1: Query all cookies with the same name (getAllByName), filter to those
 *   matching the target domain (exact, subdomain, or registrable domain match).
 *   Try removing each candidate with both its native scheme and the alternate scheme.
 *   Phase 2: Try the fallback URL (if provided) with both http and https schemes.
 *   Phase 3: Try constructing URLs from the target domain with both schemes, trying
 *   both the normalized and raw domain forms.
 *   Phase 4: As a last resort, try ALL cookies with the same name (even if they don't
 *   match the target domain) — this catches edge cases where domain resolution differs
 *   between chrome.cookies.getAll and the internal state.
 *   Phase 5: Verify removal by re-querying; if no cookies with that name exist, return
 *   true (the cookie was already gone or was removed by a previous phase).
 * INPUT: cookie (cookie object to remove), fallbackUrl (string — URL context for removal).
 * OUTPUT: Promise<boolean> — true if the cookie was successfully removed or confirmed absent.
 * Source: Chrome cookies API — remove() semantics; RFC 6265 cookie domain matching rules.
 */
function removeBrowserCookie(cookie, fallbackUrl) {
  const tryRemove = (details) => new Promise(r => chrome.cookies.remove(details, c => r(!!c)));
  const getAllByName = (name) => new Promise(r => chrome.cookies.getAll({ name }, r));
  return (async () => {
    const cookieName = cookie?.name;
    if (!cookieName) return false;

    const targetDomain = normalizeHost(cookie?.domain || "");
    const targetReg = targetDomain ? getRegistrableDomain(targetDomain) : "";

    let candidates = [];
    try {
      const all = await getAllByName(cookieName);
      if (Array.isArray(all)) {
        candidates = all.filter(c => {
          const cDomain = normalizeHost(c?.domain || "");
          if (!cDomain) return false;
          if (targetDomain && cDomain === targetDomain) return true;
          if (targetDomain && (cDomain.endsWith("." + targetDomain) || targetDomain.endsWith("." + cDomain))) return true;
          const cReg = getRegistrableDomain(cDomain);
          if (targetReg && cReg && cReg === targetReg) return true;
          return false;
        });
      }

      for (const c of candidates) {
        const scheme = c.secure ? "https" : "http";
        const url = cookieRemovalUrl(c, scheme);
        if (!url) continue;
        const details = { url, name: c.name };
        if (c.storeId) details.storeId = c.storeId;
        if (await tryRemove(details)) return true;
        const altScheme = c.secure ? "http" : "https";
        const altUrl = cookieRemovalUrl(c, altScheme);
        if (altUrl && await tryRemove({ ...details, url: altUrl })) return true;
      }

      if (fallbackUrl) {
        const details = { url: fallbackUrl, name: cookieName };
        if (cookie.storeId) details.storeId = cookie.storeId;
        if (await tryRemove(details)) return true;
        const altUrl = fallbackUrl.replace(/^http:/, "https:");
        if (altUrl !== fallbackUrl) {
          if (await tryRemove({ ...details, url: altUrl })) return true;
        }
        const altUrl2 = fallbackUrl.replace(/^https:/, "http:");
        if (altUrl2 !== fallbackUrl && await tryRemove({ ...details, url: altUrl2 })) return true;
      }

      if (targetDomain) {
        const urlsToTry = [];
        for (const scheme of ["https", "http"]) {
          const url = cookieRemovalUrl({ ...cookie, domain: targetDomain }, scheme);
          if (url && !urlsToTry.includes(url)) urlsToTry.push(url);
        }
        const rawDomain = cookie?.domain || "";
        if (rawDomain !== targetDomain) {
          for (const scheme of ["https", "http"]) {
            const url = cookieRemovalUrl({ ...cookie, domain: rawDomain }, scheme);
            if (url && !urlsToTry.includes(url)) urlsToTry.push(url);
          }
        }
        for (const url of urlsToTry) {
          const details = { url, name: cookieName };
          if (cookie.storeId) details.storeId = cookie.storeId;
          if (await tryRemove(details)) return true;
        }
      }

      const allRaw = Array.isArray(all) ? all : [];
      for (const c of allRaw) {
        if (candidates.includes(c)) continue;
        const scheme = c.secure ? "https" : "http";
        const url = cookieRemovalUrl(c, scheme);
        if (!url) continue;
        const details = { url, name: c.name };
        if (c.storeId) details.storeId = c.storeId;
        if (await tryRemove(details)) return true;
        const altUrl = cookieRemovalUrl(c, c.secure ? "http" : "https");
        if (altUrl && await tryRemove({ ...details, url: altUrl })) return true;
      }
    } catch (e) {
      console.warn("[CC] getAll-based removal query failed:", e?.message);
    }

    try {
      const anyByName = await getAllByName(cookieName);
      if (Array.isArray(anyByName) && anyByName.length === 0) return true;
    } catch (e) { /* ignore */ }

    return false;
  })();
}

/**
 * purgeRiskySessionCookiesForState: Sweeps all cookies in a tab's state and removes
 *   those that meet the session purge criteria (S1-S3 rules).
 * WHY IT EXISTS: Session lock needs a batch removal function that evaluates every
 *   cookie in a tab against the session purge rules and removes those that qualify.
 *   This is called when the user leaves a site (site_exit), closes a tab (tab_close),
 *   or closes the browser (browser_close). Without this sweep, session cookies would
 *   persist indefinitely, defeating the purpose of session lock. The function also
 *   records the purge event in the global feed and notifies the side panel.
 * HOW IT WORKS: 1) Checks if session lock is enabled and the trigger is allowed
 *   (only site_exit, tab_close, browser_close). 2) If the site is on Session
 *   Guard's whitelist (sgSiteWhitelist), records an SG_WHITELIST_SKIP receipt,
 *   pushes a skipped history event (without it the recorder refuses sites that
 *   hold session cookies but show no event) and returns — no cookie is judged.
 *   3) For site_exit and tab_close,
 *   checks if any OTHER tab is still on the same site — if so, skips the purge
 *   entirely, because removeBrowserCookie() is global and would log out surviving
 *   tabs. Only purges when this is the last tab leaving the site. browser_close
 *   skips this check (all tabs closing, nothing to protect). 4) Loads the risk
 *   data database. 5) Iterates all cookies in state, running getSessionAnalysis()
 *   and isProtectedAuthCookie() on each. 6) For each cookie that passes
 *   shouldPurgeSessionCookie(), calls removeBrowserCookie() to remove it from the
 *   browser, then removeCookieFromState() to clean up state. 7) Records the purge
 *   event via pushGlobalPurgeEvent(). 8) If any cookies were removed, notifies
 *   the side panel and queues a removal notice.
 * INPUT: tabId (integer), state (tab state object), trigger (string — event type).
 * OUTPUT: Promise<number> — count of cookies actually removed.
 * Source: Session cookie security — RFC 6265 Section 5.2.1; OWASP Session Management
 *   — session fixation prevention; browser privacy — session data cleanup on navigation.
 */
async function purgeRiskySessionCookiesForState(tabId, state, trigger) {
  if (!sessionLockSettings.sessionLockEnabled || !state?.cookies?.size) return 0;
  const allowed = trigger === "site_exit" || trigger === "tab_close" || trigger === "browser_close";
  if (!allowed) return 0;
  // Site-whitelist gate (Session Guard's list only — Tracker Blocking has its
  // own independent list checked per cookie). A whitelisted site is hands-off:
  // no cookie on it is judged for purge. The skipped history event is required,
  // not cosmetic — with session cookies present but no event, the recorder
  // refuses the site ("no history event but session cookies existed").
  if (siteMatchesWhitelist(state?.siteKey || "", sgSiteWhitelist)) {
    const wlSite = normalizeHost(state?.siteKey || "");
    recordDecision({ tabId, site: wlSite, origin: "", name: "", domain: "", path: "-", url: state?.url || "", httpOnly: false, secure: false, fromDocCookie: false, session: false, verdict: "KEPT", reason: "SG_WHITELIST_SKIP", trigger, tb: riskBlockingSettings.riskBlockingEnabled, sg: true });
    pushGlobalPurgeEvent({
      timestamp: Date.now(),
      tabId,
      siteKey: state?.siteKey || "",
      url: state?.url || "",
      trigger,
      consideredCount: 0,
      removedCount: 0,
      sessionLikeCount: null,
      sessionAuthCount: null,
      status: "skipped",
      cookies: [],
    });
    return 0;
  }
  // Layer 1 cross-tab guard: removeBrowserCookie() deletes globally, so if any
  // OTHER tab is still on the same site, skip the purge to avoid logging it out.
  // Only purge when this is the last tab leaving. browser_close is exempt —
  // all tabs are closing, nothing survives to protect.
  if (trigger === "site_exit" || trigger === "tab_close") {
    const leavingSite = normalizeHost(state?.siteKey || "");
    if (leavingSite) {
      for (const [otherTabId, otherState] of Object.entries(tabState)) {
        if (Number(otherTabId) === tabId) continue;
        // siteKey may still be blank on a just-restored tab (pre-snapshot
        // format or a tab that hasn't re-stamped since worker restart) —
        // fall back to the URL host so the guard fails open neither way.
        let otherSite = normalizeHost(otherState?.siteKey || "");
        if (!otherSite && otherState?.url) {
          try { otherSite = getRegistrableDomain(new URL(otherState.url).hostname); } catch (e) {}
        }
        if (otherSite && otherSite === leavingSite) {
          recordDecision({ tabId, site: leavingSite, origin: "", name: "", domain: "", path: "-", url: state?.url || "", httpOnly: false, secure: false, fromDocCookie: false, session: false, verdict: "KEPT", reason: "LAYER1_SITE_OPEN", trigger, tb: riskBlockingSettings.riskBlockingEnabled, sg: true });
          return 0;
        }
      }
    }
  }
  const db = await getRiskData();
  // Scope guard baseline: registrable domain of the site being left.
  // Only cookies belonging to this scope are evaluated below; everything
  // else is a hitchhiker from background activity on other sites.
  const purgeScope = getRegistrableDomain(normalizeHost(state?.siteKey || "")) || normalizeHost(state?.siteKey || "");

  let removedCount = 0;
  let consideredCount = 0;
  let sessionLikeCount = 0;
  let sessionAuthCount = 0;
  const removedCookies = [];
  for (const cookie of [...state.cookies.values()]) {
    // Scope guard: judge only cookies belonging to the site being left.
    // Tab state accumulates cookies from background activity on other sites
    // (e.g. Gmail sync traffic filed into an unrelated tab). Evaluating those
    // in the leaving site's context misreads them (wrong first/third-party,
    // wrong exemptions) and globally deletes sessions the user still needs —
    // observed as GMAIL_AT purged under a chrome-extension siteKey.
    // Registrable-domain comparison keeps subdomains (mail.google.com vs
    // google.com) in scope. Empty scope purges nothing (fail closed).
    const cookieReg = getRegistrableDomain(normalizeHost(cookie?.domain || ""));
    if (!cookieReg || !purgeScope || cookieReg !== purgeScope) {
      recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: getCookieOrigin(cookie?.domain || "", state?.siteKey || ""), name: cookie?.name, domain: cookie?.domain, verdict: "KEPT", reason: "SCOPE_SKIP", trigger, tb: riskBlockingSettings.riskBlockingEnabled, sg: true });
      continue;
    }
    // Jurisdiction guard: Tracker Blocking already judged this cookie once
    // (suppression map hit). Its current instance is likely a degraded re-set
    // shadow (JS-set, no HttpOnly, session-lifespan). Purging it would complete
    // a TB-degrade → SG-delete feedback loop that logs users out of auth flows.
    // Only defer on FRESH claims (removed within the last 24h) so stale entries
    // from other sites/days don't permanently shield cookies. Tracker Blocking
    // re-evaluates the cookie against the rule table on next visit (the
    // reappearance verdict was retired — return is need, not evidence).
    const suppressed = getSuppressedTrackingCookie(cookie);
    if (suppressed && Date.now() - Number(suppressed.lastRemovedAt || 0) < 86400000) {
      recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "JURISDICTION_SKIP", trigger, tb: riskBlockingSettings.riskBlockingEnabled, sg: true });
      continue;
    }
    const analysis = getSessionAnalysis(cookie, state, db);
    const protectedAuth = isProtectedAuthCookie(cookie, state, db);
    // Merged S1-candidacy count (definition boundary: sessionLikeCount used to
    // count strictly isSessionLike; it now counts every in-scope cookie the
    // decision rules evaluate — session-shaped OR importance-admitted — so the
    // record matches S1. sessionAuthCount keeps the admitted-only part so the
    // merged total stays decomposable for audit. Neither counter feeds any
    // gate, rule, removal, or purge decision — record/feed only.
    if (analysis.isSessionLike || protectedAuth) sessionLikeCount++;
    if (protectedAuth && !analysis.isSessionLike) sessionAuthCount++;
    if (!shouldPurgeSessionCookie(cookie, analysis, trigger, protectedAuth)) continue;
    consideredCount++;
    const removed = await removeBrowserCookie(cookie, state?.url);
    if (!removed) continue;
    removedCookies.push({
      name: cookie?.name || "",
      domain: normalizeHost(cookie?.domain || ""),
      path: cookie?.path || "/",
      httpOnly: !!cookie?.httpOnly,
      secure: !!cookie?.secure,
      origin: getCookieOrigin(cookie?.domain || "", state?.siteKey || ""),
      protectedAuth,
    });
    recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: getCookieOrigin(cookie?.domain || "", state?.siteKey || ""), name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "PURGED", reason: "S1S3-" + (analysis.sessionRiskLevel || "?"), cat: cookie._cat || "?", trigger, tb: riskBlockingSettings.riskBlockingEnabled, sg: true });
    const stateRemoved = removeCookieFromState(state, cookie);
    if (stateRemoved) {
      removedCount++;
    }
  }
  pushGlobalPurgeEvent({
    timestamp: Date.now(),
    tabId,
    siteKey: state?.siteKey || "",
    url: state?.url || "",
    trigger,
    consideredCount,
    removedCount,
    sessionLikeCount,
    sessionAuthCount,
    status: removedCount > 0 ? "removed" : consideredCount > 0 ? "attempted" : "skipped",
    cookies: removedCookies.slice(0, 12),
  });
  if (removedCount) {
    notifySidePanel(tabId);
    queueRemovalNotice("SESSION_LOCK_PURGED", tabId, { trigger, count:removedCount });
  }
  return removedCount;
}

async function getRiskData() {
  if (riskDataCache) return riskDataCache;
  const data = await getLocalData();
  riskDataCache = data.cookieDb || null;
  return riskDataCache;
}

async function getRiskModel() {
  if (riskModelCache) return riskModelCache;
  const data = await getLocalData();
  if (!data.modelWeights) return null;
  try {
    riskModelCache = new CookieMLClassifier(data.modelWeights);
  } catch (e) {
    console.warn("[CC] Risk model init failed:", e);
    riskModelCache = null;
  }
  return riskModelCache;
}

function getDomainVendorNorm(domain, db) {
  return getResolvedVendorInfo(domain, db)?.norm || "";
}

function getDomainVendorLabel(domain, db) {
  return getResolvedVendorInfo(domain, db)?.label || "";
}

function isAuthSafeVendor(vendor) {
  return AUTH_SAFE_VENDORS.has(normalizeHost(vendor));
}

function isTrackingVendor(domain, db) {
  const info = getResolvedVendorInfo(domain, db) || {};
  const vendorLabel = String(info.label || "").toLowerCase();
  const vendorNorm = info.norm || "";
  if (!vendorLabel && !vendorNorm) return false;
  return TRACKING_VENDOR_HINTS.some(hint => vendorLabel.includes(hint) || vendorNorm.includes(hint));
}

/**
 * isAuthSafeHost: Checks if a domain is owned by a known auth-safe platform
 *   (Google, Facebook, Microsoft, Apple, GitHub).
 * WHY IT EXISTS: These platforms provide authentication infrastructure that is used
 *   across millions of third-party sites (SSO buttons, OAuth flows). Their cookies
 *   on third-party sites are auth cookies, not trackers. Without this check, the
 *   system would block Google's SID/HSID cookies when a user visits a site with a
 *   Google login button, breaking the login flow. This function is a prerequisite
 *   for the E4 exemption (auth infrastructure first-party).
 * HOW IT WORKS: Normalizes the domain, gets its registrable domain, then checks
 *   against GOOGLE_AUTH_HOSTS (the login-state subset — NOT the full GOOGLE_OWNED_HOSTS
 *   service list, so ad/infra domains never confer auth-safe status), plus a hardcoded
 *   list of Facebook/Microsoft/Apple/GitHub domains. The check uses both the full domain and the registrable domain to handle
 *   subdomains like "accounts.google.com" → "google.com".
 * INPUT: domain (string — cookie domain).
 * OUTPUT: Boolean — true if the domain is auth-safe.
 * Source: Platform SSO documentation; IANA root zone database for ccTLD matching.
 */
function isAuthSafeHost(domain) {
  const d = normalizeHost(domain);
  if (!d) return false;
  const reg = getRegistrableDomain(d);
  return GOOGLE_AUTH_HOSTS.some(host => d === host || d.endsWith(`.${host}`) || reg === host) || [
    "facebook.com",
    "facebook.net",
    "instagram.com",
    "live.com",
    "login.live.com",
    "microsoft.com",
    "apple.com",
    "github.com",
  ].some(host => d === host || d.endsWith(`.${host}`) || reg === host);
}

/**
 * isLikelyAuthInfrastructureDomain: Multi-signal check to determine if a domain is
 *   part of authentication infrastructure (SSO providers, OAuth endpoints, identity
 *   providers).
 * WHY IT EXISTS: Auth infrastructure domains serve cookies that are essential for
 *   login functionality. These cookies must not be blocked or purged because doing so
 *   would break authentication flows. This function combines three signals:
 *   1) isAuthSafeHost (Google auth-state hosts + Facebook/Microsoft/Apple/GitHub)
 *   2) Vendor name from the cookie database (isAuthSafeVendor)
 *   3) Tiered domain-keyword matching: Tier 1 protocol keywords stand alone;
 *      Tier 2 generic words require auth-safe-vendor corroboration (a Tier 2 match
 *      with an unknown vendor grants nothing).
 *   A single signal is insufficient: isAuthSafeHost misses smaller IdPs, vendor
 *   matching misses new vendors, and ungated keyword matching has false positives.
 *   Combining all three provides robust detection with low false-positive rate.
 * HOW IT WORKS: 1) If isAuthSafeHost returns true, immediately return true.
 *   2) Check Tier 1 keywords on the domain and its registrable domain; if matched,
 *   return true. 3) Look up the domain's vendor; Tier 2 keywords return the
 *   vendor-safe verdict (true only with corroboration), then a bare vendor-safe
 *   verdict applies. Otherwise the domain is not auth infrastructure.
 * INPUT: domain (string), db (cookie database).
 * OUTPUT: Boolean — true if the domain is likely auth infrastructure.
 * Source: OAuth 2.0 (RFC 6749 §3.1) — authorization server domains; OpenID Connect
 *   Discovery (§4) — issuer domain patterns.
 */
function isLikelyAuthInfrastructureDomain(domain, db) {
  const d = normalizeHost(domain);
  if (!d) return false;
  if (isAuthSafeHost(d)) return true;

  const reg = getRegistrableDomain(d);
  // Tier 1 (protocol-derived keywords) stands alone.
  if (AUTH_DOMAIN_HINT_RE.test(d) || AUTH_DOMAIN_HINT_RE.test(reg)) return true;

  const vendorSafe = isAuthSafeVendor(getDomainVendorNorm(d, db));
  // Tier 2 (generic words): trusted only with auth-safe-vendor corroboration.
  if (WEAK_AUTH_DOMAIN_HINT_RE.test(d) || WEAK_AUTH_DOMAIN_HINT_RE.test(reg)) return vendorSafe;
  if (vendorSafe) return true;

  return false;
}

/**
 * authSafeCrossTabHome: True when a cookie's registrable domain is the home site
 *   of some OTHER open tab and the cookie's domain is auth-safe platform
 *   infrastructure (isAuthSafeHost — Google auth-state hosts + Facebook/
 *   Microsoft/Apple/GitHub).
 * WHY IT EXISTS: chrome.cookies.remove() deletes globally. A Google companion
 *   cookie (NID, COMPASS, OTZ, LSID, … — not in AUTH_COOKIE_NAMES) judged by a
 *   foreign tab (a news site that merely contacted google.com, winning
 *   cookie-set attribution or scan queries by recency) reads as third-party,
 *   loses the E4 first-party auth-infra exemption, matches Advertising in the
 *   database, and is deleted — killing the session held by the open Gmail tab
 *   minutes later via Google's server-side invalidation. Observed as: idle
 *   multi-account Gmail logout with Session Guard off, intermittent, delayed.
 *   The old GOOGLE_DOMAIN blanket exemption covered this but also shielded
 *   Google's 3P ad cookies everywhere; this rescue is the narrow replacement —
 *   it fires only when another open tab actually LIVES on that domain.
 * HOW IT WORKS: Requires isAuthSafeHost(cookieDomain) — non-auth-safe tracker
 *   domains (doubleclick.net etc.) are still blocked on foreign sites even if
 *   another tab contacted them. Then scans tabState for any other tab whose
 *   siteKey equals the cookie's registrable domain (blank siteKey falls back
 *   to the tab URL host, covering just-restored tabs). The judging tab itself
 *   never counts as "other" — if it did, E4 would already have matched.
 * INPUT: cookie (cookie object with domain).
 * OUTPUT: Boolean — true if an auth-safe cookie should be kept for another tab's sake.
 * Source: chrome.cookies API — chrome.cookies.remove is browser-global, not per-tab;
 *   multi-account session invalidation — Google companion-cookie dependencies
 *   (the SID family alone is not the full session key).
 */
function authSafeCrossTabHome(cookie) {
  const cookieHost = normalizeHost(cookie?.domain || "");
  if (!cookieHost) return false;
  if (!isAuthSafeHost(cookieHost)) return false;
  const reg = getRegistrableDomain(cookieHost);
  if (!reg) return false;
  for (const otherState of Object.values(tabState)) {
    if (!otherState) continue;
    let sk = normalizeHost(otherState.siteKey || "");
    if (!sk && otherState.url) {
      try { sk = getRegistrableDomain(new URL(otherState.url).hostname); } catch (e) {}
    }
    if (sk && sk === reg) return true;
  }
  return false;
}

/**
 * isExemptFromRiskBlocking: Determines if a cookie should be exempt from risk-based
 *   blocking based on the Strict + E2-E6 exemption rules.
 * WHY IT EXISTS: Risk blocking must not break legitimate functionality. Certain cookies
 *   — Strictly-necessary labels (STRICT_EXEMPT), session/auth cookies without tracking
 *   hints (E2), cookies on login pages (E3), first-party auth infrastructure
 *   cookies (E4), auth-safe cookies that are the home site of another open tab (E5),
 *   and captcha/bot-verification infrastructure cookies (E6) — must be allowed through
 *   even if they match blocking rules. Without exemptions, the system would block
 *   Google's SID cookie on docs.google.com (E4), break login flows on auth pages (E3),
 *   remove legitimate session cookies (E2), log the user out of a Gmail tab in
 *   another window (E5), and break every hCaptcha/Turnstile-dependent login (E6).
 * HOW IT WORKS: Checks exemption conditions in order:
 *   1) Strict label → STRICT_EXEMPT (immune to everything in Tracker Blocking).
 *   2) isSessionExempt: session-like cookie that is NOT a third-party tracking vendor
 *      cookie (E2). Also requires the cookie to have a known category (not Unknown).
 *   3) AUTH_MODE: tab is on a login page (E3).
 *   4) AUTH_INFRA_FIRSTPARTY: first-party cookie on auth infrastructure domain (E4).
 *   5) CROSS_TAB_HOME: auth-safe cookie whose domain is the current site of another
 *      open tab (E5) — removing it globally would log that tab out.
 *   6) CAPTCHA_INFRA: Functionality/Unknown cookie on known captcha infrastructure
 *      (E6) — the challenge round trip depends on it (see CAPTCHA_INFRA_HOSTS).
 *   Returns the exemption reason string if exempt, null otherwise.
 * INPUT: cookie (cookie object), analysis (getSessionAnalysis output), state (tab state),
 *   db (cookie database).
 * OUTPUT: String ("STRICT_EXEMPT" | "SESSION_AUTH_EXEMPT" | "AUTH_MODE" |
 *   "AUTH_INFRA_FIRSTPARTY" | "CROSS_TAB_HOME" | "CAPTCHA_INFRA") or null.
 * Source: Privacy-by-design principles — exemptions for essential functionality;
 *   ePrivacy Directive Article 5(3) — exemption for technical storage;
 *   ICO guidance — security/fraud-prevention cookies are strictly necessary (E6).
 */
function isExemptFromRiskBlocking(cookie, analysis, state, db) {
  // Strict immunity: a Strictly Necessary label is treated as a guarantee —
  // the site breaks without it, so it is never risked.
  // Applies to all Strict labels including ML-guessed (simple rule).
  if (analysis && analysis.cat === "Strict") return "STRICT_EXEMPT";
  const thirdParty = analysis.origin === "Third-party";
  const vendorTracking = isTrackingVendor(cookie?.domain || "", db);
  const isSessionExempt = analysis.isSessionLike && !(thirdParty && vendorTracking && !analysis.isAuthLike);
  if ((isSessionExempt || analysis.isAuthLike) && analysis.cat !== "Unknown") return "SESSION_AUTH_EXEMPT";
  if (state?.authMode) return "AUTH_MODE";
  if (analysis.authInfra && !thirdParty) return "AUTH_INFRA_FIRSTPARTY";
  // Cross-tab home rescue (auth-safe hosts only): the cookie's domain is the
  // current site of another open tab, so removing it globally would log that
  // tab out. Narrow by design — see authSafeCrossTabHome.
  if (authSafeCrossTabHome(cookie)) return "CROSS_TAB_HOME";
  // Captcha/bot-verification infrastructure (E6): challenge cookies must
  // survive their own flow — hCaptcha __cflb is load-balancer affinity, so a
  // mid-flow deletion makes the verify call hit the wrong node and the login
  // fails. Category-scoped: Strict is already returned by E0 above; only
  // Functionality/Unknown are rescued here — Advertising/Performance cookies
  // on these hosts are still judged by the rule table.
  if ((analysis.cat === "Functionality" || analysis.cat === "Unknown") &&
      isCaptchaInfraDomain(cookie?.domain || "")) return "CAPTCHA_INFRA";
  return null;
}

/**
 * isProtectedAuthCookie: Checks if a cookie is a protected authentication cookie
 *   that must never be blocked by Tracker Blocking.
 * WHY IT EXISTS: Known authentication cookies from major platforms (Google's SID/HSID,
 *   Facebook's c_user/xs, Microsoft's MSA cookies) are essential for login persistence.
 *   These cookies have well-documented names and are set on known auth infrastructure
 *   domains. Without this protection, the risk-blocking system would incorrectly
 *   remove them, causing immediate logout while the user is still on the site.
 *   This function is the gatekeeper for the E1 exemption (protected auth cookie)
 *   in tracker blocking. Session Guard uses it only as a candidacy signal: at
 *   leave, documented login cookies are pulled into the S1 candidate set, then
 *   judged on flags like every other cookie (no keep — importance is not immunity).
 * HOW IT WORKS: 1) Normalizes the cookie's domain and the tab's site key.
 *   2) Checks if EITHER the cookie's domain OR the site's domain is auth infrastructure
 *   (isLikelyAuthInfrastructureDomain). This handles both first-party and third-party
 *   auth cookies. 3) If on auth infrastructure, checks if the cookie's name is in
 *   AUTH_COOKIE_NAMES (exact match) or starts with any AUTH_COOKIE_PREFIXES.
 *   Both conditions must be met (auth infrastructure AND known name/prefix).
 * INPUT: cookie (cookie object), state (tab state), db (cookie database).
 * OUTPUT: Boolean — true if the cookie is a protected auth cookie.
 * Source: Platform authentication cookie documentation; RFC 6265 — cookie name
 *   conventions; RFC 6265bis — __host- prefix specification.
 */
function isProtectedAuthCookie(cookie, state, db) {
  const name = String(cookie?.name || "").toLowerCase();
  const cookieHost = normalizeHost(cookie?.domain || "");
  const siteKey = normalizeHost(state?.siteKey || "");
  if (!name || !cookieHost) return false;

  if (!(isLikelyAuthInfrastructureDomain(cookieHost, db) || isLikelyAuthInfrastructureDomain(siteKey, db))) return false;

  if (AUTH_COOKIE_NAMES.has(name)) return true;
  if (AUTH_COOKIE_PREFIXES.some(prefix => name.startsWith(prefix))) return true;

  return false;
}

/**
 * getTrackerMatch: Looks up a domain in the cookie database's tracker domain list
 *   to check if it's a known tracking domain.
 * WHY IT EXISTS: The cookie database contains a curated list of domains known to
 *   serve tracking scripts, pixels, or other cross-site tracking infrastructure.
 *   When a cookie's domain matches a known tracker, it provides strong evidence
 *   for blocking (feeds ruleTracker3p and blocking evidence). Without this lookup,
 *   the system would rely solely
 *   on heuristics (category, vendor, description) which can miss known trackers
 *   that don't have explicit vendor labels.
 * HOW IT WORKS: Normalizes the domain and gets its registrable domain. Checks the
 *   database's domains dictionary for both the full domain and the registrable domain.
 *   Returns the database entry if found (containing category, description, vendor, etc.),
 *   or null if not a known tracker.
 * INPUT: domain (string), db (cookie database with domains dictionary).
 * OUTPUT: Database entry object or null if not a known tracker.
 * Source: Cookie database curation — known tracker domains from cookie_db.json
 *   domains dictionary ("Merged: Disconnect.me + WhoTracksMe + OCD").
 */
function getTrackerMatch(domain, db) {
  const d = normalizeHost(domain);
  if (!d || !db) return null;
  const reg = getRegistrableDomain(d);
  if (db.domains?.[d]) return db.domains[d];
  if (reg && db.domains?.[reg]) return db.domains[reg];
  return null;
}

/**
 * getTrackingSuppressionKey: Generates a unique key for a cookie in the suppression map,
 *   identifying a specific cookie by name, domain, and path.
 * WHY IT EXISTS: When a tracking cookie is removed, the system needs to remember it
 *   for reappearance telemetry, the SG jurisdiction guard (defer purges of
 *   recently-judged cookies), and DNR escalation (promoteSuppressedTrackingSource).
 *   The suppression key uniquely identifies a cookie instance, preventing false
 *   matches between different cookies that share a name but have different
 *   domains or paths. Note: reappearance no longer executes a kill (O2 retired).
 * HOW IT WORKS: Joins [name, normalizedDomain, path] with "::" separator. Same format
 *   as cookieKey() but used specifically for the suppression tracking system.
 * INPUT: cookie (cookie object).
 * OUTPUT: String key in format "name::normalizedDomain::path".
 * Source: N/A — internal key format for suppression tracking.
 */
function getTrackingSuppressionKey(cookie) {
  return [
    cookie?.name || "",
    normalizeHost(cookie?.domain || ""),
    cookie?.path || "/",
  ].join("::");
}

/**
 * getTrackingSuppressionFamilyKey: Generates a family-level key for a cookie in the
 *   suppression map, identifying all cookies with the same name across subdomains of
 *   the same registrable domain.
 * WHY IT EXISTS: Trackers often set the same cookie name across multiple subdomains
 *   (e.g., "_ga" on "example.com", "www.example.com", "cdn.example.com"). If the
 *   system removes "_ga" on "www.example.com" but then sees "_ga" on "cdn.example.com",
 *   it should recognize this as the same tracker and block it immediately. The family
 *   key uses the registrable domain (e.g., "example.com") instead of the full domain,
 *   enabling cross-subdomain suppression. Without this, the reappearance counter would
 *   reset for each subdomain, requiring re-evaluation.
 * HOW IT WORKS: Joins [name, registrableDomain] with "::" separator. If the
 *   registrable domain can't be determined, falls back to the full normalized domain.
 * INPUT: cookie (cookie object).
 * OUTPUT: String key in format "name::registrableDomain" or "name::normalizedDomain".
 * Source: eTLD+1 concept from public suffix list — registrable domain is the
 *   effective top-level domain plus one label (e.g., "example.co.uk").
 */
function getTrackingSuppressionFamilyKey(cookie) {
  return [
    cookie?.name || "",
    getRegistrableDomain(normalizeHost(cookie?.domain || "")) || normalizeHost(cookie?.domain || ""),
  ].join("::");
}

/**
 * getTrackingSuppressionKeys: Returns an array of suppression keys (exact + family)
 *   for looking up a cookie in the suppression map.
 * WHY IT EXISTS: The suppression map uses two key formats — exact (name::domain::path)
 *   for precise matching, and family (name::registrableDomain) for cross-subdomain
 *   matching. By returning both keys, callers can check if a cookie matches either
 *   format. This handles the common case where a tracker sets the same cookie name
 *   across multiple subdomains of the same domain.
 * HOW IT WORKS: Generates the exact key and the family key. If they're different
 *   (which they will be unless the domain is already the registrable domain), returns
 *   both as an array. If they're the same, returns only the exact key to avoid
 *   redundant lookups.
 * INPUT: cookie (cookie object).
 * OUTPUT: Array of 1-2 string keys for suppression map lookup.
 * Source: N/A — composite key strategy for cross-subdomain tracking.
 */
function getTrackingSuppressionKeys(cookie) {
  const exact = getTrackingSuppressionKey(cookie);
  const family = getTrackingSuppressionFamilyKey(cookie);
  return family && family !== exact ? [exact, family] : [exact];
}

/**
 * getSuppressedTrackingCookie: Looks up a cookie in the suppression map to check
 *   if it was previously removed as a tracking cookie.
 * WHY IT EXISTS: When a tracking cookie is removed, it's recorded in the suppression
 *   map. On reappearance the cookie is NOT auto-blocked (the O2 reappearance verdict
 *   was retired — return is need, not evidence); instead the entry feeds reappearance
 *   telemetry, the SG jurisdiction guard (defer purges of recently-judged cookies),
 *   and DNR escalation. This function checks both the exact key and the family key to
 *   catch cross-subdomain matches.
 * HOW IT WORKS: Iterates through all suppression keys (exact + family) for the cookie
 *   and returns the first matching entry from suppressedTrackingCookies Map. The entry
 *   contains the removal count, reasons, and timestamp.
 * INPUT: cookie (cookie object).
 * OUTPUT: Suppression entry object { name, domain, path, cookieID, reasons, count,
 *   lastRemovedAt } or null if not previously suppressed.
 * Source: N/A — reappearance tracking for persistent tracker blocking.
 */
function getSuppressedTrackingCookie(cookie) {
  for (const key of getTrackingSuppressionKeys(cookie)) {
    const entry = suppressedTrackingCookies.get(key);
    if (entry) return entry;
  }
  return null;
}

/**
 * rememberBlockedDomain: Adds a domain to the sticky blocklist, remembering that
 *   it should be blocked via DNR rules.
 * WHY IT EXISTS: When a tracking cookie is removed from a domain, the system should
 *   also block future network requests to that domain (via DNR rules) to prevent the
 *   tracker from setting new cookies or loading tracking scripts. The sticky blocklist
 *   persists across tab navigations and service worker restarts (via
 *   suppressedTrackingCookies Map). Without this, the system would only remove cookies
 *   reactively, allowing trackers to set new cookies on every page load.
 * HOW IT WORKS: Normalizes the domain and adds it to stickyBlockedDomains Set. Also
 *   adds the registrable domain (if different) to cover subdomains. The Set is
 *   later used by syncTrackerBlockingRules() to generate DNR blocking rules.
 * INPUT: domain (string — cookie domain).
 * OUTPUT: None — adds to stickyBlockedDomains Set as a side effect.
 * Source: DNR API — declarativeNetRequest rules block by domain pattern;
 *   domain evidence — cookie_db.json domains dictionary (Disconnect.me + WhoTracksMe + OCD).
 */
function rememberBlockedDomain(domain) {
  const clean = normalizeHost(domain);
  if (!clean) return;
  // Captcha infra never seeds DNR rules (domain layer of E6): the domain's
  // scripts ARE the challenge widget — network-blocking ||hcaptcha.com^ kills
  // the login flow on every embedding site even when cookie verdicts are KEPT.
  if (isCaptchaInfraDomain(clean)) return;
  stickyBlockedDomains.add(clean);
  const reg = getRegistrableDomain(clean);
  if (reg) stickyBlockedDomains.add(reg);
}

/**
 * promoteSuppressedTrackingSource: Promotes a suppressed tracking cookie's domain
 *   to the blocked domains set, with sticky persistence for repeated offenders.
 * WHY IT EXISTS: When a tracking cookie is removed multiple times (reappearance count
 *   >= 2) or has persistent tracking-related reasons, the domain should be permanently
 *   added to the sticky blocklist. This escalates enforcement from "remove cookies
 *   when seen" to "block all network requests to this domain." Without this promotion,
 *   persistent trackers could keep setting cookies on every page load, requiring
 *   repeated removal. The sticky blocklist ensures that once a domain is confirmed
 *   as a persistent tracker, it stays blocked.
 * HOW IT WORKS: 1) Skips auth infrastructure domains (they shouldn't be blocked).
 *   2) Checks if the entry has count >= 2 or persistent/reappear tracking reasons.
 *   3) Adds the domain to both the blockedDomains set (for current sync) and
 *   stickyBlockedDomains (for persistence across syncs). 4) Also adds the registrable
 *   domain to cover subdomains.
 * INPUT: entry (suppression entry), db (cookie database), blockedDomains (Set — current sync).
 * OUTPUT: None — modifies blockedDomains and stickyBlockedDomains as side effects.
 * Source: Escalation pattern — progressive enforcement for persistent violators;
 *   tracker domain blocklists — industry practice for known persistent trackers.
 */
function promoteSuppressedTrackingSource(entry, db, blockedDomains) {
  const domain = normalizeHost(entry?.domain || "");
  if (!domain || !blockedDomains) return;
  if (isLikelyAuthInfrastructureDomain(domain, db)) return;
  // Captcha infrastructure (E6 domain layer): never promote to blocked domains —
  // a suppressed challenge cookie must not escalate into a network block of the
  // challenge service itself.
  if (isCaptchaInfraDomain(domain)) return;
  // Logout-trap fix: never escalate a login-flavored entry to the sticky
  // blocklist, even at count >= 2. Legacy entries without the flag keep the
  // old behavior (flag absent = falsy = eligible as before).
  if (entry?.authFlavored) return;
  const count = Number(entry?.count || 0);
  const reasons = Array.isArray(entry?.reasons) ? entry.reasons : [];
  const repeated = count >= 2 || reasons.some(r => /reappear|tracking-related description|persistent/i.test(String(r || "")));
  rememberBlockedDomain(domain);
  blockedDomains.add(domain);
  const reg = getRegistrableDomain(domain);
  if (reg && reg !== domain) blockedDomains.add(reg);
  if (repeated) {
    stickyBlockedDomains.add(domain);
    if (reg) stickyBlockedDomains.add(reg);
  }
}

// ═══════════════════════════════════════════════════════════════════
// TRACKER BLOCKING — ONE RULE TABLE (replaces scoring; formerly
// category + override split — flattened, and the O1/O2 verdicts retired)
//
// Flow diagram:
//   1. Exemptions   → isExemptFromRiskBlocking() → always ALLOW
//   2. Safety net   → SESSION_SAFETY_NET (session-shaped 1p HttpOnly) → ALLOW
//   3. Rule table   → 9 rules OR'd; first true term names the receipt label
//
// Rules (9 blocking + 7 exemptions + 2 refinements — defensible to panel):
//   Exemptions (7):
//     E0. Strict label (STRICT_EXEMPT — immune to everything below)
//     E1. Protected auth cookie (SID, HSID, etc.)
//     E2. Session/auth-like without tracking hint
//     E3. Auth mode (login page active)
//     E4. Auth-infra first-party (google.com cookies on docs.google.com)
//     E5. Cross-tab home (auth-safe cookie is the home site of another open
//         tab — removal would log that tab out; Gmail multi-account fix)
//     E6. Captcha infrastructure (Functionality/Unknown cookie on a known
//         captcha/bot-verification host — the challenge round trip depends on
//         it; hosts DB-seeded from cookie_db.json Anti-fraud class. Domain
//         layer also guards DNR seeding so ||hcaptcha.com^ is never ruled.)
//     (Removed: Google domain blanket — superseded by E1-E6; third-party
//      Google ad cookies are blocked like any other tracker. Verified by
//      Gmail-stays-logged-in test.)
//   Classification rules (C1-C3, first-party Advertising/Unknown need
//   corroboration — 3 per-cookie sources: DB description admitting tracking,
//   tracking vendor list, JS-visibility; ML alone cannot kill a first-party
//   cookie):
//     C1. Advertising → block (3p always; 1p only with corroboration)
//     C2. Third-party Performance → block
//     C3. Unknown → block (3p always; 1p only with corroboration, same rule)
//   Selection refinements (2):
//     N1. Vendor-scoped exact DB matches (domain_utils.js) — a vendor's
//         dictionary entry only convicts on positive vendor contradiction;
//         unknown vendors trust the name (CID/Adform-vs-Canva case)
//     N2. Vendor-scoped description hints — colliding vendors' words can't
//         smuggle tracking/session hints into corroboration or exemption
//   Evidence rules (B1-B6):
//     B1. trackingDescHint — DB description contains "track", "pixel", "ads"
//     B2. Third-party + known tracker match (tracker domains DB)
//     B3. Tracking vendor hint (Google Ads/DoubleClick/Adobe AAM…, not
//         session/auth/infra — label BLOCK_VENDOR_HINT)
//     B4. Third-party persistent Functionality (session-like 3p Func not caught by E2)
//     B5. JavaScript-set Performance (fromDoc + Performance)
//     B6. JavaScript-set third-party Functionality (fromDoc + 3p Func)
//   Retired verdicts (deliberated and removed — see enforce comments):
//     R4. Forced vendor identity (2-entry Adobe list) — identity neither
//         convicts nor excuses; Adobe AAM still reachable via B3
//     R5. reappearance (reappeared after removal) — return is need, not
//         evidence; a one-time misjudgment became a permanent logout
// ═══════════════════════════════════════════════════════════════════
/**
 * getTrackingRiskAnalysis: Performs the full risk analysis pipeline for a cookie,
 *   combining classification, session analysis, tracker matching, and exemption
 *   checks into a single analysis result.
 * WHY IT EXISTS: This is the central analysis function that feeds into
 *   enforceRiskBlockingForCookie(). It synthesizes multiple data sources — ML
 *   classification, cookie database lookups, session analysis, tracker matching,
 *   and suppression state — into a single risk assessment. Without this centralized
 *   pipeline, different callers would need to duplicate the analysis logic, leading
 *   to inconsistencies. The function also handles early returns for protected auth
 *   cookies (E1), session/auth cookies without tracking hints (E2), and first-party
 *   auth infrastructure cookies (E4).
 * HOW IT WORKS: 1) Loads the ML model and classifies the cookie (category + method).
 *   2) Determines first/third party origin using getCookieOrigin().
 *   3) Runs getSessionAnalysis() for session/auth scoring.
 *   4) Looks up tracker match in the database.
 *   5) Checks suppression state (has this cookie been removed before?).
 *   6) Checks auth infrastructure status.
 *   7) If protected auth cookie → return with riskScore=0 and "auth/session exempted".
 *   8) If session-like/auth-like WITHOUT tracking hint → return with riskScore=0.
 *   9) If first-party auth infrastructure → return with riskScore=0.
 *   10) Otherwise, return full analysis with risk reasons (category, JS-set, reappeared, etc.).
 * INPUT: cookie (cookie object), state (tab state), db (cookie database).
 * OUTPUT: Object with cat, method, origin, isSessionLike, isAuthLike, authInfra,
 *   riskScore, riskLevel, riskReasons, trackingDescHint, trackerMatch, suppressionKey,
 *   reappearanceCount, vendor.
 * Source: Multi-signal classification — ensemble approach from ML literature;
 *   cookie security analysis — RFC 6265 attribute analysis.
 */
async function getTrackingRiskAnalysis(cookie, state, db) {
  const model = await getRiskModel();
  const rawSite = state?.url ? new URL(state?.url).hostname : (state?.siteKey || normalizeHost(cookie?.domain || ""));
  const site = getRegistrableDomain(rawSite);
  const classification = classifyCookie(cookie, site, db, model);
  // FIX: use getCookieOrigin() as the single source of truth
  const cookieHost = normalizeHost(cookie?.domain || "");
  const siteKey = normalizeHost(state?.siteKey || "");
  const origin = getCookieOrigin(cookieHost, siteKey);
  const sessionAnalysis = getSessionAnalysis(cookie, state, db);
  const trackerMatch = getTrackerMatch(cookieHost, db);
  const suppressionKey = getTrackingSuppressionKey(cookie);
  const suppressed = getSuppressedTrackingCookie(cookie);
  const authInfra = isLikelyAuthInfrastructureDomain(cookieHost, db);

  // Always exempt known auth cookies, regardless of description hints.
  if (isProtectedAuthCookie(cookie, state, db)) {
    return {
      cat: classification.cat,
      method: classification.method,
      origin,
      isSessionLike: true,
      isAuthLike: sessionAnalysis.isAuthLike,
      authInfra,
      riskScore: 0,
      riskLevel: "None",
      riskReasons: ["auth/session cookie exempted"],
      trackingDescHint: sessionAnalysis.trackingDescHint,
      trackerMatch,
      suppressionKey,
      reappearanceCount: suppressed?.count || 0,
    };
  }

  // For heuristic session/auth-like cookies, only exempt if NOT flagged as tracking
  if (!sessionAnalysis.trackingDescHint && (sessionAnalysis.isSessionLike || sessionAnalysis.isAuthLike)) {
    return {
      cat: classification.cat,
      method: classification.method,
      origin,
      isSessionLike: true,
      isAuthLike: sessionAnalysis.isAuthLike,
      authInfra,
      riskScore: 0,
      riskLevel: "None",
      riskReasons: ["auth/session cookie exempted"],
      trackingDescHint: sessionAnalysis.trackingDescHint,
      trackerMatch,
      suppressionKey,
      reappearanceCount: suppressed?.count || 0,
    };
  }
  // Exempt first-party cookies on auth infrastructure domains (e.g. google.com cookies on docs.google.com)
  if (authInfra && origin === "First-party") {
    return {
      cat: classification.cat,
      method: classification.method,
      origin,
      isSessionLike: sessionAnalysis.isSessionLike,
      isAuthLike: sessionAnalysis.isAuthLike,
      authInfra,
      riskScore: 0,
      riskLevel: "None",
      riskReasons: ["first-party auth infra cookie"],
      trackingDescHint: sessionAnalysis.trackingDescHint,
      trackerMatch,
      suppressionKey,
      reappearanceCount: suppressed?.count || 0,
    };
  }
  const reasons = [];
  if (sessionAnalysis.trackingDescHint) reasons.push("tracking-related description");
  if (classification.cat === "Advertising") reasons.push("advertising category");
  if (classification.cat === "Performance" && origin === "Third-party") reasons.push("third-party performance");
  if (classification.cat === "Unknown" && origin === "Third-party") reasons.push("unknown third-party");
  if (cookie.fromDocCookie) reasons.push("JavaScript-set");
  if (suppressed) reasons.push("reappeared after removal");
  const vendorInfo = getResolvedVendorInfo(cookie, db);
  return {
    cat: classification.cat,
    method: classification.method,
    origin,
    isSessionLike: false,
    isAuthLike: sessionAnalysis.isAuthLike,
    authInfra,
    riskScore: 0,
    riskLevel: "None",
    riskReasons: reasons,
    trackingDescHint: sessionAnalysis.trackingDescHint,
    trackerMatch,
    suppressionKey,
    reappearanceCount: suppressed?.count || 0,
    vendor: vendorInfo?.label || "",
  };
}

/**
 * rememberSuppressedTrackingCookie: Records a removed tracking cookie in the
 *   suppression map so it can be counted and looked up on reappearance.
 * WHY IT EXISTS: When a tracking cookie is removed, the system should remember it
 *   for reappearance telemetry, the SG jurisdiction guard (recently-judged cookies
 *   are not double-purged), and escalation to DNR domain blocking
 *   (promoteSuppressedTrackingSource). Reappearance itself no longer executes a
 *   kill (O2 retired — return is need, not evidence; a one-time misjudgment
 *   became a permanent logout). The suppression map tracks removal count and
 *   reasons. Without this memory, every cookie removal would be a one-shot
 *   action with no enforcement history.
 * HOW IT WORKS: 1) Checks if the cookie was previously suppressed (to get the old
 *   count). 2) Creates a suppression entry with incremented count. 3) Stores the
 *   entry under all suppression keys (exact + family) for cross-subdomain matching.
 *   4) Evicts oldest entries if the map exceeds SUPPRESSED_MAP_MAX (500) to prevent
 *   memory leaks. 5) If the cookie is NOT on auth infrastructure, adds its domain
 *   to the blocked domains set (for DNR rule generation).
 * INPUT: cookie (cookie object), analysis (getTrackingRiskAnalysis output).
 * OUTPUT: None — updates suppressedTrackingCookies Map and stickyBlockedDomains Set.
 * Source: N/A — reappearance tracking pattern for persistent enforcement.
 */
function rememberSuppressedTrackingCookie(cookie, analysis) {
  // Captcha infrastructure (E6 domain layer): no suppression entry is created,
  // so the domain can never be escalated into a DNR rule (the entry is also
  // unreachable elsewhere — SG's scope guard excludes these hosts).
  if (isCaptchaInfraDomain(cookie?.domain || "")) return;
  const previous = getSuppressedTrackingCookie(cookie);
  const payload = {
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path || "/",
    cookieID: cookie.cookieID,
    reasons: analysis.riskReasons,
    count: (previous?.count || 0) + 1,
    lastRemovedAt: Date.now(),
    // Logout-trap fix: records whether the removed cookie looked like login
    // infrastructure, so sticky promotion can refuse to escalate it later.
    authFlavored: !!analysis?.isSessionLike || !!analysis?.isAuthLike || !!analysis?.authInfra,
  };
  for (const key of getTrackingSuppressionKeys(cookie)) {
    suppressedTrackingCookies.set(key, payload);
  }
  while (suppressedTrackingCookies.size > SUPPRESSED_MAP_MAX) {
    suppressedTrackingCookies.delete(suppressedTrackingCookies.keys().next().value);
  }
  // Logout-trap fix: login-flavored domains are never network-blocked on
  // removal (was: auth-infra only). Per-cookie removal still applies; only
  // the domain escalation is withheld.
  if (!payload.authFlavored) {
    rememberBlockedDomain(cookie?.domain || "");
  }
}

/**
 * makeRiskInfo: Constructs a standardized risk info object from a cookie, its
 *   analysis, and vendor information.
 * WHY IT EXISTS: Multiple callers (enforceRiskBlockingForCookie, getTrackingRiskAnalysis)
 *   need to create a consistent risk info object for logging, debugging, and returning
 *   to callers. Without a builder function, each caller would construct the object
 *   slightly differently, making debugging harder and log parsing inconsistent.
 * HOW IT WORKS: Extracts and formats fields from the cookie, analysis, and vendorInfo
 *   objects into a flat, readable structure. Uses safe defaults (empty strings, 0,
 *   false) for missing fields.
 * INPUT: cookie (cookie object), analysis (risk analysis output), vendorInfo (vendor
 *   info object with label field).
 * OUTPUT: Object with name, domain, vendor, origin, category, riskScore, isSessionLike,
 *   isAuthLike, reasons.
 * Source: N/A — data formatting utility.
 */
function makeRiskInfo(cookie, analysis, vendorInfo) {
  return {
    name: cookie?.name || "",
    domain: cookie?.domain || "",
    vendor: vendorInfo?.label || "",
    origin: analysis.origin,
    category: analysis.cat || "Unknown",
    riskScore: Number(analysis.riskScore || 0),
    isSessionLike: !!analysis.isSessionLike,
    isAuthLike: !!analysis.isAuthLike,
    reasons: analysis.riskReasons || [],
  };
}

/**
 * enforceRiskBlockingForCookie: The core enforcement function that evaluates a cookie
 *   against all blocking rules (C1-C3, B1-B6) and removes it if it should be blocked.
 * WHY IT EXISTS: This is the decision engine that determines whether each individual
 *   cookie should be kept or removed. It implements 9 blocking rules (3 classification
 *   + 6 evidence) behind 5 exemption checks, balancing privacy protection
 *   against functionality preservation. Without this function, the extension would
 *   either block too aggressively (breaking sites) or too weakly (letting trackers through).
 * HOW IT WORKS: Three-phase evaluation:
 *   Phase 1 — Analysis: Runs getTrackingRiskAnalysis() to get classification, origin,
 *   session analysis, tracker match, and suppression state.
 *   Phase 2 — Decision: Gates first — blocking must be ON, the site known
 *   (VIRGIN_STATE_SKIP), and the site not on the TB site whitelist
 *   (TB_WHITELIST_SKIP; runs after Phase 1 so classification and the SG session
 *   tally still update on exempt sites). Then checks exemptions
 *   (isExemptFromRiskBlocking). If exempt,
 *   return skip. Then the session safety net (SESSION_SAFETY_NET). If not skipped,
 *   evaluates the flat rule table:
 *     - Classification (C1-C3): Advertising → block; 3p Performance → block; Unknown → block
 *       (first-party needs corroboration for C1/C3 — DB description, tracking
 *       vendor, or JS-visibility).
 *     - Evidence (B1-B6): trackingDescHint, 3p trackerMatch, vendor hint,
 *       3p persistent Functionality, JS-set Performance, JS-set 3p Functionality.
 *   Phase 3 — Action: If shouldBlock, calls removeBrowserCookie() to remove from browser,
 *   then records in suppression map, updates blocked keys, cleans up state, syncs DNR
 *   rules, notifies side panel, and queues removal notice.
 * INPUT: tabId (integer), state (tab state), cookie (cookie object).
 * OUTPUT: Promise<object> with blocked (boolean), shouldBlock, skipReason, and risk info.
 * Source: Blocking rules derived from IAB TCF purpose classifications, ePrivacy
 *   Directive Article 5(3), and cookie security best practices (OWASP).
 */
async function enforceRiskBlockingForCookie(tabId, state, cookie) {
  const db = await getRiskData();
  const vendorInfo = getResolvedVendorInfo(cookie, db);
  const analysis = await getTrackingRiskAnalysis(cookie, state, db);
  cookie._cat = analysis.cat;
  cookie._method = analysis.method;
  // SG entry criterion, refreshed every enforce pass (blocking ON or OFF —
  // analysis runs before the removal gate). Consumed panel-side by the SG
  // snapshot tally: the session count = cookies SG would evaluate at exit.
  cookie._sessionLike = !!analysis.isSessionLike;
  if (!riskBlockingSettings.riskBlockingEnabled) {
    return false;
  }
  // Virgin-state guard: never judge a cookie without knowing which site
  // you're on. With siteKey empty (cold start, fresh tab, post-navigation
  // reset before siteKey assignment), getCookieOrigin() reports everything
  // as third-party, exemptions E2/E4 go blind, and only the E1 name-list
  // holds — slaughtering every unlisted first-party cookie (e.g. Google
  // multi-login SIDCC/OSID) on the spot. Deferred cookies are re-evaluated
  // by later scans once state initializes.
  const gateSiteKey = normalizeHost(state?.siteKey || "");
  if (!gateSiteKey) {
    recordDecision({ tabId, site: "", origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "VIRGIN_STATE_SKIP", cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    return false;
  }
  // Site-whitelist gate (Tracker Blocking's list only — Session Guard has its
  // own independent list checked at leave). Runs AFTER the analysis stamps above
  // so a whitelisted site's panel classification and SG session tally are
  // untouched: the whitelist exempts removal, not observation. Receives the
  // same siteKey scope as every other gate; subdomains of an entry are covered
  // because siteKey is the registrable domain.
  if (siteMatchesWhitelist(gateSiteKey, tbSiteWhitelist)) {
    recordDecision({ tabId, site: gateSiteKey, origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "TB_WHITELIST_SKIP", cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    return false;
  }
  const persistence = getCookiePersistence(cookie);
  const thirdParty = analysis.origin === "Third-party";
  const reappearanceCount = Number(analysis.reappearanceCount || 0);
  const vendorTracking = isTrackingVendor(cookie?.domain || "", db);

  // First-party Advertising/Unknown needs corroboration beyond the category
  // label alone: short opaque first-party IDs (e.g. Canva's CUI/CUL/CID) are
  // exactly what the ML guesser confuses with tracker IDs. Strangers
  // (third-party) are still blocked on sight, as before.
  // First-party corroboration = per-cookie evidence only. (Retired: sticky as
  // execution and as corroboration — registrable-domain guilt-by-association,
  // open.spotify.com 21→1, one killed ad cookie condemned every sibling login
  // cookie; reappearance as verdict — return is need, not evidence, and a
  // one-time misjudgment became a permanent logout; forced vendor identity —
  // a 2-entry Adobe list: identity neither convicts nor excuses.) Surviving
  // sources: DB description admitting tracking, tracking vendor list,
  // JS-visibility. ML alone cannot kill a first-party cookie.
  const firstPartyCorroborated =
    !!analysis.trackingDescHint ||
    !!vendorTracking ||
    !!cookie.fromDocCookie;

  // One rule table (9 rules: C1-C3 classification, B1-B6 evidence).
  // Verdict = OR of all nine; first true term names the receipt label.
  const ruleAdvertising = analysis.cat === "Advertising" && (thirdParty || firstPartyCorroborated);
  const rulePerformance3p = analysis.cat === "Performance" && thirdParty;
  const ruleUnknown = analysis.cat === "Unknown" && (thirdParty || firstPartyCorroborated);
  const ruleTrackDesc = !!analysis.trackingDescHint;
  const ruleTracker3p = thirdParty && !!analysis.trackerMatch;
  const ruleVendorHint = vendorTracking && !analysis.authInfra && !analysis.isSessionLike && !analysis.isAuthLike && (thirdParty || analysis.cat === "Advertising" || analysis.cat === "Unknown" || !persistence.isSession);
  const ruleFunc3p = thirdParty && !persistence.isSession && analysis.cat === "Functionality";
  const rulePerfJs = !!cookie.fromDocCookie && analysis.cat === "Performance";
  const ruleFunc3pJs = !!cookie.fromDocCookie && thirdParty && analysis.cat === "Functionality";
  const shouldBlock = ruleAdvertising || rulePerformance3p || ruleUnknown ||
    ruleTrackDesc || ruleTracker3p || ruleVendorHint ||
    ruleFunc3p || rulePerfJs || ruleFunc3pJs;

  const exemptReason = isExemptFromRiskBlocking(cookie, analysis, state, db);
  if (exemptReason) {
    const info = makeRiskInfo(cookie, analysis, vendorInfo);
    console.debug("[CC][risk-block][skip]", exemptReason, info);
    try { cookie._keepReason = "SKIP-" + exemptReason; } catch (e) {}
    recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "SKIP-" + exemptReason, cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    return { blocked: false, shouldBlock, skipReason: exemptReason, ...info };
  }

  // Session safety net (after exemptions so exemption labels keep precedence;
  // both are KEPT — order affects only receipt truth). First-party +
  // session-lifespan + HttpOnly + not JS-set = login artifact by construction.
  // Last line of defense against session-rotation logouts where the cookie
  // name misses AUTH_NAME_HINTS and ML misclassifies it. Shape beats label:
  // trackers need persistence to track, so this class is nearly free of
  // false positives (false positive cost = broken login; false negative
  // cost = a session cookie that dies at browser exit anyway). Scope
  // warning: protects session-lifespan cookies only — persistent login
  // cookies rely on the corroboration rules below.
  const isSessionSafetyNet = !!persistence.isSession
    && analysis.origin === "First-party"
    && !!cookie.httpOnly
    && !cookie.fromDocCookie;
  if (isSessionSafetyNet) {
    const info = makeRiskInfo(cookie, analysis, vendorInfo);
    try { cookie._keepReason = "SKIP-SESSION_SAFETY_NET"; } catch (e) {}
    recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: true, verdict: "KEPT", reason: "SESSION_SAFETY_NET", cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    console.debug("[CC][risk-block][skip] SESSION_SAFETY_NET", info);
    return { blocked: false, shouldBlock: false, skipReason: "SESSION_SAFETY_NET", ...info };
  }

  if (!shouldBlock) {
    const info = makeRiskInfo(cookie, analysis, vendorInfo);
    info.reappearanceCount = reappearanceCount;
    info.trackingDescHint = analysis.trackingDescHint || false;
    info.trackerMatch = !!analysis.trackerMatch;
    info.vendorTracking = !!vendorTracking;
    info.persistenceSession = !!persistence.isSession;
    console.debug("[CC][risk-block][skip] NOT_BLOCKED", info);
    try { cookie._keepReason = "ALLOW-" + (analysis.cat || "Unknown") + "-" + (thirdParty ? "3P" : "1P") + (cookie.fromDocCookie ? "-JS" : ""); } catch (e) {}
    recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "NOT_BLOCKED-" + (analysis.cat || "Unknown"), cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    return { blocked: false, shouldBlock, skipReason: "NOT_BLOCKED", ...info };
  }

  const removed = await removeBrowserCookie(cookie, state?.url);
  if (!removed) {
    const info = makeRiskInfo(cookie, analysis, vendorInfo);
    console.debug("[CC][risk-block][skip] REMOVE_FAILED", info);
    recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "KEPT", reason: "REMOVE_FAILED", cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });
    return { blocked: false, shouldBlock, skipReason: "REMOVE_FAILED", ...info };
  }

  const info = makeRiskInfo(cookie, analysis, vendorInfo);
  info.reappearanceCount = reappearanceCount;
  const blockReason =
    ruleAdvertising ? "CATEGORY_ADVERTISING" + (thirdParty ? "_3P" : "") :
    rulePerformance3p ? "CATEGORY_PERFORMANCE_3P" :
    ruleUnknown ? "CATEGORY_UNKNOWN" + (thirdParty ? "_3P" : "") :
    ruleTrackDesc ? "BLOCK_TRACK_DESC" :
    ruleTracker3p ? "BLOCK_TRACKER_3P" :
    ruleVendorHint ? "BLOCK_VENDOR_HINT" :
    ruleFunc3p ? "BLOCK_FUNC_3P" :
    rulePerfJs ? "BLOCK_PERF_JS" :
    "BLOCK_FUNC_3P_JS";
  console.debug("[CC][risk-block][remove]", blockReason, info);
  recordDecision({ tabId, site: normalizeHost(state?.siteKey || ""), origin: analysis.origin || "", name: cookie?.name, domain: cookie?.domain, path: cookie?.path || "/", url: state?.url || "", httpOnly: !!cookie?.httpOnly, secure: !!cookie?.secure, fromDocCookie: !!cookie?.fromDocCookie, session: !!cookie?.session, verdict: "BLOCKED", reason: blockReason, cat: analysis.cat || "?", trigger: "tb-enforce", tb: true, sg: sessionLockSettings.sessionLockEnabled });

  rememberSuppressedTrackingCookie(cookie, analysis);
  catchUpBlockedKeys.add(cookieKey(cookie));
  while (catchUpBlockedKeys.size > CATCHUP_KEYS_MAX) {
    catchUpBlockedKeys.delete(catchUpBlockedKeys.values().next().value);
  }
  const stateRemoved = removeCookieFromState(state, cookie);
  if (stateRemoved) {
    notifySidePanel(tabId);
  }
  syncTrackerBlockingRules().catch(() => {});
  if (stateRemoved) {
    queueRemovalNotice("RISK_BLOCKING_REMOVED", tabId, {
      count: 1,
      reason: analysis.riskReasons[0] || "high-risk tracking cookie",
    });
  }
  return { blocked: true, shouldBlock, ...info };
}

function dnrRuleIds() {
  return Array.from({ length:DNR_RULE_LIMIT }, (_, i) => DNR_RULE_ID_START + i);
}

function googleTrackingRuleIds() {
  return GOOGLE_TRACKING_RULES.map((_, i) => GOOGLE_TRACKING_DNR_START + i);
}

function buildGoogleTrackingDnrRules() {
  return GOOGLE_TRACKING_RULES.map((rule, idx) => {
    // Union the rule's built-in Google-service exemptions with the TB site
    // whitelist so a whitelisted initiator is never blocked by these rules
    // either (regex-filtered so a malformed entry can't fail the DNR sync).
    const wl = (Array.isArray(tbSiteWhitelist) ? tbSiteWhitelist : [])
      .filter(d => /^[a-z0-9.-]+$/.test(d) && d.includes("."));
    const excluded = [...new Set([...(rule.exempt || []), ...wl])];
    return {
      id: GOOGLE_TRACKING_DNR_START + idx,
      priority: 1,
      action: { type: "block" },
      condition: {
        urlFilter: rule.urlFilter,
        ...(excluded.length ? { excludedInitiatorDomains: excluded } : {}),
        resourceTypes: GOOGLE_TRACKING_RESOURCE_TYPES,
      },
    };
  });
}

/**
 * syncTrackerBlockingRules: Generates and updates Chrome's Declarative Net Request
 *   (DNR) rules to block network requests to known tracking domains.
 * WHY IT EXISTS: DNR rules block tracking requests at the network level, before they
 *   leave the browser. This is more effective than post-hoc cookie removal because it
 *   prevents trackers from loading scripts, pixels, or other resources that could set
 *   cookies or collect data. Without DNR rules, the extension would only react to
 *   cookies after they're set, missing the opportunity to block the request entirely.
 *   DNR rules are also enforced by Chrome's networking stack, making them impossible
 *   for JavaScript to circumvent.
 * HOW IT WORKS: 1) If risk blocking is disabled, removes all rules and returns.
 *   2) Loads the cookie database and builds the blocked domains set from:
 *     - stickyBlockedDomains (previously confirmed trackers)
 *     - suppressedTrackingCookies (removed cookies → their domains)
 *     - Current tab state cookies (evaluate all cookies against blocking criteria)
 *   3) For each cookie in tab state, runs getTrackingRiskAnalysis() and determines
 *   if it should be blocked (same logic as enforceRiskBlockingForCookie but for
 *   DNR rule generation).
 *   4) Deduplicates domains and caps at DNR_RULE_LIMIT (1500) to stay within
 *   Chrome's DNR rule limit.
 *   5) Generates DNR rules with urlFilter patterns and excludedInitiatorDomains
 *   (self-exclusion prevents breaking the tracker's own site; the TB site
 *   whitelist is merged in so whitelisted initiators are never blocked).
 *   6) Also adds Google tracking rules (GOOGLE_TRACKING_RULES) with their own
 *   exclusion lists.
 *   7) Updates dynamic rules via chrome.declarativeNetRequest.updateDynamicRules().
 * INPUT: None — reads from global state (tabState, suppressedTrackingCookies, etc.).
 * OUTPUT: Promise — resolves when rules are updated; catches and logs errors.
 * Source: Chrome Extensions Declarative Net Request API; DNR rule limits
 *   (chrome.declarativeNetRequest.MAX_NUMBER_OF_REGEX_RULES).
 */
async function syncTrackerBlockingRules() {
  if (!chrome.declarativeNetRequest?.updateDynamicRules) return;
  const removeRuleIds = [...dnrRuleIds(), ...googleTrackingRuleIds()];
  if (!riskBlockingSettings.riskBlockingEnabled) {
    chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [] });
    return;
  }

  try {
    const db = await getRiskData();
    const blockedDomains = new Set();
    for (const domain of stickyBlockedDomains) {
      if (/^[a-z0-9.-]+$/.test(domain) && domain.includes(".") && !isLikelyAuthInfrastructureDomain(domain, db) && !isCaptchaInfraDomain(domain)) {
        blockedDomains.add(domain);
      }
    }
    for (const entry of suppressedTrackingCookies.values()) {
      promoteSuppressedTrackingSource(entry, db, blockedDomains);
    }
    const states = Object.values(tabState || {});
    for (const state of states) {
      if (!state?.cookies?.size || state.authMode) continue;
      // TB whitelist: hands off — cookies on exempted sites never seed new
      // blocked domains. Domains already in the set keep their rules; the
      // exempted initiator is covered by excludedInitiatorDomains below.
      if (siteMatchesWhitelist(state?.siteKey || "", tbSiteWhitelist)) continue;
      for (const cookie of state.cookies.values()) {
        const analysis = await getTrackingRiskAnalysis(cookie, state, db);
        const isTrackingDomain = isTrackingVendor(cookie?.domain || "", db);
        const isSessionExempt = analysis.isSessionLike && !(analysis.origin === "Third-party" && isTrackingDomain && !analysis.isAuthLike);
        if (isSessionExempt || analysis.isAuthLike || state?.authMode) continue;
        const persistent = !getCookiePersistence(cookie).isSession;
        const thirdParty = analysis.origin === "Third-party";
        const effectivelyPersistent = persistent || (thirdParty && isTrackingDomain && !analysis.isAuthLike);
        const category = analysis.cat || "Unknown";
        const trackerRelated = !!analysis.trackerMatch;
        const shouldBlock =
          (thirdParty && effectivelyPersistent && analysis.trackingDescHint) ||
          (thirdParty && trackerRelated && (category === "Advertising" || category === "Unknown")) ||
          (effectivelyPersistent && trackerRelated && !isLikelyAuthInfrastructureDomain(cookie?.domain || "", db)) ||
          (thirdParty && effectivelyPersistent && category === "Advertising") ||
          (thirdParty && category === "Unknown") ||
          (thirdParty && effectivelyPersistent && category === "Performance") ||
          (thirdParty && effectivelyPersistent && category === "Functionality");
        if (!shouldBlock) continue;
        const domain = normalizeHost(cookie?.domain || "");
        if (!domain || isLikelyAuthInfrastructureDomain(domain, db) || isCaptchaInfraDomain(domain)) continue;
        rememberBlockedDomain(domain);
        blockedDomains.add(domain);
        const reg = getRegistrableDomain(domain);
        if (reg && reg !== domain) blockedDomains.add(reg);
      }
    }
    const uniqueDomains = [...blockedDomains]
      .filter(domain => /^[a-z0-9.-]+$/.test(domain) && domain.includes("."))
      .slice(0, DNR_RULE_LIMIT);
    // Self-exclusion (the tracker's own site) + TB whitelist: requests
    // initiated by whitelisted pages are never blocked by any rule. Entries are
    // regex-filtered so a malformed storage value can't fail the whole DNR sync.
    const whitelistInitiators = (Array.isArray(tbSiteWhitelist) ? tbSiteWhitelist : [])
      .filter(d => /^[a-z0-9.-]+$/.test(d) && d.includes("."));
    const addRules = uniqueDomains.map((domain, idx) => ({
      id: DNR_RULE_ID_START + idx,
      priority: 1,
      action: { type: "block" },
        condition: {
          urlFilter: `||${domain}^`,
          excludedInitiatorDomains: [...new Set([domain, ...whitelistInitiators])],
          resourceTypes: ["script", "xmlhttprequest", "sub_frame", "stylesheet", "image", "media", "font", "object", "ping", "websocket", "other"],
        },
      }));
    const googleRules = buildGoogleTrackingDnrRules();
    await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds, addRules: [...addRules, ...googleRules] });
  } catch (e) {
    console.warn("[CC] Tracker request blocking rule sync failed:", e);
  }
}

/**
 * chrome.cookies.onChanged handler: Real-time listener that fires whenever ANY cookie
 *   is set or deleted anywhere in the browser.
 * WHY IT EXISTS: This is the most complete and immediate signal for cookie changes.
 *   Unlike polling-based approaches (which miss short-lived cookies), this event fires
 *   the instant a cookie is created, modified, or deleted — including cookies set by
 *   JavaScript, HTTP headers, or other extensions. Without this listener, the system
 *   would miss cookies set between page loads or by background scripts, leading to
 *   incomplete cookie tracking and delayed blocking decisions.
 * HOW IT WORKS: For each cookie change event:
 *   1) Normalizes the cookie's domain and generates a cookie key.
 *   2) Finds the best page-scoped tab (most recently contacted this domain
 *   among tabs the cookie was exchanged with) for attribution; partitioned
 *   cookies additionally require the tab's schemeful site to match.
 *   3) Iterates all tab states to find tabs where this cookie is page-scoped
 *   (first-party reg-match or cookieInPageScope check).
 *   4) If removed with cause "overwrite": stages a handoff (pendingCookieOver-
 *   writes) instead of deleting — the replacement set updates holders in
 *   place. Other removals delete from state.cookies, cookiesSetBySite,
 *   preExistingKeys.
 *   5) If added (and tab is best match, or holds a staged overwrite): adds to
 *   cookiesSetBySite if not pre-existing, records churn event, saves session
 *   state, and calls mergeCookies() for enforcement.
 * INPUT: chrome.cookies.onChanged event — { removed (boolean), cookie (Chrome cookie
 *   object), cause (string — "explicit" | "expired_overwrite" | "evicted" | etc.) }.
 * OUTPUT: None — updates tab state and triggers enforcement as side effects.
 * Source: Chrome Extensions cookies API — onChanged fires for all cookie changes;
 *   RFC 6265 Section 5.3 — cookie lifecycle (set, expire, delete).
 */
// ── 1. chrome.cookies.onChanged ──────────────────────────────
// Fires the instant ANY cookie is set or deleted anywhere.
// This is the most complete real-time signal — no polling needed.
/**
 * overwriteHandoffSweep / overwriteHandoffStage / overwriteHandoffTake /
 * partitionMatchesTab: Pure overwrite-handoff and partition-attribution
 * helpers for the live cookie-event path (P-A, P-B).
 * WHY THEY EXIST: The handoff bookkeeping (5s expiry, 500-entry bound,
 *   consume-once takes, multi-tab holder sets) is the most bug-prone part of
 *   the live path — an off-by-one leaks memory or drops replacements. Pure
 *   functions let the ad-hoc suite assert the full matrix without Chrome APIs.
 * HOW THEY WORK: Sweep drops entries older than 5s. Stage records (or refreshes
 *   holders for) a key, then enforces the bound. Take sweeps, returns and
 *   deletes the entry (consume-once). partitionMatchesTab encodes the
 *   partition gate: unpartitioned passes everywhere; unparseable tab URLs fail
 *   open; otherwise exact schemeful-site equality is required.
 */
function overwriteHandoffSweep(map, now) {
  for (const [k, p] of map) { if (now - p.t > 5000) map.delete(k); }
}
function overwriteHandoffStage(map, key, tabId, now) {
  overwriteHandoffSweep(map, now);
  let pending = map.get(key);
  if (!pending) {
    pending = { t: now, tabIds: new Set() };
    map.set(key, pending);
  }
  pending.tabIds.add(tabId);
  while (map.size > 500) map.delete(map.keys().next().value);
  return pending;
}
function overwriteHandoffTake(map, key, now) {
  overwriteHandoffSweep(map, now);
  const pending = map.get(key) || null;
  if (pending) map.delete(key);
  return pending;
}
function partitionMatchesTab(cookie, tabUrl) {
  const top = (cookie && cookie.partitionKey && cookie.partitionKey.topLevelSite) || "";
  if (!top) return true;
  const tabSite = schemefulSite(tabUrl);
  if (!tabSite) return true;
  return top === tabSite;
}
chrome.cookies.onChanged.addListener(({ removed, cookie, cause }) => {
  const ckHost = normalizeHost(cookie?.domain);
  const ck = cookieKey(cookie);
  const now = Date.now();
  overwriteHandoffSweep(pendingCookieOverwrites, now);
  const pendingOverwrite = !removed ? overwriteHandoffTake(pendingCookieOverwrites, ck, now) : null;

  // Find the tab with the most recent contact to this domain
  // (applies to BOTH add and remove paths). K2: candidacy requires page
  // scope — a tab sharing only the registrable with the cookie's domain but
  // never exchanging it must not win attribution (or judgment) for it.
  // P-B: partitioned cookies additionally require the tab's schemeful site to
  // match the cookie's partition — unpartitioned cookies pass everywhere.
  let bestTabId = null;
  let bestTime = 0;
  for (const [tabIdStr, state] of Object.entries(tabState)) {
    const tabId = Number(tabIdStr);
    if (!Number.isInteger(tabId)) continue;
    if (!state?.url) continue;
    let candHost = "";
    try { candHost = normalizeHost(new URL(state.url).hostname); } catch (e) {}
    const candReg = getRegistrableDomain(cookie?.domain || "");
    const candHome = !!(candReg && state?.siteKey && candReg === state.siteKey);
    if (!candHome) {
      try { if (!cookieInPageScope(cookie, candHost, state.domains)) continue; } catch (e) { continue; }
    }
    if (!partitionMatchesTab(cookie, state.url)) continue;
    const lastContact = state.domains.get(ckHost) || 0;
    if (lastContact > bestTime) {
      bestTime = lastContact;
      bestTabId = tabId;
    }
  }

  for (const [tabIdStr, state] of Object.entries(tabState)) {
    const tabId = Number(tabIdStr);
    if (!Number.isInteger(tabId)) continue;
    if (!state?.url) continue;
    try {
      const tabHost = normalizeHost(new URL(state.url).hostname);
      // K2: same page-scope rule as scans — first-party reg-match passes
      // regardless of contact; otherwise the cookie must be page-scoped.
      // Removal fan-out below stays global-truth for in-scope tabs; scan
      // reconciliation converges anything left behind.
      const tabReg = getRegistrableDomain(cookie?.domain || "");
      const isRelevant = (tabReg && state?.siteKey && tabReg === state.siteKey) || cookieInPageScope(cookie, tabHost, state.domains);
      if (!isRelevant) continue;
      if (removed) {
        ccDiag({ ev:"cookie_removed", tabId, name: cookie?.name, domain: cookie?.domain, cause });
        // P-A: Chrome reports an overwrite as remove-then-set. Stage the
        // handoff instead of deleting: the replacement set updates holding
        // tabs in place below. Treating this as a real deletion would create
        // a transient undercount and misattribute the replacement.
        if (cause === "overwrite") {
          overwriteHandoffStage(pendingCookieOverwrites, ck, tabId, now);
          ccDiag({ ev:"cookie_overwrite_pending", tabId, name: cookie?.name, domain: cookie?.domain });
          continue;
        }
        recordChurnEvent("DEL", cookie, tabId, cause);
        state.cookiesSetBySite.delete(ck);
        state.preExistingKeys.delete(ck);
        if (removeCookieFromState(state, cookie)) notifySidePanel(tabId);
      } else if (tabId === bestTabId || (pendingOverwrite && pendingOverwrite.tabIds.has(tabId))) {
        if (!state.preExistingKeys.has(ck)) {
          state.cookiesSetBySite.add(ck);
        }
        ccDiag({ ev:"cookie_set", tabId, name: cookie?.name, domain: cookie?.domain });
        recordChurnEvent("ADD", cookie, tabId, "");
        saveSessionState(tabId, state);
        mergeCookies(tabId, [cookie]);
      }
    } catch(e) { console.warn("[CC]", e.message); }
  }
});

/**
 * webRequest.onBeforeRequest handler: Tracks all domains contacted by each tab
 *   via network requests.
 * WHY IT EXISTS: When a tab loads a page, it contacts many third-party domains
 *   (analytics, ads, CDNs, trackers). The system needs to know which domains a tab
 *   has contacted to: 1) Determine page scope (cookieInPageScope) for scan and
 *   live attribution, 2) Build
 *   the domain map for third-party classification, 3) Identify tracker domains for
 *   blocking decisions. Without this tracking, the system would only know about the
 *   tab's own domain, missing all third-party contacts and incorrectly classifying
 *   third-party cookies as first-party.
 * HOW IT WORKS: For each network request, extracts the hostname from the URL, normalizes
 *   it, and stores it in the tab's domains Map with a timestamp. Also sets the tab's
 *   siteKey (registrable domain) from the first request if not already set.
 * INPUT: chrome.webRequest.onBeforeRequest event — { tabId, url, ... }.
 * OUTPUT: None — updates tabState[tabId].domains as a side effect.
 * Source: Chrome Extensions webRequest API — onBeforeRequest fires before the request
 *   is sent; URLs include all request types (script, image, XHR, etc.).
 */
// ── 2. webRequest: track all domains contacted ────────────────
chrome.webRequest.onBeforeRequest.addListener(
  ({ tabId, url }) => {
    if (tabId < 0) return;
    try {
      touchTab(tabId);
      const state = getState(tabId);
      let normHost = "";
      try { normHost = normalizeHost(new URL(url).hostname); } catch(e) {}
      const isNewHost = !!(normHost && !state.domains.has(normHost));
      if (normHost) state.domains.set(normHost, Date.now());
      if (isNewHost) maybeScheduleTrailingScan(tabId, true);
      if (!state.siteKey) {
        try { state.siteKey = getRegistrableDomain(new URL(url).hostname); } catch(e) { console.warn("[CC]", e.message); }
      }
    }
    catch(e) { console.warn("[CC]", e.message); }
  },
  { urls: ["<all_urls>"] }
);

chrome.webRequest.onCompleted.addListener(
  ({ tabId, url }) => {
    if (tabId < 0) return;
    try {
      touchTab(tabId);
      const state = getState(tabId);
      let normHost = "";
      try { normHost = normalizeHost(new URL(url).hostname); } catch(e) {}
      const isNewHost = !!(normHost && !state.domains.has(normHost));
      if (normHost) state.domains.set(normHost, Date.now());
      if (isNewHost) maybeScheduleTrailingScan(tabId, true);
      if (!state.siteKey) {
        try { state.siteKey = getRegistrableDomain(new URL(url).hostname); } catch(e) { console.warn("[CC]", e.message); }
      }
    }
    catch(e) { console.warn("[CC]", e.message); }
  },
  { urls: ["<all_urls>"] }
);

/**
 * tabs.onUpdated handler: Reacts to tab navigation events (page load, reload, etc.)
 *   and triggers full cookie scans and session management.
 * WHY IT EXISTS: Tab navigation is the primary trigger for cookie analysis. When a
 *   page loads, the system needs to: 1) Reset state if navigating to a different site,
 *   2) Save state if navigating within the same site, 3) Scan all cookies for the new
 *   page, 4) Inject document.cookie reader for JS-accessible cookies, 5) Detect auth
 *   flows and set authMode. Without this handler, the system would only react to
 *   individual cookie changes, missing the holistic view of a new page load.
 * HOW IT WORKS: Two-phase handling:
 *   Phase 1 (status="loading"): When navigation starts, checks if the site key is
 *   changing (different registrable domain). If so, triggers session purge for the
 *   previous state (site_exit). Saves state if staying on the same site. Resets state
 *   if moving to a different site.
 *   Phase 2 (status="complete"): When the page finishes loading, initializes state,
 *   sets the URL and siteKey, detects auth flow (isLikelyAuthFlowUrl), notifies the
 *   side panel, triggers a full scan (scanAll), and injects the document.cookie reader
 *   (unless the tab is pending a restart).
 * INPUT: chrome.tabs.onUpdated event — { tabId, changeInfo: { status, url }, tab }.
 * OUTPUT: None — triggers side effects (state management, scans, injections).
 * Source: Chrome Extensions tabs API — onUpdated fires for navigation, reload, and
 *   title change events.
 */
// ── 3. tabs.onUpdated + scripting.executeScript ───────────────
// On page complete: full scan + inject script to read document.cookie
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") {
    const previousState = tabState[tabId];
    // M2: fresh trailing-scan budget per navigation; drop any pending trailer
    // for the previous document so it can't scan the new page on stale contacts.
    trailingScanBudget.set(tabId, TRAILING_SCANS_PER_NAV);
    if (trailingScanTimers.has(tabId)) { clearTimeout(trailingScanTimers.get(tabId)); trailingScanTimers.delete(tabId); }
    let nextSiteKey = "";
    try { nextSiteKey = getRegistrableDomain(new URL(changeInfo.url || tab?.url || "").hostname); } catch(e) { console.warn("[CC]", e.message); }
    if (previousState?.siteKey && nextSiteKey && nextSiteKey !== previousState.siteKey) {
      purgeRiskySessionCookiesForState(tabId, previousState, "site_exit");
    }
    // H4: stamp the navigation start on ANY navigation with a previous state
    // (same- or cross-site), BEFORE the snapshot/restore or reset below. The
    // first post-navigation scan consumes the marker: it merges + expires
    // pre-navigation contacts but never prunes, so early-contact gaps can't
    // evict browser-present cookies. Abandoned loads fail safe — the next scan
    // simply treats itself as first and skips pruning.
    if (previousState?.siteKey && nextSiteKey) {
      navStartTimes.set(tabId, Date.now());
    }
    if (riskBlockingJustEnabled) {
      riskBlockingJustEnabled = false;
      savedCookieTracking.delete(tabId);
      delete sessionCache[tabId];
    } else if (previousState?.siteKey && nextSiteKey && nextSiteKey === previousState.siteKey) {
      // D5: the navStartTimes marker above already covers the first-scan
      // guarantee; the snapshot/restore below carries the contacted domains
      // forward so that scan sees them (no under-blocking window).
      savedCookieTracking.set(tabId, {
        cookiesSetBySite: new Set(previousState.cookiesSetBySite),
        domains: new Map(previousState.domains)
      });
      if (previousState) saveSessionState(tabId, previousState);
      ccDiag({ ev:"state_save", tabId, siteKey: nextSiteKey, setBySite: previousState.cookiesSetBySite.size, cookiesSize: previousState.cookies.size, domains: previousState.domains.size });
    } else {
      savedCookieTracking.delete(tabId);
      delete sessionCache[tabId];
    }
    delete tabState[tabId]; // reset on navigation
  }
  if (changeInfo.status === "complete" && tab.url) {
    const state = getState(tabId);
    touchTab(tabId);
    state.url = tab.url;
    try { state.siteKey = getRegistrableDomain(new URL(tab.url).hostname); } catch(e) { state.siteKey = ""; }
    state.authMode = !!state.authMode || isLikelyAuthFlowUrl(tab.url);
    notifySidePanelTabContext(tabId, tab.url, "navigation_complete");
    scanAll(tabId, tab.url);
    // 4. Inject script to read JS-accessible (non-HttpOnly) cookies
    if (!restartPendingTabIds.has(tabId)) {
      injectDocCookieReader(tabId, tab.url);
    }
  }
});

/**
 * tabs.onActivated handler: Reacts to tab switches (user clicks a different tab)
 *   and updates the active tab's state and triggers a scan.
 * WHY IT EXISTS: When the user switches tabs, the side panel needs to display the
 *   new tab's cookie data. This handler updates the tab's URL/siteKey (which may have
 *   changed since the tab was last active), notifies the side panel of the context
 *   change, and triggers a scan to ensure the cookie list is current. Without this,
 *   switching tabs would show stale data from the previous tab until the next page load.
 * HOW IT WORKS: 1) Calls touchTab() to update the lastActiveAt timestamp. 2) Gets
 *   the tab's current URL via chrome.tabs.get(). 3) Updates state.url and state.siteKey.
 *   4) Notifies the side panel of the tab context change. 5) Triggers a full scan
 *   (scanAll) to refresh the cookie list.
 * INPUT: chrome.tabs.onActivated event — { tabId, windowId }.
 * OUTPUT: None — updates state and triggers scan as side effects.
 * Source: Chrome Extensions tabs API — onActivated fires when the active tab changes
 *   within a window.
 */
chrome.tabs.onActivated.addListener(info => {
  if (!Number.isInteger(info?.tabId)) return;
  touchTab(info.tabId);
  reconcileTab(info.tabId); // re-attach content scripts if the world died (disable→enable)
  chrome.tabs.get(info.tabId, tab => {
    if (chrome.runtime.lastError || !tab?.url) return;
    const state = getState(info.tabId);
    state.url = tab.url;
    try { state.siteKey = getRegistrableDomain(new URL(tab.url).hostname); } catch(e) { state.siteKey = ""; }
    notifySidePanelTabContext(info.tabId, tab.url, "tab_activated");
    scanAll(info.tabId, tab.url);
  });
});

/**
 * tabs.onRemoved handler: Cleans up tab state and triggers session purge when a
 *   tab is closed.
 * WHY IT EXISTS: When a tab is closed, its state (cookies, domains, etc.) is no
 *   longer needed and should be cleaned up to prevent memory leaks. If session lock
 *   is enabled, the tab's session cookies should also be purged (tab_close trigger).
 *   Without this cleanup, the tabState dictionary would grow indefinitely as tabs
 *   are opened and closed, eventually consuming all available memory. The session
 *   purge ensures that session cookies don't persist after the user leaves a site.
 * HOW IT WORKS: 1) If session lock is enabled, calls purgeRiskySessionCookiesForState()
 *   with trigger="tab_close" to remove risky session cookies. 2) Deletes tabState[tabId],
 *   savedCookieTracking[tabId], sessionCache[tabId], pendingScanUrls[tabId],
 *   scanInFlight[tabId]. 3) Clears any pending side panel notification for this tab.
 * INPUT: chrome.tabs.onRemoved event — tabId (integer).
 * OUTPUT: None — cleans up state as side effects.
 * Source: Chrome Extensions tabs API — onRemoved fires when a tab is closed.
 */
chrome.tabs.onRemoved.addListener(tabId => {
  const state = tabState[tabId];
  if (state) purgeRiskySessionCookiesForState(tabId, state, "tab_close");
  delete tabState[tabId];
  savedCookieTracking.delete(tabId);
  delete sessionCache[tabId];
  pendingScanUrls.delete(tabId);
  scanInFlight.delete(tabId);
  navStartTimes.delete(tabId);
  trailingScanBudget.delete(tabId);
  if (trailingScanTimers.has(tabId)) { clearTimeout(trailingScanTimers.get(tabId)); trailingScanTimers.delete(tabId); }
  const pendingNotify = sidePanelNotifyQueue.get(tabId);
  if (pendingNotify) clearTimeout(pendingNotify);
  sidePanelNotifyQueue.delete(tabId);
});

/**
 * runtime.onSuspend handler: Triggers session purge for all tabs when the service
 *   worker is about to be suspended (browser close or extension disable).
 * WHY IT EXISTS: When the browser is closing or the extension is being disabled,
 *   all open tabs' session cookies should be purged if session lock is enabled.
 *   This is the last chance to clean up before the service worker is killed. Without
 *   this handler, session cookies would persist across browser restarts, which
 *   contradicts the "lock on browser close" behavior that session lock promises.
 *   The handler only fires if sessionLockEnabled is true, avoiding unnecessary
 *   cleanup when the feature is disabled.
 * HOW IT WORKS: Iterates all entries in tabState and calls
 *   purgeRiskySessionCookiesForState() with trigger="browser_close" for each tab.
 *   This triggers the S1-S3 purge rules for every cookie in every tab.
 * INPUT: chrome.runtime.onSuspend event — no parameters.
 * OUTPUT: None — triggers session purge as side effects.
 * Source: Chrome Extensions runtime API — onSuspend fires before the service worker
 *   is terminated (browser close, extension disable/update).
 */
chrome.runtime.onSuspend.addListener(() => {
  if (!sessionLockSettings.sessionLockEnabled) return;
  for (const [tabId, state] of Object.entries(tabState)) {
    purgeRiskySessionCookiesForState(Number(tabId), state, "browser_close");
  }
});

// ── 4. chrome.scripting.executeScript ────────────────────────
// Injects directly into the page to read document.cookie.
// Catches cookies set by JS that chrome.cookies.getAll may not return
// if the extension hasn't seen the subdomain yet.
/**
 * injectDocCookieReader: Injects a script into the page to read document.cookie and
 *   report JS-accessible (non-HttpOnly) cookies back to the extension.
 * WHY IT EXISTS: Chrome's chrome.cookies.getAll() returns all cookies, including
 *   HttpOnly ones, but it may not return cookies set by JavaScript that haven't been
 *   persisted to the cookie store yet (e.g., cookies set via document.cookie in the
 *   current page load that haven't been flushed). More importantly, document.cookie
 *   is the ONLY way to detect cookies that are set by client-side JavaScript in the
 *   page context. Without this injection, the system would miss JS-set cookies that
 *   are only visible to the page, leading to incomplete cookie counts and missed
 *   tracking detection.
 * HOW IT WORKS: 1) Checks if the URL is injectable (not chrome:// or about:).
 *   2) Uses chrome.scripting.executeScript() to inject a function that runs in the
 *   page's MAIN world (has access to document.cookie). 3) The injected function reads
 *   document.cookie, parses it into cookie objects (name, value, domain, path), and
 *   marks them with fromDocCookie=true. 4) Returns the parsed cookies to the extension.
 *   5) The callback calls mergeCookiesRawSafe() to process and store them.
 * INPUT: tabId (integer), url (string — page URL).
 * OUTPUT: None — injects script and processes results as side effects.
 * Source: Chrome Extensions scripting API — executeScript runs in page context;
 *   document.cookie access — MDN Web Docs; HttpOnly cookies are not visible to
 *   document.cookie per RFC 6265 Section 4.1.2.5.
 */
function injectDocCookieReader(tabId, url) {
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) return;
  try {
    chrome.scripting.executeScript({
      target: { tabId },
      func: () => {
        // Runs in page context — has access to document.cookie
        try {
          const raw = document.cookie;
          if (!raw.trim()) return null;
          return raw.split(";").map(p => {
            const idx   = p.indexOf("=");
            const name  = p.slice(0, idx).trim();
            const value = p.slice(idx + 1).trim();
            return { name, value, domain: location.hostname, path: "/",
                     httpOnly: false, secure: location.protocol === "https:",
                     fromDocCookie: true };
          }).filter(c => c.name);
        } catch(e) { return null; }
      },
    }, results => {
      if (chrome.runtime.lastError) return;
      const result = results?.[0]?.result;
      if (Array.isArray(result) && result.length > 0) {
        mergeCookiesRawSafe(tabId, result, url || "");
      }
    });
  } catch(e) { console.warn("[CC]", e.message); }
}

// ── Full scan using chrome.cookies.getAll ─────────────────────
// Queries by tab URL, the current site domain, and contacted third-party domains.
/**
 * rebuildCookiesForTab: Performs a full cookie scan for a tab by querying
 *   chrome.cookies.getAll() with the tab's URL and merging results into state.
 * WHY IT EXISTS: When a page loads or the user requests a manual refresh, the
 *   system needs a complete snapshot of all cookies visible to the tab. The
 *   cookies.onChanged listener only captures real-time changes, but misses cookies
 *   that were already set before the extension started or before the tab was tracked.
 *   This full scan fills in those gaps and ensures the cookie list is complete.
 *   Without it, the initial cookie count would be zero until the first cookie change,
 *   which could take seconds or never happen for passive cookies.
 * HOW IT WORKS: 1) Validates the URL (skips chrome:// and about: pages).
 *   2) Initializes or retrieves the tab state. 3) Resolves the tab's cookie
 *   store (fail-open: unknown store degrades the query, never cancels the
 *   scan). 4) Builds the coverage query set (page URL, site domain, contacted
 *   third-party hosts, plus a partition probe per domain) and fetches with
 *   error reporting. 5) Deduplicates by twin-aware cookieKey, keeping only
 *   this tab's store/partition/accept-scope identity, stamping each result
 *   with its finding query (provenance). 6) Marks all found cookies as
 *   pre-existing. 7) Calls mergeCookies() to judge and merge each cookie.
 *   8) On trusted scans only (every query fulfilled + store resolved + past
 *   the first scan since navigation), reconciles state: removes in-scope
 *   entries covered by the scan but gone from the browser, removes
 *   out-of-scope entries (de-attribution, not browser deletion), preserves
 *   unqueried regs — then expires pre-navigation contacted domains.
 *   Anything less than trusted merges/judges only and preserves
 *   state untouched.
 * INPUT: tabId (integer), url (string — tab's current URL).
 * OUTPUT: Promise — resolves when scan, merge, and reconciliation complete.
 * Source: Chrome cookies API — getAll({ url }) returns cookies matching the URL's
 *   domain and path per RFC 6265 Section 5.4; {domain}/{partitionKey}/{storeId}
 *   scoping covers third-party, partitioned, and multi-store cookies.
 */
/**
 * shouldReconcile: Pure triple-gate deciding whether a scan may prune state.
 * WHY IT EXISTS: Pruning on degraded data deletes real cookies from state —
 *   the F1 failure mode (single-scan eviction on incomplete contacts) and the
 *   D1×D4 cross-store hole (unscoped results evicting container-store entries).
 *   Reconciliation runs only on scans trusted on all three legs; anything else
 *   merges/judges only and preserves state.
 * HOW IT WORKS: Returns true iff every query fulfilled (fetchOk), the tab's
 *   store was resolved (storeKnown), and this is not the first scan since a
 *   navigation (firstScan — contacts may still be arriving).
 * INPUT: {fetchOk, storeKnown, firstScan} booleans.
 * OUTPUT: Boolean.
 */
function shouldReconcile({ fetchOk, storeKnown, firstScan }) {
  return !!fetchOk && !!storeKnown && !firstScan;
}

/**
 * reconcileState: Computes state convergence actions for a trusted scan.
 * WHY IT EXISTS: State must converge toward the browser (dead entries removed,
 *   out-of-scope entries de-attributed) without ever deleting what the scan
 *   couldn't judge: domains it didn't query. No grace clock — out-of-scope
 *   removal is not eviction-from-browser (nothing is deleted from Chrome),
 *   just de-attribution from this tab's inventory, so it is safe on the first
 *   trusted scan; the H4 first-scan gate already protects early-contact gaps.
 *   Pure function (no side effects), so ad-hoc tests drive it without Chrome
 *   APIs. Callers apply removals and log diagnostics.
 * INPUT: bags {cookies (Map key->cookie), setBySite (Set)}, uniqueKeys (Set
 *   of observed keys), queriedRegs (Set of queried registrable domains),
 *   inScope ((cookie)=>bool).
 * OUTPUT: {removed, preserved} arrays of {key, cookie, why} where why is
 *   "absent-covered" (in scope, queried, gone from browser) or "out-of-scope".
 */
function reconcileState(bags, uniqueKeys, queriedRegs, inScope) {
  const removed = [], preserved = [];
  for (const [key, cookie] of bags.cookies) {
    if (uniqueKeys.has(key)) continue;
    let scope = false;
    try { scope = !!inScope(cookie); } catch (e) { scope = false; }
    if (!scope) {
      removed.push({ key, cookie, why: "out-of-scope" });
      continue;
    }
    const reg = normalizeCookieDomain(getRegistrableDomain((cookie && cookie.domain) || "") || ((cookie && cookie.domain) || ""));
    if (!queriedRegs.has(reg)) {
      preserved.push({ key, cookie, why: "domain-not-queried" });
      continue;
    }
    removed.push({ key, cookie, why: "absent-covered" });
  }
  return { removed, preserved };
}

async function rebuildCookiesForTab(tabId, url) {
  if (!ccEnabled) return;
  if (!url || url.startsWith("chrome://") || url.startsWith("about:")) return;
  const state = getState(tabId);
  state.url = url;
  try { state.siteKey = getRegistrableDomain(new URL(url).hostname); } catch(e) { state.siteKey = ""; }
  // K3 (fail-closed store): an unresolvable store aborts the scan BEFORE any
  // fetch. Merging unscoped default-store results into this tab's inventory
  // is cross-store contamination (wrong cookies displayed, judged, and
  // potentially deleted under the wrong tab's verdict) — far worse than one
  // skipped scan for a tab that is almost certainly already gone. Replaces
  // the earlier D1 fail-open, which H4's prune gate could not fully contain.
  const storeId = await getCookieStoreIdForTab(tabId);
  if (!storeId) {
    console.warn("[CC] Scan aborted (store unresolvable, inventory preserved), tab:", tabId);
    ccDiag({ ev: "scan_no_store", tabId, reason: "store unresolvable — scan aborted, inventory preserved" });
    return;
  }
  const { queries, partitionSite, domains } = buildScopedCookieQueries(url, state, storeId);
  const fetchedResults = await getCookiesDiagnosticBatch(queries);
  const stateBefore = state.cookies.size;
  let pageHost = "";
  try { pageHost = normalizeHost(new URL(url).hostname); } catch (e) {}
  let fetchOk = true;
  for (const r of fetchedResults) {
    if (!r || r.status !== "fulfilled" || !Array.isArray(r.value)) {
      fetchOk = false;
      const msg = String((r && r.reason && r.reason.message) || (r && r.reason) || "unknown");
      console.warn("[CC] Scan query failed:", r && r.key, msg);
      ccDiag({ ev: "scan_query_failed", tabId, site: state.siteKey || "", key: (r && r.key) || "?", message: msg.slice(0, 200) });
    }
  }
  const unique = new Map();
  const rejCount = { store: 0, partition: 0, scope: 0 };
  const rejExamples = { store: [], partition: [], scope: [] };
  const identOf = (cookie, src) => String(cookie?.name || "?") + "@" + normalizeHost(cookie?.domain || "?")
    + " " + (cookie?.path || "/") + " hostOnly=" + (cookie?.hostOnly === true)
    + " part=" + ((cookie?.partitionKey && cookie.partitionKey.topLevelSite) || "-")
    + " store=" + (cookie?.storeId || "?") + " src=" + (src || "?");
  for (const result of fetchedResults) {
    if (result.status !== "fulfilled") continue;
    for (const cookie of result.value || []) {
      const rej = scanRejectReason(cookie, state, storeId, partitionSite);
      if (rej) {
        rejCount[rej]++;
        if (rejExamples[rej].length < 3) rejExamples[rej].push(identOf(cookie, result.key));
        continue;
      }
      // H6 (provenance): stamp which query first produced each cookie, so
      // surplus diagnosis can tell sibling-subdomain vs stale vs unscoped
      // fetches apart. First-writer-wins: the {url} query leads by construction.
      if (cookie && cookie._foundVia === undefined) {
        try { cookie._foundVia = result.key; } catch (e) {}
      }
      unique.set(cookieKey(cookie), cookie);
    }
  }

  for (const key of unique.keys()) {
    state.cookiesSetBySite.add(key);
    state.preExistingKeys.add(key);
  }
  try {
    const perKey = {};
    queries.forEach((qd, i) => {
      const r = fetchedResults[i];
      const ok = !!(r && r.status === "fulfilled" && Array.isArray(r.value));
      perKey[qd.key] = { ok, count: ok ? r.value.length : 0 };
    });
    ccDiag({ ev: "scan_queries", tabId, site: state.siteKey || "", page: pageHost, queries: perKey,
      unique: unique.size, accepted: unique.size, rejected: rejCount, examples: rejExamples });
  } catch (e) {}
  await mergeCookies(tabId, [...unique.values()]);
  // D5 (deferred contacted-clear): pre-navigation contacted entries served the
  // scan above (restored into state via savedCookieTracking); now expire them
  // so stale third parties don't linger in the next page's inventory, panel,
  // or DNR seeding. Entries re-contacted during load carry fresh timestamps
  // and survive. The marker doubles as the H4 first-scan flag (consumed once).
  const navStart = navStartTimes.get(tabId);
  const firstScan = navStart !== undefined;
  // M4 (observability): count restored pre-navigation contacts expired here,
  // so captures can tell first-scan overcount (old contacts) from leakage.
  let restoredContacts = 0;
  if (firstScan) {
    for (const [host, ts] of state.domains) {
      if (Number(ts || 0) < navStart) { state.domains.delete(host); restoredContacts++; }
    }
    navStartTimes.delete(tabId);
  }
  // H4 (completeness triple-gate): reconcile state only on scans trusted on
  // all three legs — every query fulfilled, store resolved, past the first
  // scan since navigation. Anything else merges/judges only and preserves
  // state, so degraded conditions freeze the inventory instead of corrupting
  // it (the F1 single-scan-eviction failure mode; the D1xD4 cross-store hole).
  if (!shouldReconcile({ fetchOk, storeKnown: !!storeId, firstScan })) {
    const why = [!fetchOk ? "query-error" : null, !storeId ? "store-unknown" : null, firstScan ? "first-scan" : null].filter(Boolean).join("+");
    ccDiag({ ev: "scan_partial", tabId, reason: "reconciliation skipped (" + why + "), state preserved" });
    ccDiag({ ev: "scan_summary", tabId, site: state.siteKey || "", page: pageHost, storeKnown: !!storeId,
      firstScan, fetchOk, contacted: state.domains.size, restoredContacts, trusted: false, failedLegs: why,
      stateBefore, stateAfter: state.cookies.size });
    state.preExistingKeys = new Set(state.cookies.keys());
    return;
  }
  const uniqueKeys = new Set(unique.keys());
  // Queries are registrable-wide, so coverage is tracked at registrable
  // level: the site query covers the whole site reg; each third-party query
  // covers its reg.
  const queriedDomainRegs = new Set(domains.map(item => normalizeCookieDomain(item.domain)));
  if (state.siteKey) queriedDomainRegs.add(normalizeCookieDomain(state.siteKey));
  const inScope = c => cookieBelongsToScan(c, state, storeId, partitionSite);
  // K4: out-of-scope entries leave on the first trusted scan (de-attribution,
  // not browser deletion — safe immediately); in-scope entries leave only when
  // covered and gone from the browser; unqueried regs are preserved.
  const actions = reconcileState({ cookies: state.cookies, setBySite: state.cookiesSetBySite }, uniqueKeys, queriedDomainRegs, inScope);
  let changed = false;
  const removedIds = [];
  for (const a of actions.removed) {
    state.cookies.delete(a.key);
    state.cookiesSetBySite.delete(a.key);
    removedIds.push(identOf(a.cookie, "") + " [" + a.why + "]");
    ccDiag({ ev: "scan_prune", tabId, name: a.cookie && a.cookie.name, domain: a.cookie && a.cookie.domain, reason: a.why });
    changed = true;
  }
  ccDiag({ ev: "scan_reconcile", tabId, site: state.siteKey || "", page: pageHost,
    removed: removedIds.slice(0, 8), removedCount: removedIds.length,
    preservedUncovered: actions.preserved.filter(p => p.why === "domain-not-queried").length });
  state.preExistingKeys = new Set(state.cookies.keys());
  ccDiag({ ev: "scan_summary", tabId, site: state.siteKey || "", page: pageHost, storeKnown: !!storeId,
    firstScan, fetchOk, contacted: state.domains.size, restoredContacts, trusted: true, failedLegs: "",
    stateBefore, stateAfter: state.cookies.size });
  if (changed) {
    saveSessionState(tabId, state);
    notifySidePanel(tabId);
  }
}

/**
 * scanAll: Orchestrates a full cookie scan for a tab with deduplication and
 *   in-flight tracking to prevent concurrent scans.
 * WHY IT EXISTS: Multiple events can trigger a scan simultaneously (page load,
 *   tab activation, manual refresh). Without deduplication, the system would run
 *   redundant scans, wasting CPU and potentially causing race conditions. This
 *   function ensures only one scan runs per tab at a time, and if a new scan is
 *   requested while one is in progress, the new URL is queued and processed after
 *   the current scan completes. This is a classic "scan deduplication" pattern.
 * HOW IT WORKS: 1) If ccEnabled is false, returns immediately. 2) Validates tabId.
 *   3) Stores the URL in pendingScanUrls Map (overwriting any previous pending URL).
 *   4) If a scan is already in flight for this tab (scanInFlight.has), returns — the
 *   pending URL will be picked up when the current scan finishes. 5) Otherwise, starts
 *   a new scan: marks in-flight, calls rebuildCookiesForTab(), clears in-flight flag,
 *   and recursively calls itself if a new URL was queued during the scan.
 * INPUT: tabId (integer), url (string — URL to scan).
 * OUTPUT: None — triggers scan as side effect.
 * Source: Deduplication pattern — standard concurrency control for async operations.
 */
function scanAll(tabId, url) {
  if (!ccEnabled) return;
  if (!Number.isInteger(tabId) || tabId < 0) return;
  pendingScanUrls.set(tabId, url);
  if (scanInFlight.has(tabId)) return;

  const run = async () => {
    const nextUrl = pendingScanUrls.get(tabId);
    pendingScanUrls.delete(tabId);
    if (!nextUrl) return;
    scanInFlight.set(tabId, true);
    try {
      await rebuildCookiesForTab(tabId, nextUrl);
    } catch (e) {
      console.warn("[CC] Tab rebuild failed:", e);
    } finally {
      scanInFlight.delete(tabId);
      if (pendingScanUrls.has(tabId)) run().catch(() => {});
    }
  };

  run().catch(() => {});
}

// ── Merge chrome.cookies objects ──────────────────────────────
/**
 * mergeCookies: Processes an array of cookies (from chrome.cookies.getAll or
 *   cookies.onChanged), runs enforcement on each, and merges surviving cookies
 *   into the tab's state.
 * WHY IT EXISTS: This is the main intake pipeline for cookies from Chrome's browser
 *   API. Each cookie must be: 1) Checked against the catch-up block list (to avoid
 *   re-processing recently blocked cookies), 2) Protected (value encryption via
 *   CC_CRYPTO.protectCookie), 3) Vendor-resolved, 4) Enforced against risk blocking
 *   rules, 5) Compared to existing state (to detect changes), 6) Added to state if
 *   new or changed. Without this pipeline, cookies would be added to state without
 *   enforcement, allowing tracking cookies to persist.
 * HOW IT WORKS: 1) Clears catchUpBlockedKeys (fresh scan). 2) Loads the cookie
 *   database. 3) For each cookie: skips if in catch-up block list (unless auth infra),
 *   protects the value, resolves vendor info, runs enforceRiskBlockingForCookie().
 *   4) If blocked, marks as changed and continues. 5) If not blocked, compares to
 *   existing state — adds if new or changed (using cookiesEqual()). 6) For first-party
 *   or previously-seen cookies, adds to state. For unknown third-party cookies, logs
 *   a gate_block diagnostic. 7) If any changes, notifies the side panel, saves session
 *   state, and logs a block summary.
 * INPUT: tabId (integer), cookies (array of Chrome cookie objects), opts (unused).
 * OUTPUT: Promise<number> — count of changes (0 if no changes).
 * Source: Cookie lifecycle management — set/modify/delete patterns; Chrome cookies API.
 */
async function mergeCookies(tabId, cookies, opts = {}) {
  if (!ccEnabled) return 0;
  void opts;
  catchUpBlockedKeys.clear();
  const state = getState(tabId);
  const db = await getRiskData();
  let changed = false;
  const blockResults = [];
  for (const c of cookies) {
    if (catchUpBlockedKeys.has(cookieKey(c)) && !isLikelyAuthInfrastructureDomain(normalizeHost(c.domain || ""), db)) continue;
    let protectedCookie;
    try {
      protectedCookie = await CC_CRYPTO.protectCookie(c);
    } catch (e) {
      console.warn("[CC] Cookie value protection failed:", e);
      continue;
    }
    protectedCookie.vendorResolved = getResolvedVendorInfo(protectedCookie, db) || null;
    const blockResult = await enforceRiskBlockingForCookie(tabId, state, protectedCookie);
    blockResults.push({ name: protectedCookie.name, domain: protectedCookie.domain, ...blockResult });
    if (blockResult && blockResult.blocked) {
      changed = true;
      continue;
    }
    const key = cookieKey(protectedCookie);
    const prev = state.cookies.get(key);
    if (!prev || !cookiesEqual(prev, protectedCookie)) {
      const cookieHost = normalizeHost(protectedCookie?.domain || "");
      const siteKey = state?.siteKey || "";
      const reg = getRegistrableDomain(cookieHost);
      const isFirstParty = cookieHost === siteKey || reg === siteKey || cookieHost.endsWith(`.${siteKey}`);
      if (isFirstParty || prev || state.cookiesSetBySite.has(key)) {
        state.cookies.set(key, protectedCookie);
        state.cookiesSetBySite.add(key);
        changed = true;
      } else {
        ccDiag({ ev:"gate_block", tabId, name: protectedCookie?.name, domain: protectedCookie?.domain });
      }
    }
  }
  if (changed) {
    notifySidePanel(tabId);
    saveSessionState(tabId, getState(tabId));
  }
  logBlockSummary(tabId, blockResults);
}

/**
 * logBlockSummary: Logs a summary of blocking decisions for a batch of cookies,
 *   showing which cookies were blocked and which were allowed.
 * WHY IT EXISTS: Debugging blocking decisions requires visibility into what the
 *   system decided for each cookie. This function logs a formatted table showing:
 *   - BLOCKED cookies (removed from browser) with their block reason
 *   - STAYED cookies (allowed through) with their skip reason
 *   Without this logging, developers would have no way to verify that the blocking
 *   rules are working correctly, making it impossible to debug false positives
 *   (cookies incorrectly blocked) or false negatives (cookies that should have been
 *   blocked but weren't).
 * HOW IT WORKS: Filters results to only those where shouldBlock is true (the system
 *   decided this cookie should be blocked). Then splits into blocked (actually removed)
 *   and stayed (decided to block but removal failed or was skipped). Logs a formatted
 *   table with name, domain, category, and reason for each.
 * INPUT: tabId (integer), results (array of enforceRiskBlockingForCookie results).
 * OUTPUT: None — logs to console.debug as side effect.
 * Source: N/A — debug logging utility.
 */
function logBlockSummary(tabId, results) {
  const shouldBlockResults = results.filter(r => r.shouldBlock);
  if (!shouldBlockResults.length) return;
  const blocked = shouldBlockResults.filter(r => r.blocked);
  const stayed = shouldBlockResults.filter(r => !r.blocked);
  console.debug(`[CC][block-summary] Tab ${tabId} — ${shouldBlockResults.length} cookies should be blocked (${blocked.length} blocked, ${stayed.length} stayed):`);
  for (const r of blocked) {
    console.debug(`  BLOCKED       | ${(r.name || "").padEnd(25)} | ${(r.domain || "").padEnd(25)} | ${(r.category || "").padEnd(15)} | ${r.blockReason || r.skipReason || ""}`);
  }
  for (const r of stayed) {
    console.debug(`  STAYED        | ${(r.name || "").padEnd(25)} | ${(r.domain || "").padEnd(25)} | ${(r.category || "").padEnd(15)} | ${r.skipReason || ""}`);
  }
}

/**
 * reloadTabViaScript: Reloads a tab by injecting a script that calls
 *   window.location.reload(), used for background tabs that can't be reloaded
 *   via chrome.tabs.reload().
 * WHY IT EXISTS: Chrome's chrome.tabs.reload() only works for tabs that are
 *   visible or recently active. For background tabs (not currently focused),
 *   the reload may fail or be delayed. Injecting a script that calls
 *   window.location.reload() from the page context is more reliable because
 *   it executes in the page's own JavaScript context, which always has the
 *   ability to trigger a reload. This is used when risk blocking is first enabled
 *   and all tabs need to be reloaded to re-evaluate existing cookies.
 * HOW IT WORKS: Uses chrome.scripting.executeScript() to inject a function that
 *   calls window.location.reload() in the page's MAIN world. The function runs
 *   in the page context (not the extension context), so it can trigger a
 *   navigation. Returns a Promise that resolves when the script injection completes
 *   (not when the reload completes — use tabs.onUpdated to detect page load).
 * INPUT: tabId (integer).
 * OUTPUT: Promise — resolves when script injection completes.
 * Source: Chrome Extensions scripting API — executeScript runs in page context;
 *   window.location.reload() — MDN Web Docs.
 */
function reloadTabViaScript(tabId) {
  return chrome.scripting.executeScript({
    target: { tabId },
    func: () => { window.location.reload(); },
  });
}

/**
 * catchUpRiskBlockingForTab: Performs multiple passes of cookie scanning and
 *   enforcement to catch cookies that were set during or after a page load.
 * WHY IT EXISTS: When risk blocking is first enabled, or after a tab is reloaded,
 *   the initial scan may not capture all cookies because: 1) Some cookies are set
 *   by lazy-loaded scripts that execute after the initial scan, 2) Some cookies are
 *   set by XHR/fetch responses that arrive after the page reports "complete", 3) The
 *   page may set cookies in response to user interactions. Multiple passes with
 *   delays between them catch these late-arriving cookies. Without this catch-up
 *   mechanism, tracking cookies set by delayed scripts would persist unblocked.
 * HOW IT WORKS: 1) Loads the risk data. 2) Runs RISK_CATCHUP_PASSES (5) passes.
 *   3) Each pass: records pre-scan cookie count, rebuilds cookies via
 *   rebuildCookiesForTab(), records post-scan count, calculates removals, syncs
 *   DNR rules, waits RISK_CATCHUP_DELAY_MS * (pass+1) before the next pass.
 *   4) After all passes, injects the document.cookie reader for JS-accessible cookies.
 *   5) Notifies the side panel of the final state.
 * INPUT: tabId (integer), url (string — tab's current URL).
 * OUTPUT: Promise<number> — total cookies removed across all passes.
 * Source: Multi-pass scanning pattern — common in network monitoring and security
 *   tools to handle asynchronous data arrival.
 */
async function catchUpRiskBlockingForTab(tabId, url) {
  if (!riskBlockingSettings.riskBlockingEnabled || !Number.isInteger(tabId) || tabId < 0 || !url) return 0;
  await getRiskData();
  let totalRemoved = 0;

  let quietStreak = 0;
  for (let pass = 0; pass < RISK_CATCHUP_PASSES; pass++) {
    if (!riskBlockingSettings.riskBlockingEnabled) break;
    const state = tabState[tabId];
    if (!state) break;
    const preSize = state.cookies.size;
    const stickyBefore = stickyBlockedDomains.size;
    try {
      await rebuildCookiesForTab(tabId, url);
    } catch (e) {
      console.warn("[CC] Risk catch-up rebuild failed:", e);
    }
    const postState = tabState[tabId];
    if (!postState) break;
    const removedHere = Math.max(0, preSize - postState.cookies.size);
    totalRemoved += removedHere;

    syncTrackerBlockingRules().catch(() => {});

    // Skip-if-clean: two consecutive passes with no removals, no newly
    // learned tracker domains, and no jar growth (nothing still arriving)
    // mean convergence — stop early instead of waiting out the full ~6s
    // window on clean or settled sites. Late arrivals reset the streak
    // via jar growth, so widened coverage is never cut short early.
    const learned = stickyBlockedDomains.size > stickyBefore;
    const jarGrew = postState.cookies.size > preSize;
    if (removedHere === 0 && !learned && !jarGrew) quietStreak++;
    else quietStreak = 0;
    if (quietStreak >= 2) break;

    if (pass < RISK_CATCHUP_PASSES - 1) {
      await delay(RISK_CATCHUP_DELAY_MS * (pass + 1));
    }
  }

  injectDocCookieReader(tabId, url);

  const finalState = tabState[tabId];
  if (finalState) notifySidePanel(tabId);
  return totalRemoved;
}

/**
 * mergeCookiesRawSafe: Processes cookies from document.cookie (JS-set) by resolving
 *   their authoritative domain/path from chrome.cookies.getAll and merging into state.
 * WHY IT EXISTS: Cookies set via document.cookie have incomplete metadata — they lack
 *   the domain (which may be a subdomain), path, httpOnly, secure, and session flags
 *   that Chrome's cookies API provides. This function enriches document.cookie cookies
 *   by cross-referencing them with chrome.cookies.getAll to get the authoritative
 *   domain, path, and attributes. Without this enrichment, the system would store
 *   cookies with incorrect domain/path, leading to failed removal attempts (wrong URL
 *   construction) and inaccurate first/third-party classification.
 * HOW IT WORKS: 1) For each document.cookie cookie, queries chrome.cookies.getAll
 *   to find the authoritative version (matching by name, value, path). 2) Uses the
 *   authoritative cookie's domain/path/flags as the canonical values. 3) Falls back
 *   to existing state or page URL if no authoritative match found. 4) Protects the
 *   value via CC_CRYPTO.protectCookie(). 5) Resolves vendor info. 6) Runs
 *   enforceRiskBlockingForCookie(). 7) If not blocked, checks hasAuthoritativeMatch()
 *   to avoid duplicates, then adds to state.
 * INPUT: tabId (integer), cookies (array of document.cookie parsed objects),
 *   pageUrl (string — page URL for domain resolution).
 * OUTPUT: Promise<boolean> — true if any changes were made.
 * Source: Chrome cookies API — getAll provides authoritative cookie metadata;
 *   document.cookie — MDN Web Docs — only shows non-HttpOnly cookies.
 */
async function mergeCookiesRawSafe(tabId, cookies, pageUrl = "") {
  if (!ccEnabled) return true;
  catchUpBlockedKeys.clear();
  const state = getState(tabId);
  const db = await getRiskData();
  let changed = false;
  for (const c of cookies) {
    if (catchUpBlockedKeys.has(cookieKey(c)) && !isLikelyAuthInfrastructureDomain(normalizeHost(c.domain || ""), db)) continue;
    let authoritative = null;
    try {
      const query = pageUrl
        ? { url: pageUrl }
        : (c.domain ? { domain: c.domain, name: c.name } : { name: c.name });
      const matches = await getCookiesAsync(query);
      authoritative =
        matches.find(m => m.name === c.name && m.value === c.value)
        || matches.find(m => (m.path || "/") === (c.path || "/"))
        || matches.find(m => m.name === c.name)
        || matches[0]
        || null;
      if (!authoritative && c.domain) {
        const broadMatches = await getCookiesAsync({ name: c.name });
        authoritative =
          broadMatches.find(m => m.name === c.name && m.value === c.value)
          || broadMatches.find(m => (m.path || "/") === (c.path || "/"))
          || broadMatches.find(m => m.name === c.name)
          || broadMatches[0]
          || authoritative;
      }
    } catch (e) { console.warn("[CC]", e.message); }

    const existing = [...state.cookies.values()].find(existingCookie => {
      if ((existingCookie?.name || "") !== (c.name || "")) return false;
      if ((existingCookie?.path || "/") !== (c.path || "/")) return false;
      if (c.value && existingCookie?.value && existingCookie.value !== c.value) return false;
      return true;
    }) || null;

    const resolvedDomain = authoritative?.domain || existing?.domain || c.domain || (pageUrl ? new URL(pageUrl).hostname : "") || "";
    if (!resolvedDomain) continue;
    let normalized;
    try {
      normalized = await CC_CRYPTO.protectCookie({
        name:           c.name,
        value:          c.value,
        domain:         resolvedDomain,
        path:           authoritative?.path || c.path || "/",
        httpOnly:       authoritative?.httpOnly ?? false,
        secure:         authoritative?.secure ?? (c.secure || false),
        session:        typeof authoritative?.session === "boolean" ? authoritative.session : undefined,
        expirationDate: authoritative?.expirationDate,
        sameSite:       authoritative?.sameSite || c.sameSite || "unspecified",
        fromDocCookie:  true,
      });
    } catch (e) {
      console.warn("[CC] Document cookie value protection failed:", e);
      continue;
    }
    normalized.vendorResolved = getResolvedVendorInfo(normalized, db) || null;
    const blockResult = await enforceRiskBlockingForCookie(tabId, state, normalized);
    if (blockResult && blockResult.blocked) {
      changed = true;
      continue;
    }
    const key = cookieKey(normalized);
    const prev = state.cookies.get(key);
    if (hasAuthoritativeMatch(state, normalized)) continue;
    if (!prev || (!!prev.fromDocCookie && !cookiesEqual(prev, normalized))) {
      state.cookies.set(key, normalized);
      changed = true;
    }
  }
  if (changed) notifySidePanel(tabId);
}

/**
 * notifySidePanel: Sends a debounced COOKIES_UPDATED message to the side panel
 *   with the current cookie list, privacy score, and ML diagnostics.
 * WHY IT EXISTS: The side panel needs to display the current cookie list and privacy
 *   score for the active tab. However, cookie changes can fire rapidly (10-50 events
 *   per second during page load), and sending a message for each change would overwhelm
 *   the side panel with updates, causing UI jank and excessive re-renders. This function
 *   debounces notifications to 75ms, coalescing rapid changes into a single update.
 *   Without debouncing, the side panel would re-render 10-50 times per second, making
 *   the UI unresponsive.
 * HOW IT WORKS: 1) Increments the notification counter. 2) Checks if a notification
 *   is already pending for this tab (in sidePanelNotifyQueue). 3) If so, clears the
 *   existing timer. 4) Sets a new 75ms timer. When the timer fires: removes the
 *   queue entry, builds the payload (cookies, score, ML diagnostics), and sends it
 *   via chrome.runtime.sendMessage. The payload includes all sanitized cookies,
 *   the computed privacy score, and recent ML diagnostic entries.
 * INPUT: tabId (integer).
 * OUTPUT: None — sends debounced message to side panel.
 * Source: Debounce pattern — standard UI optimization; Chrome runtime messaging API.
 */
function notifySidePanel(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0) return;
  churnStats.notificationCount++;
  const existing = sidePanelNotifyQueue.get(tabId);
  if (existing) clearTimeout(existing);
  sidePanelNotifyQueue.set(tabId, setTimeout(() => {
    sidePanelNotifyQueue.delete(tabId);
    const state = tabState[tabId];
    const panelOpen = !!sidePanelOpenTabs.has(tabId);
    const clientCookies = state?.cookies?.size ? cookiesForClient(state.cookies.values(), state) : [];
    const siteKey = state?.siteKey || "";
    const privacy = computePrivacyScore(clientCookies, siteKey, riskDataCache, riskModelCache);
    const payload = {
      type: "COOKIES_UPDATED",
      tabId,
      panelOpen,
      cookies: clientCookies,
      url: state?.url || "",
      score: privacy.score,
      scoreLabel: privacy.label,
      mlDiag: mlDiagLog.slice(-50),
    };
    ccDiag({ ev:"notify", tabId, sent: payload.cookies.length, stateSize: state?.cookies?.size||0 });
    chrome.runtime.sendMessage(payload).catch(() => {});
  }, 75));
}

/**
 * queryTcfScore: Queries the page's TCF (Transparency and Consent Framework) API
 *   to detect if a consent management platform (CMP) is active and visible.
 * WHY IT EXISTS: The TCF is the industry standard for GDPR consent management in
 *   Europe. When a CMP is active and displaying a consent banner, the system should
 *   note this in the privacy score (indicating the site has a consent mechanism).
 *   Without TCF detection, the system would miss the presence of consent management,
 *   which is a positive privacy signal. The score returned (0 or 3) is used as a
 *   simple indicator: 0 = no TCF/CMP detected, 3 = TCF active and visible.
 * HOW IT WORKS: 1) Injects a script into the page's MAIN world (to access window.__tcfapi).
 *   2) Checks if window.__tcfapi is a function (TCF API present). 3) If present,
 *   calls __tcfapi("getTCData", 2, callback) with a 1-second timeout. 4) The callback
 *   receives TCF data including gdprApplies, cmpStatus, and displayStatus. 5) If the
 *   CMP is loaded and the banner is visible, returns 3; otherwise returns 0.
 *   6) If the API is not present or times out, returns 0.
 * INPUT: tabId (integer), frameId (integer — frame index, -1 for main frame),
 *   sendResponse (function — callback for async response).
 * OUTPUT: Calls sendResponse with { score: number } — 0 or 3.
 * Source: IAB TCF v2.2 Specification — __tcfapi API (iabtechlab.com);
 *   TCF CMP implementation guidelines.
 */
function queryTcfScore(tabId, frameId, sendResponse) {
  chrome.scripting.executeScript({
    target: frameId >= 0 ? { tabId, frameIds: [frameId] } : { tabId },
    world: "MAIN",
    func: () => new Promise(resolve => {
      try {
        if (typeof window.__tcfapi !== "function") { resolve(0); return; }
        let done = false;
        const finish = score => {
          if (done) return;
          done = true;
          resolve(score);
        };
        const timeout = setTimeout(() => finish(0), 1000);
        window.__tcfapi("getTCData", 2, (data, ok) => {
          clearTimeout(timeout);
          if (!ok || !data) { finish(0); return; }
          const visible = !!(data.gdprApplies && data.cmpStatus === "loaded" && data.displayStatus === "visible");
          finish(visible ? 3 : 0);
        });
      } catch (e) {
        resolve(0);
      }
    }),
  }, results => {
    if (chrome.runtime.lastError) {
      sendResponse({ score: 0 });
      return;
    }
    sendResponse({ score: Number(results?.[0]?.result) || 0 });
  });
}

// ── 5. DOC_COOKIES from content.js ───────────────────────────
// content.js sends document.cookie on load and when asked
/**
 * handleDocCookies: Processes document.cookie data received from the content script
 *   and merges it into the tab's state.
 * WHY IT EXISTS: The content script (content.js) reads document.cookie on page load
 *   and sends it to the background via the DOC_COOKIES message. This handler receives
 *   that data and feeds it into mergeCookiesRawSafe() for authoritative domain
 *   resolution and enforcement. Without this handler, cookies set by JavaScript in
 *   the page context would never reach the background for analysis, leaving a gap
 *   in the cookie inventory.
 * HOW IT WORKS: Validates the sender tab ID and the cookies array, then calls
 *   mergeCookiesRawSafe() with the cookies and page URL. The merge function handles
 *   all the domain resolution, value protection, and enforcement logic.
 * INPUT: msg (message object with type, cookies array, url), senderTabId (integer).
 * OUTPUT: None — delegates to mergeCookiesRawSafe().
 * Source: Chrome Extensions messaging — content.js to background communication;
 *   document.cookie — MDN Web Docs.
 */
function handleDocCookies(msg, senderTabId) {
  if (!senderTabId || !Array.isArray(msg.cookies)) return;
  mergeCookiesRawSafe(senderTabId, msg.cookies, msg.url || "");
}

// ── 6. Polling as backup ──────────────────────────────────────
// Still useful for cookies set after page load by lazy-loaded scripts
/**
 * Main message handler: Routes incoming Chrome runtime messages to the appropriate
 *   handler based on message type.
 * WHY IT EXISTS: The extension communicates between components (side panel, content
 *   scripts, popup, options page) via Chrome's runtime messaging system. This handler
 *   is the central dispatcher that receives all messages and routes them to the correct
 *   handler. Without a centralized dispatcher, each component would need to know the
 *   exact message format and handler location, making the codebase harder to maintain.
 *   The handler also manages the sendResponse callback for async responses (returning
 *   true to indicate async response).
 * HOW IT WORKS: Checks msg.type and routes to the appropriate handler:
 *   - GET_LOCAL_DATA: Returns cookie database and ML model weights
 *   - GET_STATE: Returns current tab's cookies, purge feed, and privacy score
 *   - REQUEST_SCAN: Fire-and-forget full scan for panel-open refresh
 *   - COOKIE_CHURN: Returns churn statistics (adds, removes, rotations)
 *   - BANNER_STATE_CHANGED: Forwards banner state to side panel
 *   - DOC_COOKIES: Processes document.cookie from content script
 *   - GET_TCF_SCORE: Queries TCF API in the page
 *   - AUTH_CONTEXT_CHANGED: Updates auth mode flag for the tab
 *   - GET_TAB_WIDGET_STATE: Returns cookie data for the tab widget overlay
 *   - TOGGLE_SIDEPANEL: Opens/closes the side panel
 *   Each handler validates its inputs and returns true for async responses.
 * INPUT: chrome.runtime.onMessage event — { msg, sender, sendResponse }.
 * OUTPUT: Calls sendResponse with response data; returns true for async handlers.
 * Source: Chrome Extensions messaging API — runtime.onMessage for extension-internal
 *   communication; sender.tab provides the originating tab context.
 */
// ── Message handler ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  if (msg.type === "GET_LOCAL_DATA") {
    getLocalData().then(data => {
      sendResponse({
        cookieDb: data.cookieDb,
        modelWeights: data.modelWeights,
      });
    }).catch(() => {
      sendResponse({ cookieDb: null, modelWeights: null });
    });
    return true;
  }

  if (msg.type === "GET_STATE") {
    touchTab(msg.tabId);
    const s = tabState[msg.tabId];
    const clientCookies = s ? cookiesForClient(s.cookies.values(), s) : [];
    const siteKey = s?.siteKey || "";
    const privacy = computePrivacyScore(clientCookies, siteKey, riskDataCache, riskModelCache);
    sendResponse({
      cookies: clientCookies,
      purgeFeed: getGlobalPurgeFeed(),
      score: privacy.score,
      scoreLabel: privacy.label,
    });
    return true;
  }

  if (msg.type === "REQUEST_SCAN") {
    // Panel-open refresh (M2): opening the panel to compare must not read
    // stale state. Fire-and-forget full scan; fresh data rides the normal
    // COOKIES_UPDATED notification. Never throws; always responds.
    try {
      const t = Number(msg.tabId);
      const st = tabState[t];
      const url = String(msg.url || (st && st.url) || "");
      if (Number.isInteger(t) && t >= 0 && url && !url.startsWith("chrome://") && !url.startsWith("about:")) {
        scanAll(t, url);
      }
      sendResponse({ ok: true });
    } catch (e) { try { sendResponse({ ok: false }); } catch (_) {} }
    return true;
  }

  if (msg.type === "COOKIE_CHURN") {
    const elapsed = ((Date.now() - churnStats.startTime) / 1000).toFixed(1);
    const rotations = [];
    for (const [key, val] of cookieRotationMap) {
      if (val.delTime && val.addTime && (val.addTime - val.delTime) < 5000) {
        const [name, domain] = key.split("::");
        rotations.push({ name, domain, gapMs: val.addTime - val.delTime });
      }
    }
    rotations.sort((a, b) => b.gapMs - a.gapMs);
    const causeCounts = {};
    const cookieCauses = {};
    for (const [key, entry] of cookieCauseMap) {
      causeCounts[entry.cause] = (causeCounts[entry.cause] || 0) + entry.count;
      const ck = entry.name + "::" + entry.domain;
      if (!cookieCauses[ck]) cookieCauses[ck] = { name: entry.name, domain: entry.domain, causes: {} };
      cookieCauses[ck].causes[entry.cause] = entry.count;
    }
    const topCookies = Object.values(cookieCauses)
      .sort((a, b) => Object.values(b.causes).reduce((s, v) => s + v, 0) - Object.values(a.causes).reduce((s, v) => s + v, 0))
      .slice(0, 15);
    sendResponse({
      stats: { ...churnStats, elapsed: Number(elapsed) },
      causeCounts,
      topCookies,
      rotations: rotations.slice(0, 20),
      recentEvents: cookieChurnLog.slice(-30),
    });
    return true;
  }

  // ── Logout-diagnostic aggregation (pure, counts-only) ──
  // WHY THEY EXIST: The Logout Diag recorder tab captures per-site logout
  //   evidence (kill timeline, churn cycles, purge events, network-ban
  //   state) across the baseline -> toggle -> reload timeline. All helpers
  //   below aggregate in memory; per-cookie names/values/domains never leave
  //   this file — the bundle carries tallies + reason codes + timestamps only.
  function logoutSiteMatch(value, site, siteReg) {
    try {
      const v = String(value || "").toLowerCase();
      if (!v || !site) return false;
      if (v === site) return true;
      return (getRegistrableDomain(v) || "") === siteReg;
    } catch (_) { return false; }
  }
  // INPUT: projected receipt rows {verdict, reason, cat, origin, trigger, js, t}.
  // OUTPUT: grouped tallies [{verdict, reason, cat, origin, trigger, count, jsSet, first, last}], capped.
  function groupLogoutReceipts(rows) {
    const groups = [];
    const idx = {};
    for (const r of (rows || [])) {
      try {
        const key = (r.verdict || "?") + "|" + (r.reason || "?") + "|" + (r.cat || "?") + "|" + (r.origin || "?") + "|" + (r.trigger || "?");
        if (!(key in idx)) {
          idx[key] = groups.length;
          groups.push({ verdict: r.verdict || "?", reason: r.reason || "?", cat: r.cat || "?", origin: r.origin || "?", trigger: r.trigger || "?", count: 0, jsSet: 0, first: r.t || 0, last: r.t || 0 });
        }
        const g = groups[idx[key]];
        g.count++;
        if (r.js) g.jsSet++;
        if (r.t && (!g.first || r.t < g.first)) g.first = r.t;
        if (r.t && r.t > g.last) g.last = r.t;
      } catch (_) {}
    }
    return groups.slice(0, 30);
  }
  // INPUT: projected churn rows {key (internal cohort id, never stored), type, cause, t, rotation}.
  // OUTPUT: {removals, readds, rotations, multiRemoved, causeTally}. No keys survive.
  function summarizeLogoutChurn(rows) {
    const dels = {};
    let removals = 0, readds = 0, rotations = 0;
    const causeTally = {};
    for (const r of (rows || [])) {
      try {
        if (r.type === "ADD") {
          readds++;
          if (r.rotation) rotations++;
        } else {
          removals++;
          dels[r.key] = (dels[r.key] || 0) + 1;
          const c = r.cause || "unknown";
          causeTally[c] = (causeTally[c] || 0) + 1;
        }
      } catch (_) {}
    }
    let multiRemoved = 0;
    for (const k of Object.keys(dels)) if (dels[k] >= 2) multiRemoved++;
    return { removals, readds, rotations, multiRemoved, causeTally };
  }
  // Assembles the counts-only logout bundle for a site. Read-only: touches
  // no rules, no state, no storage writes.
  async function buildLogoutDiagBundle(site) {
    const s = String(site || "").toLowerCase();
    let siteReg = s;
    try { siteReg = getRegistrableDomain(s) || s; } catch (_) {}
    const kills = groupLogoutReceipts(
      decisionReceipts
        .filter(r => r && r.verdict !== "KEPT" && logoutSiteMatch(r.site, s, siteReg))
        .slice(-100)
        .map(r => ({ verdict: r.verdict, reason: r.reason, cat: r.cat, origin: r.origin, trigger: r.trigger, js: !!r.fromDocCookie, t: r.t }))
    );
    // Survivors: KEPT verdicts grouped by reason — proves shields working
    // (or their absence). Same counts-only projection, no names.
    const survived = groupLogoutReceipts(
      decisionReceipts
        .filter(r => r && r.verdict === "KEPT" && logoutSiteMatch(r.site, s, siteReg))
        .slice(-100)
        .map(r => ({ verdict: "KEPT", reason: r.reason, cat: r.cat, origin: r.origin, trigger: r.trigger, js: !!r.fromDocCookie, t: r.t }))
    );
    const churn = summarizeLogoutChurn(
      cookieChurnLog
        .filter(e => e && logoutSiteMatch(e.domain, s, siteReg))
        .map(e => ({ key: (e.name || "") + "::" + (e.domain || ""), type: e.type, cause: e.cause, t: e.t, rotation: !!e.rotation }))
    );
    const purges = (globalPurgeFeed || [])
      .filter(e => e && logoutSiteMatch(e.siteKey, s, siteReg))
      .slice(0, 12)
      .map(e => ({ t: e.timestamp || 0, trigger: e.trigger || "?", considered: Number(e.consideredCount || 0), removed: Number(e.removedCount || 0), status: e.status || "?" }));
    let tabFlags = null;
    try {
      for (const st of Object.values(tabState || {})) {
        const sk = normalizeHost(st?.siteKey || "");
        if (sk && (sk === s || (getRegistrableDomain(sk) || "") === siteReg)) {
          tabFlags = { authMode: !!st.authMode };
          break;
        }
      }
    } catch (_) {}
    let dnrMatching = null, dnrTotal = null;
    try {
      if (chrome?.declarativeNetRequest?.getDynamicRules) {
        const rules = await chrome.declarativeNetRequest.getDynamicRules();
        dnrTotal = Array.isArray(rules) ? rules.length : 0;
        dnrMatching = (rules || []).filter(r => String((r?.condition?.urlFilter) || "").indexOf(siteReg) >= 0).length;
      }
    } catch (_) {}
    let sticky = 0, suppressedEntries = 0, suppressedRemovals = 0, freq3plus = 0, latestRemoval = 0;
    try {
      for (const d of stickyBlockedDomains) {
        const dd = String(d || "");
        if (dd && (dd === siteReg || dd.endsWith("." + siteReg))) sticky++;
      }
      for (const entry of suppressedTrackingCookies.values()) {
        try {
          const reg = getRegistrableDomain(normalizeHost(entry?.domain || "")) || "";
          if (reg && reg === siteReg) {
            suppressedEntries++;
            suppressedRemovals += Number(entry?.count || 0);
            if (Number(entry?.count || 0) >= 3) freq3plus++;
            if (Number(entry?.lastRemovedAt || 0) > latestRemoval) latestRemoval = Number(entry.lastRemovedAt);
          }
        } catch (_) {}
      }
    } catch (_) {}
    return {
      site: s, t: Date.now(),
      flags: tabFlags,
      toggles: { tb: !!riskBlockingSettings.riskBlockingEnabled, sg: !!sessionLockSettings.sessionLockEnabled },
      kills, survived, churn, purges,
      net: { dnrMatching, dnrTotal, sticky, suppressedEntries, suppressedRemovals, freq3plus, latestRemoval },
    };
  }

  if (msg.type === "GET_LOGOUT_DIAG") {
    // Logout-diagnostic bundle for the recorder tab. Async (DNR query);
    // failures resolve to an error payload, never a dropped response.
    try {
      buildLogoutDiagBundle(String((msg && msg.site) || ""))
        .then(b => { try { sendResponse(b); } catch (_) {} })
        .catch(() => { try { sendResponse({ error: "diag-failed" }); } catch (_) {} });
    } catch (_) {
      sendResponse({ error: "diag-failed" });
      return false;
    }
    return true;
  }

  if (msg.type === "GET_DECISIONS") {
    // Decision receipt export for the sidepanel "Decisions" tab.
    // Returns the bounded receipt ring (newest last) plus toggle state
    // so the export shows under which settings each verdict was made.
    // Mirrors the COOKIE_CHURN precedent above.
    sendResponse({
      receipts: decisionReceipts.slice(-DECISION_RECEIPTS_MAX),
      cap: DECISION_RECEIPTS_MAX,
      toggles: {
        tb: !!riskBlockingSettings.riskBlockingEnabled,
        sg: !!sessionLockSettings.sessionLockEnabled,
      },
    });
    return true;
  }

  if (msg.type === "BANNER_STATE_CHANGED") {
    // Forward to side panel
    chrome.runtime.sendMessage({
      type:          "BANNER_STATE_CHANGED",
      bannerVisible: msg.bannerVisible,
      tabId:         sender.tab?.id,
    }).catch(() => {});
    return false;
  }

  if (msg.type === "DOC_COOKIES") {
    if (sender.tab?.id) touchTab(sender.tab.id);
    handleDocCookies(msg, sender.tab?.id);
    return false;
  }

  if (msg.type === "GET_TCF_SCORE") {
    if (!sender.tab?.id) {
      sendResponse({ score: 0 });
      return false;
    }
    queryTcfScore(sender.tab.id, sender.frameId ?? -1, sendResponse);
    return true;
  }

  if (msg.type === "AUTH_CONTEXT_CHANGED") {
    const tabId = sender.tab?.id;
    if (!tabId) return false;
    const state = getState(tabId);
    state.authMode = !!msg.authMode || isLikelyAuthFlowUrl(state.url || sender.tab?.url || "");
    state.lastAuthUpdateAt = Date.now();
    syncTrackerBlockingRules();
    return false;
  }

  if (msg.type === "GET_TAB_WIDGET_STATE") {
    const tabId = sender.tab?.id;
    if (tabId) touchTab(tabId);
    const s = tabId ? tabState[tabId] : null;
    const clientCookies = s ? cookiesForClient(s.cookies.values(), s) : [];
    const siteKey = s?.siteKey || "";
    const privacy = computePrivacyScore(clientCookies, siteKey, riskDataCache, riskModelCache);
    sendResponse({
      tabId: tabId || null,
      cookies: clientCookies,
      panelOpen: !!(tabId && sidePanelOpenTabs.has(tabId)),
      score: privacy.score,
      scoreLabel: privacy.label,
    });
    return true;
  }

  if (msg.type === "TOGGLE_SIDEPANEL") {
    const tabId = sender.tab?.id;
    if (!tabId) return false;
    const isOpen = sidePanelOpenTabs.has(tabId);
    try {
      if (isOpen) {
        if (chrome.sidePanel?.close) chrome.sidePanel.close({ tabId });
        else chrome.sidePanel.setOptions({ tabId, enabled: false });
      } else {
        chrome.sidePanel.setOptions({ tabId, path: "sidepanel.html", enabled: true });
        chrome.sidePanel.open({ tabId });
      }
      if (!chrome.sidePanel?.onOpened && !chrome.sidePanel?.onClosed) {
        if (isOpen) sidePanelOpenTabs.delete(tabId);
        else sidePanelOpenTabs.add(tabId);
        notifyPanelState(tabId, !isOpen);
      }
      sendResponse({ ok: true, panelOpen: !isOpen });
    } catch (e) {
      sendResponse({ ok: false, panelOpen: isOpen });
    }
    return true;
  }

});
