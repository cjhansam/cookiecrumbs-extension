// ============================================================
// Cookie Crumbs v5.3 - sidepanel.js
// Datasets loaded from cookie_db.json (built from real sources)
// ============================================================

// â”€â”€ Globals populated after DB + model load â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let DB    = null;   // from cookie_db.json
let ML    = null;   // CookieMLClassifier instance
let MODEL_META = null;
let widgetEnabled = true;
let ccEnabled = true;
let consentAnalysisEnabled = true;
let settingsViewOpen = false;
let debugOpen = false;

const SESSION_LOCK_DEFAULTS = {
  sessionLockEnabled: false,
};
const RISK_BLOCKING_DEFAULTS = {
  riskBlockingEnabled: true,
};
// Independent per-engine site exemption lists (registrable domains, eTLD+1):
// tbSiteWhitelist = exempt from Tracker Blocking; sgSiteWhitelist = exempt from
// Session Guard. Same keys/defaults as background.js WHITELIST_DEFAULTS.
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
  widgetEnabled: true,
};
let protectionSettings = { ...PROTECTION_DEFAULTS };

/**
 * requestLocalData: Promise wrapper around chrome.runtime.sendMessage for fetching DB + ML model weights.
 * WHY IT EXISTS: chrome.runtime.sendMessage is callback-based; this converts it into an awaitable
 *   Promise so the rest of the init pipeline can use async/await cleanly.
 * HOW IT WORKS: Sends a "GET_LOCAL_DATA" message to the background script, wraps the callback in a
 *   Promise, and resolves with the response (or safe defaults on error).
 * INPUT: None (reads from background via message).
 * OUTPUT: Promise<{ cookieDb: Object|null, modelWeights: Object|null }>
 */
function requestLocalData() {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type: "GET_LOCAL_DATA" }, resp => {
      if (chrome.runtime.lastError) {
        resolve({ cookieDb: null, modelWeights: null });
        return;
      }
      resolve(resp || { cookieDb: null, modelWeights: null });
    });
  });
}

// â”€â”€ Load cookie_db.json (OCD + Disconnect + CMP selectors) â”€â”€â”€
/**
 * loadData: Loads the cookie classification database and ML model weights into global variables.
 * WHY IT EXISTS: The side panel needs access to the cookie DB (blocklists, vendor data, etc.) and
 *   the ML classifier model to classify and score cookies. Without this, every classification would
 *   fail and the panel would show empty data.
 * HOW IT WORKS: Calls requestLocalData() to fetch data from the background script, then assigns
 *   the cookie DB to the global `DB` variable and initializes a new CookieMLClassifier instance
 *   with the model weights. If no weights are available, ML remains null.
 * INPUT: None (reads from background via requestLocalData).
 * OUTPUT: Populates globals DB, ML, and MODEL_META. Returns nothing.
 */
async function loadData() {
  const data = await requestLocalData();
  DB = data.cookieDb || null;
  const w = data.modelWeights || null;
  if (!w) return;
  ML        = new CookieMLClassifier(w);
  MODEL_META= w.meta;
}

/**
 * loadProtectionSettings: Loads user protection toggle states from chrome.storage.local.
 * WHY IT EXISTS: The extension has multiple protection features (CC master toggle, consent analysis,
 *   widget, session lock, tracker blocking) whose on/off states persist across sessions. This function
 *   reads those states on startup so the UI and runtime logic reflect the user's saved preferences.
 * HOW IT WORKS: Reads from chrome.storage.local using PROTECTION_DEFAULTS as the key set, merges
 *   with defaults to handle first-run, then updates the global booleans (ccEnabled, consentAnalysisEnabled,
 *   widgetEnabled) to match the stored values. Tracker Blocking is always on: riskBlockingEnabled is
 *   forced true regardless of stored value (pre-change profiles migrate silently).
 * INPUT: None (reads from chrome.storage.local).
 * OUTPUT: Populates globals protectionSettings, ccEnabled, consentAnalysisEnabled, widgetEnabled.
 */
async function loadProtectionSettings() {
  const res = await chrome.storage.local.get(PROTECTION_DEFAULTS);
  protectionSettings = { ...PROTECTION_DEFAULTS, ...res };
  protectionSettings.riskBlockingEnabled = true;
  ccEnabled = protectionSettings.ccEnabled !== false;
  consentAnalysisEnabled = protectionSettings.consentAnalysisEnabled !== false;
  widgetEnabled = protectionSettings.widgetEnabled !== false;
}

/**
 * updateSettingsPanel: Syncs the DOM toggle buttons in the settings panel to match the current protectionSettings state.
 * WHY IT EXISTS: When settings change (on load or when toggled), the ON/OFF buttons in the UI must
 *   visually reflect the actual state. This function ensures the DOM and the internal state stay in sync.
 *   It also enforces the dependency rule: consent and widget toggles are disabled when CC master is OFF.
 * HOW IT WORKS: Queries all elements with [data-setting] attribute, reads the matching key from
 *   protectionSettings, sets the button text to ON/OFF, updates aria-pressed for accessibility,
 *   toggles the "on" CSS class, and disables consent/widget buttons when ccEnabled is false.
 * INPUT: None (reads from globals protectionSettings).
 * OUTPUT: Modifies DOM elements (button text, class, disabled state).
 */
function updateSettingsPanel() {
  const ccOn = protectionSettings.ccEnabled !== false;
  document.querySelectorAll("[data-setting]").forEach(btn => {
    const key = btn.getAttribute("data-setting");
    const enabled = protectionSettings[key] !== false;
    btn.textContent = enabled ? "ON" : "OFF";
    btn.setAttribute("aria-pressed", enabled ? "true" : "false");
    btn.classList.toggle("on", enabled);
    // The toggle's card follows it: green whole card while ON (e.g. Session
    // Guard), plain card while OFF. Cards without a toggle (Tracker Blocking
    // is always on) are unaffected.
    const card = btn.closest(".protection-card");
    if (card) card.classList.toggle("card-on", enabled);
    if (key === "consentAnalysisEnabled" || key === "widgetEnabled") {
      btn.disabled = !ccOn;
    }
  });
}

/**
 * setProtectionSetting: Updates a single protection toggle with cascade logic and persistence.
 * WHY IT EXISTS: Toggling a setting must update the in-memory state, persist to storage, re-sync the
 *   UI, and trigger a re-render. The CC master toggle has special cascade behavior: turning it OFF
 *   forces consent analysis and widget OFF; turning it ON re-enables them. Without this cascade,
 *   sub-features could remain active when the master switch is off.
 * HOW IT WORKS: Handles three cases — (1) ccEnabled turning OFF: disables all sub-features and re-renders,
 *   (2) ccEnabled turning ON: re-enables sub-features and triggers a fresh scan, (3) individual toggle:
 *   updates the specific key if ccEnabled is active. Persists each change to chrome.storage.local.
 * INPUT: key (string) — the setting name; value (boolean) — new state.
 * OUTPUT: Updates globals, storage, DOM, and triggers re-render/scan.
 */
async function setProtectionSetting(key, value) {
  if (key === "riskBlockingEnabled") {
    // Tracker Blocking is always on and has no toggle: force any write back
    // to true (in memory and storage) and ignore the requested value.
    protectionSettings.riskBlockingEnabled = true;
    await chrome.storage.local.set({ riskBlockingEnabled: true });
    return;
  }
  if (key === "ccEnabled" && !value) {
    protectionSettings.ccEnabled = false;
    protectionSettings.consentAnalysisEnabled = false;
    protectionSettings.widgetEnabled = false;
    ccEnabled = false;
    consentAnalysisEnabled = false;
    widgetEnabled = false;
    await chrome.storage.local.set({
      ccEnabled: false,
      consentAnalysisEnabled: false,
      widgetEnabled: false,
    });
    updateSettingsPanel();
    render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
    return;
  }
  if (key === "ccEnabled" && value) {
    protectionSettings.ccEnabled = true;
    protectionSettings.consentAnalysisEnabled = true;
    protectionSettings.widgetEnabled = true;
    ccEnabled = true;
    consentAnalysisEnabled = true;
    widgetEnabled = true;
    await chrome.storage.local.set({
      ccEnabled: true,
      consentAnalysisEnabled: true,
      widgetEnabled: true,
    });
    updateSettingsPanel();
    render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
    chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
      if (tabs[0]) doScan(tabs[0].id, tabs[0].url);
    });
    return;
  }
  if ((key === "consentAnalysisEnabled" || key === "widgetEnabled") && !ccEnabled) {
    return;
  }
  protectionSettings[key] = value;
  if (key === "widgetEnabled") widgetEnabled = !!value;
  if (key === "consentAnalysisEnabled") consentAnalysisEnabled = !!value;
  if (key === "ccEnabled") ccEnabled = !!value;
  await chrome.storage.local.set({ [key]: value });
  updateSettingsPanel();
}

/**
 * toggleSiteWhitelist / addWhitelistEntry / removeWhitelistEntry: Writers for the
 *   two independent site whitelists (tbSiteWhitelist = Tracker Blocking exempt,
 *   sgSiteWhitelist = Session Guard exempt).
 * WHY IT EXISTS: Exemption must be a first-class user action with three entry
 *   points — chip on the main panel (current site), Settings text input
 *   (any domain, e.g. "google.com"), and per-entry removal — and both engines
 *   must stay independent: touching one list never affects the other.
 * HOW IT WORKS: Normalizes the entry to its registrable domain (eTLD+1) via
 *   normalizeSiteWhitelistEntry(), so a single "google.com" entry covers every
 *   subdomain. Each function updates protectionSettings optimistically, persists
 *   the whole array to chrome.storage.local, and lets the existing storage
 *   listener re-render the UI. Background mirrors the arrays via its own
 *   storage.onChanged listener (and re-syncs DNR rules for TB changes).
 * INPUT: engine ("tb" | "sg"); raw user text (add only); stored entry (remove only).
 * OUTPUT: Promise — side effects on protectionSettings, storage, toast.
 * Source: Site identity via registrable domain (eTLD+1) — same normalization as
 *   tab siteKey; whitelist matching per RFC 6265 Section 5.1.3 (label-boundary).
 */
function whitelistKeyFor(engine) {
  return engine === "tb" ? "tbSiteWhitelist" : "sgSiteWhitelist";
}
function whitelistLabelFor(engine) {
  return engine === "tb" ? "Tracking Protection" : "Session Guard";
}
async function toggleSiteWhitelist(engine) {
  const key = whitelistKeyFor(engine);
  const site = normalizeSiteWhitelistEntry(currentDomain || "");
  if (!site) { showToast("No site to exempt"); return; }
  const list = Array.isArray(protectionSettings[key]) ? [...protectionSettings[key]] : [];
  const idx = list.indexOf(site);
  const added = idx < 0;
  if (added) list.push(site); else list.splice(idx, 1);
  protectionSettings[key] = list;
  await chrome.storage.local.set({ [key]: list });
  showToast(added ? `${site} exempt from ${whitelistLabelFor(engine)}` : `${site} removed from ${whitelistLabelFor(engine)} whitelist`);
}
async function addWhitelistEntry(engine, raw) {
  const key = whitelistKeyFor(engine);
  const site = normalizeSiteWhitelistEntry(raw);
  if (!site) { showToast("Enter a valid domain (e.g. google.com)"); return; }
  const list = Array.isArray(protectionSettings[key]) ? [...protectionSettings[key]] : [];
  if (list.includes(site)) { showToast(`${site} already listed`); return; }
  list.push(site);
  protectionSettings[key] = list;
  await chrome.storage.local.set({ [key]: list });
  showToast(`${site} added to ${whitelistLabelFor(engine)} whitelist`);
}
async function removeWhitelistEntry(engine, entry) {
  const key = whitelistKeyFor(engine);
  const list = (Array.isArray(protectionSettings[key]) ? protectionSettings[key] : []).filter(e => e !== entry);
  protectionSettings[key] = list;
  await chrome.storage.local.set({ [key]: list });
  showToast(`${entry} removed from ${whitelistLabelFor(engine)} whitelist`);
}

/**
 * wlChipText / wlChipTitle / updateWhitelistChips: Chip display helpers and the
 *   targeted chip patcher.
 * WHY IT EXISTS: After the first full render, processRawCookies only patches the
 *   score/summary/tabs/table — the protection-card chips are rebuilt exclusively
 *   by render(). Navigation therefore left chips showing the PREVIOUS site's
 *   whitelist state (a falsely-green chip that silently wrote the wrong list
 *   entry when clicked). The chip must track currentDomain exactly like the
 *   domain bar does, and render() must share the patcher's text/title so a full
 *   render and a targeted patch can never disagree.
 * HOW IT WORKS: updateWhitelistChips() recomputes the registrable site from
 *   currentDomain and both engines' membership, then patches every
 *   [data-whitelist] chip in place: .on class, label, title (which names the
 *   site that a click will actually store, e.g. "Exempt google.com from Session
 *   Guard"), and disabled (no site, e.g. chrome:// pages). No-op when the chips
 *   are not in the DOM (Settings view, pre-first-render, invalid page).
 * INPUT: none — reads currentDomain and protectionSettings.
 * OUTPUT: side effects on the chip elements only.
 * Source: whitelist identity identical to the background gates —
 *   normalizeSiteWhitelistEntry + siteMatchesWhitelist (RFC 6265 Section 5.1.3).
 */
function wlChipText(active) {
  return active ? "✓ Site exempt" : "Exempt this site";
}
function wlChipTitle(site, engine) {
  return `Exempt ${site || "this site"} from ${whitelistLabelFor(engine)}`;
}
function updateWhitelistChips() {
  const site = normalizeSiteWhitelistEntry(currentDomain || "");
  const states = {
    sg: !!site && siteMatchesWhitelist(site, protectionSettings.sgSiteWhitelist),
    tb: !!site && siteMatchesWhitelist(site, protectionSettings.tbSiteWhitelist),
  };
  document.querySelectorAll("[data-whitelist]").forEach(chip => {
    const engine = chip.getAttribute("data-whitelist");
    const active = !!states[engine];
    chip.classList.toggle("on", active);
    chip.textContent = wlChipText(active);
    chip.title = wlChipTitle(site, engine);
    chip.disabled = !site;
  });
}

// â”€â”€ HIGH_RISK: Disconnect Advertising domains (from DB) â”€â”€â”€â”€â”€â”€â”€
/**
 * isHighRisk: Checks whether a domain appears in the Disconnect blocklist.
 * WHY IT EXISTS: The scoring formula needs to penalize cookies that come from known tracking/advertising
 *   domains more heavily. This function provides the blocklist lookup used as a multiplier in scoring.
 * HOW IT WORKS: Delegates to isDomainInList() with the DB's blocklist array. Returns false if the DB
 *   hasn't loaded yet.
 * INPUT: domain (string) — the registrable domain to check.
 * OUTPUT: boolean — true if domain is on the blocklist.
 */
function isHighRisk(domain) {
  if (!DB) return false;
  return isDomainInList(domain, DB.blocklist || []);
}

/**
 * formatLifespan: Converts a cookie's expiry data into a short human-readable lifespan string.
 * WHY IT EXISTS: The cookie table UI needs a concise "Life" column that tells the user at a glance
 *   whether a cookie is a session cookie, persistent (with days remaining), or already expired.
 * HOW IT WORKS: Calls getCookiePersistence() to get isSession and daysRemaining, then maps to a
 *   short label: "Session", "Persistent", "Expired", "<1d", or "Nd".
 * INPUT: cookie (Object) — a raw cookie object with expirationDate/session fields.
 * OUTPUT: string — human-readable lifespan label.
 */
function formatLifespan(cookie) {
  const { isSession, daysRemaining } = getCookiePersistence(cookie);
  if (isSession) return "Session";
  if (daysRemaining === null) return "Persistent";
  if (daysRemaining <= 0) return "Expired";
  if (daysRemaining < 1) return "<1d";
  return `${Math.ceil(daysRemaining)}d`;
}

// — Scoring formula ———————————————————————————————————

/**
 * computeScore: Calculates a privacy score (0–100) from the enriched cookie list.
 * WHY IT EXISTS: The privacy score is the primary metric shown to users. It quantifies how much
 *   tracking a site performs, combining category weight, cookie longevity, first/third-party origin,
 *   and blocklist membership. Without this function, there's no way to translate raw cookie data
 *   into an actionable privacy rating.
 * HOW IT WORKS: Iterates over enriched cookies, computing a penalty for each. Penalty = weight × longevity
 *   multiplier × blocklist multiplier. Weight depends on category (Strict=0, Advertising=highest) and
 *   first vs third party. Longevity multiplier scales with days remaining. Blocklist multiplier doubles
 *   the penalty for known trackers. Final score = max(0, 100 - total penalty). Also computes a label
 *   ("Excellent" to "Dangerous") and per-category breakdown.
 * INPUT: enriched (Array) — array of {cookie, cat, origin} objects.
 * OUTPUT: {score, label, breakdown, total, tpPct} object.
 */
function computeScore(enriched) {
  if (!enriched.length) return {score:100,label:"Excellent",breakdown:{},total:0,tpPct:0};
  let penalty=0, tpCount=0;
  const bd={Strict:0,Performance:0,Functionality:0,Advertising:0,Unknown:0};
  for (const item of enriched) {
    const {cookie,cat,origin} = item;
    const fp   = origin==="First-party";
    const persistence = getCookiePersistence(cookie);
    const p    = !persistence.isSession;
    const days = p ? (persistence.daysRemaining ?? 0) : 0;
    const dom  = (cookie.domain||"").toLowerCase().replace(/^\./,"");
    let w=0;
    if      (cat==="Strict")        w=0;
    else if (cat==="Performance")   w=0;
    else if (cat==="Functionality") w=fp?(p?3:1):(p?4:2);
    else if (cat==="Advertising")   w=fp?(p?5:2):(p?6:3);
    else                            w=fp?(p?3:0):(p?4:1);
    let l=1;
    if (p){ if (!fp) l=days<7?1:days<=30?1.5:2; else l=days<=60?1:2; }
    const b = (!fp && isHighRisk(dom)) ? 2 : 1;
    const pen = w*l*b;
    bd[cat]=(bd[cat]||0)+pen;
    penalty+=pen;
    if (!fp) tpCount++;
  }
  const score=Math.max(0,Math.round(100-penalty));
  const label=score===0?"Dangerous":score<25?"Critical":score<50?"Poor":score<70?"Fair":score<90?"Good":"Excellent";
  return {score,label,breakdown:bd,total:enriched.length,tpPct:Math.round(tpCount/enriched.length*100)};
}

/**
 * escapeHtml: Escapes special HTML characters to prevent XSS injection.
 * WHY IT EXISTS: Cookie names, domains, and vendor labels are user/attacker-controlled strings
 *   that get injected into innerHTML. Without escaping, a malicious cookie name like
 *   "<img src=x onerror=alert(1)>" would execute JavaScript.
 * HOW IT WORKS: Replaces the five dangerous characters (&, <, >, ", ') with their HTML entity
 *   equivalents using a chain of .replace() calls.
 * INPUT: text (string|any) — value to escape (coerced to string, null-safe).
 * OUTPUT: string — safe for innerHTML insertion.
 */
function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * CAT_EXPLAIN: Maps cookie categories to plain-English purpose descriptions.
 * WHY IT EXISTS: The summary paragraph generator needs human-readable explanations of what each
 *   category does, so users understand why those cookies exist without needing technical knowledge.
 * HOW IT WORKS: Static lookup object keyed by category name.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → description string.
 */
const CAT_EXPLAIN = {
  Advertising:   "are used for targeting you across other sites",
  Performance:   "measure how you use the site",
  Functionality: "keep you logged in and remember your preferences",
  Strict:        "are essential for the site to work",
  Unknown:       "could not be identified",
};

/**
 * CAT_PLURAL: Maps cookie categories to their user-friendly plural names.
 * WHY IT EXISTS: The summary paragraph uses these labels when referring to groups of cookies
 *   (e.g., "ad trackers" instead of "Advertising cookies") to make the text more natural.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → plural label string.
 */
const CAT_PLURAL = {
  Advertising:   "ad trackers",
  Performance:   "analytics cookies",
  Functionality: "functional cookies",
  Strict:        "essential cookies",
  Unknown:       "unclassified cookies",
};

/**
 * CAT_SENTENCE: Maps cookie categories to full explanatory sentences for the category tab UI.
 * WHY IT EXISTS: When a user clicks on a specific category tab, a contextual sentence explains
 *   the purpose of that category so they understand what those cookies do.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → explanatory sentence string.
 */
const CAT_SENTENCE = {
  Strict:        "Strict cookies are required for the site to function. Disabling them may break login, security, or core features.",
  Performance:   "Performance cookies measure how you use the site, such as which pages you visit and how long you stay.",
  Functionality: "Functional cookies remember your preferences and keep you logged in across sessions.",
  Advertising:   "Advertising cookies track you across other sites to show you targeted ads.",
  Unknown:       "Unclassified cookies could not be categorized. They may be newly set or lack enough data to classify.",
};

/**
 * PROTECTION_HELP: Maps protection feature keys to tooltip/help text shown in the UI.
 * WHY IT EXISTS: Users need to understand what Session Guard and Tracker Blocking do before
 *   enabling them. This provides the popover content for the "?" help buttons.
 * INPUT: None (constant).
 * OUTPUT: Object mapping setting key → help text string.
 */
const PROTECTION_HELP = {
  sessionLock: "Removes insecure session cookies when you leave a site, preventing them from being hijacked for tracking.",
  riskBlocking: "Tracking Protection is always on. It blocks known tracking and unclassified cookies. Login and authentication cookies are always kept.",
  trackingAlwaysOn: "Always on for security. Use Exempt this site to allow a specific site.",
};

/**
 * relQty: Converts a count/total ratio into a relative quantity word for natural language.
 * WHY IT EXISTS: The summary paragraph needs phrases like "Most cookies are ad trackers" rather
 *   than raw percentages. This function maps percentage ranges to natural-language quantifiers.
 * HOW IT WORKS: Computes count/total, then maps to "Most" (>50%), "Many" (>20%), "Some" (>5%), or "A few".
 * INPUT: count (number), total (number).
 * OUTPUT: string — one of "Most", "Many", "Some", "A few", or "" if total is 0.
 */
function relQty(count, total) {
  if (total === 0) return "";
  const pct = count / total;
  if (pct > 0.5) return "Most";
  if (pct > 0.2) return "Many";
  if (pct > 0.05) return "Some";
  return "A few";
}

/**
 * extractParagraphStats: Computes summary statistics from the enriched cookie list for paragraph generation.
 * WHY IT EXISTS: The summary paragraph needs aggregate data (total cookies, third-party count, top
 *   categories, top vendors, max cookie lifetime) to construct a meaningful natural-language overview.
 *   Centralizing this in one function avoids redundant computation across summary components.
 * HOW IT WORKS: Iterates over enriched cookies to compute: total count, third-party count, category
 *   frequency map (sorted descending), top 3 third-party vendor labels, and maximum days remaining
 *   for any third-party persistent cookie.
 * INPUT: enriched (Array) — array of enriched cookie items.
 * OUTPUT: {total, totalThirdParty, topCategories, topVendors, maxDays}
 */
function extractParagraphStats(enriched) {
  const safe = Array.isArray(enriched) ? enriched : [];
  const total = safe.length;
  const totalThirdParty = safe.filter(c => c.origin === "Third-party").length;

  const catCounts = {};
  for (const c of safe) {
    const cat = c.cat || "Unknown";
    catCounts[cat] = (catCounts[cat] || 0) + 1;
  }
  const topCategories = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .filter(([, count]) => count > 0);

  const vendorMap = new Map();
  for (const c of safe) {
    if (c.origin !== "Third-party") continue;
    const raw = (c.domain || "").replace(/^\./, "").toLowerCase();
    if (!raw) continue;
    const reg = getRegistrableDomain(raw);
    const vendorInfo = getResolvedVendorInfo(raw, typeof DB === "object" ? DB : null);
    const label = vendorInfo?.label || reg || raw;
    vendorMap.set(label, (vendorMap.get(label) || 0) + 1);
  }
  const topVendors = [...vendorMap.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 3)
    .map(([label]) => label);

  let maxDays = 0;
  for (const c of safe) {
    if (c.origin !== "Third-party") continue;
    const p = getCookiePersistence(c.cookie);
    if (!p.isSession && p.daysRemaining !== null && p.daysRemaining > maxDays) {
      maxDays = Math.ceil(p.daysRemaining);
    }
  }

  return { total, totalThirdParty, topCategories, topVendors, maxDays };
}

/**
 * generateSummaryParagraph: Builds a natural-language privacy summary paragraph for the current site.
 * WHY IT EXISTS: Users need a plain-English overview of the site's cookie behavior rather than just
 *   a raw score number. This function composes a readable paragraph that explains what cookies are
 *   set, what categories dominate, which third parties receive data, and how long tracking persists.
 * HOW IT WORKS: Extracts stats via extractParagraphStats(), then constructs sentence fragments: score
 *   badge, cookie count, top category descriptions (using relQty + CAT_PLURAL + CAT_EXPLAIN), top
 *   vendor destinations, persistence duration notes, and a closing verdict. Fragments are joined into
 *   a single coherent paragraph.
 * INPUT: enriched (Array) — enriched cookie items; sr (Object) — score result {score, label}.
 * OUTPUT: string — human-readable summary paragraph.
 */
function generateSummaryParagraph(enriched, sr) {
  const score = Number(sr?.score || 0);
  const label = sr?.label || "Unknown";
  const { total, totalThirdParty, topCategories, topVendors, maxDays } = extractParagraphStats(enriched);

  if (total === 0 || score >= 90) {
    return `This site scored ${score}/100 (${label}). ${total === 0 ? "No tracking cookies were detected." : "This site has excellent privacy practices."}`;
  }

  const parts = [`This site scored ${score}/100 (${label}). It set ${total} cookie${total !== 1 ? "s" : ""}${totalThirdParty > 0 ? ` \u2014 ${totalThirdParty} are third-party` : "."}`];

  if (totalThirdParty > 0 && !parts[parts.length - 1].endsWith(".")) parts.push(".");

  const catParts = [];
  for (const [cat, count] of topCategories.slice(0, 3)) {
    const plural = CAT_PLURAL[cat] || "cookies";
    const explain = CAT_EXPLAIN[cat] || "";
    const qty = relQty(count, total).toLowerCase();
    if (cat === "Unknown") {
      catParts.push(`${qty} ${plural} that ${explain}`);
    } else {
      catParts.push(`${qty} are ${plural} that ${explain}`);
    }
  }
  if (catParts.length >= 1) {
    catParts[0] = catParts[0].charAt(0).toUpperCase() + catParts[0].slice(1);
  }
  if (catParts.length === 1) {
    parts.push(catParts[0] + ".");
  } else if (catParts.length === 2) {
    parts.push(catParts[0] + ", and " + catParts[1] + ".");
  } else if (catParts.length > 2) {
    parts.push(catParts.slice(0, -1).join(", ") + ", and " + catParts[catParts.length - 1] + ".");
  }

  if (topVendors.length > 0) {
    if (topVendors.length === 1) {
      parts.push(`${topVendors[0]} is the main third-party destination.`);
    } else if (topVendors.length === 2) {
      parts.push(`${topVendors[0]} and ${topVendors[1]} are the main third-party destinations.`);
    } else {
      parts.push(`${topVendors[0]}, ${topVendors[1]}, and ${topVendors[2]} are the main third-party destinations.`);
    }
  }

  if (maxDays > 30) {
    parts.push(`Some third-party cookies persist for up to ${maxDays} days.`);
  } else if (maxDays > 1 && totalThirdParty > 0) {
    parts.push(`Third-party cookies persist for up to ${maxDays} days.`);
  }

  if (score < 50) {
    parts.push("Most of your browsing activity on this site is shared with external ad networks.");
  } else if (score < 70) {
    parts.push("Some of your activity is shared with external services.");
  } else {
    parts.push("Your data stays mostly with this site.");
  }

  return parts.join(" ");
}

// â”€â”€ Category metadata â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * CAT_META: Category metadata including display emoji, description, and color for each cookie category.
 * WHY IT EXISTS: Multiple UI components need category descriptions and colors (risk segments, intel
 *   panels, score breakdowns). This constant provides a single source of truth for all category
 *   display properties, avoiding duplicated color strings and descriptions.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → {emoji, desc, color}.
 */
const CAT_META={
  Strict:        {emoji:"S",desc:"Security / Infrastructure",   color:"#007a55"},
  Performance:   {emoji:"P",desc:"Analytics / A/B Testing",     color:"#006699"},
  Functionality: {emoji:"F",desc:"Auth / Preferences",          color:"#996e00"},
  Advertising:   {emoji:"A",desc:"Tracking / Ads / Retargeting", color:"#b32844"},
  Unknown:       {emoji:"U",desc:"Unclassified",                color:"#4d5e77"},
};

/**
 * scoreColor: Maps a numeric privacy score to a color hex for visual display.
 * WHY IT EXISTS: The score ring, verdict text, and stat chips all need color-coding to visually
 *   communicate risk level (red = dangerous, green = excellent) at a glance.
 * HOW IT WORKS: Threshold-based color mapping: 0 → red (#ff4d6e), <25 → orange (#ff7a35),
 *   <50 → yellow (#ffb700), <70 → blue (#00aeff), ≥70 → green (#00e5a0).
 * INPUT: s (number) — privacy score 0–100.
 * OUTPUT: string — hex color code.
 */
function scoreColor(s){return s===0?"#ff4d6e":s<25?"#ff7a35":s<50?"#ffb700":s<70?"#00aeff":"#00e5a0";}

/**
 * methodBadge: Generates a styled HTML badge showing how a cookie was classified.
 * WHY IT EXISTS: Each cookie is classified by one of several methods (DB lookup, domain match,
 *   blocklist, ML, etc.). The badge provides a compact visual indicator of the classification
 *   method and confidence, helping users and developers verify classification accuracy.
 * HOW IT WORKS: Maps the method string to a short label (DB, DM, BL, ML, UN) and a color, then
 *   generates a <span> with inline styles. For ML predictions, includes the confidence percentage
 *   as a tooltip.
 * INPUT: method (string) — classification method name; conf (number|undefined) — ML confidence.
 * OUTPUT: string — HTML <span> element for the badge.
 */
function methodBadge(method,conf){
  const MAP={"DB":"DB","DB-wild":"DB","Domain":"DM","Blocklist":"BL","ML":"ML","Unknown":"UN"};
  const COL={"DB":"#00e5a0","DB-wild":"#00e5a0","Domain":"#ff4d6e","Blocklist":"#ff4d6e","ML":"#00aeff","Unknown":"#8899bb"};
  const lbl=MAP[method]||"?", col=COL[method]||"#8899bb";
  const tip=method==="ML"&&conf
    ? `ML ${Math.round(conf*100)}%`
    : method;
  return `<span class="mbadge" style="background:${col}22;color:${col};border-color:${col}55" title="${tip}">${lbl}</span>`;
}

// — Summary data (registrable domains only) ————————

/**
 * CAT_COLORS: Maps cookie category names to their display color hex codes.
 * WHY IT EXISTS: Consistent color-coding across the UI (risk segments, collected items, category
 *   tabs) requires a single source of truth for category colors. This avoids hardcoded colors
 *   scattered throughout rendering functions.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → hex color string.
 */
const CAT_COLORS={Strict:"#007a55",Performance:"#006699",Functionality:"#996e00",Advertising:"#b32844",Unknown:"#4d5e77"};

/**
 * formatDestination: Formats a third-party domain into a human-readable destination label.
 * WHY IT EXISTS: Raw cookie domains are often subdomains or internal hostnames that are
 *   meaningless to users. This function resolves them to registrable domains and, when possible,
 *   attaches a known vendor label (e.g., "Google (google.com)").
 * HOW IT WORKS: Strips leading dot, resolves the registrable domain via getRegistrableDomain(),
 *   looks up a vendor label via getResolvedVendorInfo(). If vendor and domain differ, returns
 *   "vendor (domain)"; otherwise just the domain.
 * INPUT: domain (string) — raw cookie domain.
 * OUTPUT: string — formatted destination label.
 */
function formatDestination(domain) {
  const clean = domain.replace(/^\./, "").toLowerCase();
  const reg = getRegistrableDomain(clean);
  const vendorInfo = getResolvedVendorInfo(clean, DB);
  const vendor = vendorInfo?.label || "";
  if (vendor && vendor !== reg) return `${vendor} (${reg})`;
  return reg;
}

/**
 * buildSummaryData: Builds the "Sent to" HTML fragment for the summary panel.
 * WHY IT EXISTS: The summary section needs the list of third-party destinations
 *   receiving data. This function pre-renders it as an HTML string so the render
 *   function can drop it directly into the DOM. (The former "Collected" list was
 *   removed: category-typical data types, not cookie-evidenced.)
 * HOW IT WORKS: Iterates over enriched cookies. For third-party cookies, resolves
 *   and formats the destination domain. Then renders the list as HTML with colored
 *   pip indicators. Caps destinations at 10.
 * INPUT: enriched (Array) — enriched cookie items.
 * OUTPUT: {dH: string} — HTML string for the destinations list.
 */
function buildSummaryData(enriched) {
  const destSet = new Set();
  let thirdPartyCount = 0, unresolvedThirdParty = 0;
  for (const item of enriched) {
    if (item.origin !== "Third-party") continue;
    thirdPartyCount++;
    const clean = (item.domain || "").replace(/^\./,"").toLowerCase();
    const reg = clean ? getRegistrableDomain(clean) : "";
    if (reg && reg.includes(".") && !reg.startsWith(".")) {
      destSet.add(formatDestination(clean));
    } else {
      unresolvedThirdParty++;
    }
  }
  if (unresolvedThirdParty) {
    destSet.add(`Unknown third-party destination (${unresolvedThirdParty})`);
  }
  const dH=thirdPartyCount
    ? [...destSet].slice(0,10).map(d=>`<div class="sum-item"><div class="sum-pip" style="background:#0043ff"></div><span>${escapeHtml(d)}</span></div>`).join("")
    : `<div style="font-size:11px;color:#b8d8f0;font-family:var(--font-mono)">// no 3rd-party destinations</div>`;
  return {dH};
}

// â”€â”€ Intel panel â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * buildIntelPanel: Builds a detailed per-cookie intelligence panel shown when a cookie row is clicked.
 * WHY IT EXISTS: Users need to understand what a specific cookie does, who operates it, what data
 *   it collects, and where it sends data. The intel panel provides this deep-dive view for any
 *   individual cookie, turning raw classification data into actionable intelligence.
 * HOW IT WORKS: Calls getCookieIntel() with the cookie's name, category, and domain to retrieve
 *   structured intelligence. Resolves the vendor label, selects a verified/inferred badge, builds
 *   an HTML list of data types gathered, and formats the destination and risk fields. Wraps
 *   everything in styled HTML. Returns a graceful fallback if intel lookup fails.
 * INPUT: cookie (Object) — enriched cookie item with name, cat, domain, vendorResolved.
 * OUTPUT: string — HTML for the intel panel (or fallback).
 */
function buildIntelPanel(cookie) {
  try {
    const name = cookie?.name || "";
    const cat = cookie?.cat || "Unknown";
    const rawDomain = cookie?.domain || "";
    const intel = getCookieIntel(name, cat, rawDomain);
    const resolvedVendor = cookie?.vendorResolved?.label || intel?.vendor || "";
    const col=CAT_META[cat]?.color||"#8899bb";
    const badge=intel.isSpecific?`<span class="intel-badge badge-v">verified</span>`:`<span class="intel-badge badge-i">inferred</span>`;
    const dataList=intel.dataGathered.map(d=>`<li>${escapeHtml(d)}</li>`).join("");
    const safeDocs = intel.docs && /^https?:\/\//i.test(intel.docs) ? escapeHtml(intel.docs) : "";
    return `<div class="intel-panel">
      <div class="intel-hdr"><span class="intel-name">${escapeHtml(name)}</span>${badge}</div>
      ${resolvedVendor?`<div class="intel-row-inner"><div class="intel-lbl">VENDOR</div><div class="intel-val">${escapeHtml(resolvedVendor)}</div></div>`:""}
      <div class="intel-row-inner"><div class="intel-lbl">DOMAIN</div><div class="intel-val">${escapeHtml(rawDomain||"unknown")}</div></div>
      <div class="intel-row-inner"><div class="intel-lbl">DATA COLLECTED</div><ul class="intel-list">${dataList}</ul></div>
      <div class="intel-row-inner"><div class="intel-lbl">DESTINATION</div><div class="intel-val">${escapeHtml(intel.destination)}</div></div>
      ${intel.risk?`<div class="intel-row-inner"><div class="intel-lbl">RISK</div><div class="intel-val" style="color:${col}">${escapeHtml(intel.risk)}</div></div>`:""}
      ${safeDocs?`<a class="intel-link" href="${safeDocs}" target="_blank">privacy docs</a>`:""}
    </div>`;
  } catch(e) { return `<div class="intel-panel"><div class="intel-lbl">no intel available</div></div>`; }
}

// â”€â”€ UI state â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let currentDomain="", lastCookieCount=0;
let currentTabId=null;
let openCategory="All", openCookieKey=null, refreshTimer=null;
let _intelCookieMap = {};
let lastCategories=null, lastScore=null;
let lastEnriched=[];
let lastMlDiag=[];
let lastDecisions=null;
let diagTab = "cookie";
let toastTimer=null;
let globalPurgeFeed=[];
let _scanId = 0;
/**
 * CATEGORY_ORDER: Canonical ordering of cookie categories used for tab rendering and iteration.
 * WHY IT EXISTS: Categories must appear in a consistent order across the UI (tabs, table, breakdown)
 *   rather than relying on object key ordering. This array defines that order.
 * INPUT: None (constant).
 * OUTPUT: Array of category name strings in display order.
 */
const CATEGORY_ORDER=["Strict","Performance","Functionality","Advertising","Unknown"];

/**
 * TAB_COLORS: Maps category names to tab color hex codes for the category tab bar.
 * WHY IT EXISTS: Each category tab in the UI needs a distinct color to visually differentiate
 *   categories. This provides the single source of truth for tab styling.
 * INPUT: None (constant).
 * OUTPUT: Object mapping category name → hex color string.
 */
const TAB_COLORS={
  Strict:"#00e5a0",
  Performance:"#00aeff",
  Functionality:"#ffb700",
  Advertising:"#ff4d6e",
  Unknown:"#8899bb",
};

/**
 * flattenCookies: Converts the category-keyed cookie map into a flat array in canonical order.
 * WHY IT EXISTS: Some UI operations (e.g., the "All" tab, scoring, export) need a single flat array
 *   of all cookies rather than a per-category map. This function normalizes the data structure.
 * HOW IT WORKS: Iterates CATEGORY_ORDER, appending each category's cookies (with `cat` attached)
 *   into a single array.
 * INPUT: categories (Object) — map of category name → array of cookie items.
 * OUTPUT: Array — flat list of all cookies with their `cat` property set.
 */
function flattenCookies(categories) {
  const all = [];
  for (const cat of CATEGORY_ORDER) {
    for (const c of (categories[cat] || [])) {
      all.push({ ...c, cat });
    }
  }
  return all;
}

/**
 * stableCookieKey: Generates a unique, stable deduplication key for a cookie.
 * WHY IT EXISTS: Cookies with the same name, domain, and path are semantically identical. This
 *   key is used for deduplication, row click state tracking (openCookieKey), and as data-key
 *   attributes in the cookie table. Without it, duplicate cookies would confuse the UI.
 * HOW IT WORKS: Joins the normalized name, host, and path with "::" to form a stable string key.
 * INPUT: cookie (Object) — raw cookie with name, domain, path.
 * OUTPUT: string — unique key like "session_id::.example.com::/".
 */
function stableCookieKey(cookie) {
  return [
    cookie?.name || "",
    normalizeHost(cookie?.domain || ""),
    cookie?.path || "/",
  ].join("::");
}

/**
 * getPanelState: Captures the current UI state (scroll position, summary panel open/closed).
 * WHY IT EXISTS: When the panel re-renders (e.g., after a scan update), the user's scroll position
 *   and open/closed panel state would be lost. This function captures that state so it can be
 *   restored after DOM replacement.
 * HOW IT WORKS: Reads scrollTop from the .cookie-card element and checks if #sum-body is displayed.
 * INPUT: None (reads from DOM).
 * OUTPUT: {scrollTop: number, summaryOpen: boolean}.
 */
function getPanelState() {
  const cookieCard = document.querySelector(".cookie-card");
  return {
    scrollTop: cookieCard?.scrollTop || 0,
    summaryOpen: document.getElementById("sum-body")?.style.display === "block",
  };
}

/**
 * restorePanelState: Restores previously captured UI state (scroll position, panel open/closed).
 * WHY IT EXISTS: After a full re-render replaces the DOM, this function puts the user back where
 *   they were — same scroll position and same panel open/close state — preventing disorienting resets.
 * HOW IT WORKS: Sets the summary body's display and trigger button class if summaryOpen is true,
 *   then restores scrollTop on the cookie card.
 * INPUT: state (Object) — result from getPanelState().
 * OUTPUT: Modifies DOM (display, class, scrollTop).
 */
function restorePanelState(state) {
  if (!state) return;
  const cookieCard = document.querySelector(".cookie-card");
  const body = document.getElementById("sum-body");
  const btn = document.getElementById("sum-trigger");
  if (body && btn && state.summaryOpen) {
    body.style.display = "block";
    btn.classList.add("open");
  }
  if (cookieCard) cookieCard.scrollTop = state.scrollTop;
}

/**
 * formatPurgeTime: Converts a timestamp (ms since epoch) into a locale-formatted date/time string.
 * WHY IT EXISTS: Session Guard audit events store timestamps as numbers. This function formats them
 *   into human-readable strings for display in the audit history panel.
 * HOW IT WORKS: Validates the timestamp is finite, then uses toLocaleString() for locale-aware formatting.
 * INPUT: ts (number) — milliseconds since epoch.
 * OUTPUT: string — locale-formatted date/time, or "unknown time" if invalid.
 */
function formatPurgeTime(ts) {
  if (!Number.isFinite(ts)) return "unknown time";
  return new Date(ts).toLocaleString();
}

/**
 * renderPurgeAudit: Renders the Session Guard cookie-purge audit history as HTML.
 * WHY IT EXISTS: Users need visibility into what Session Guard has done — which cookies were removed,
 *   when, and why. This function renders a timeline of purge events with status pills, cookie lists,
 *   and trigger labels so users can audit the extension's automated actions.
 * HOW IT WORKS: Maps each feed event to an audit block showing: status (removed/attempted/skipped)
 *   with color, removal count, site key, trigger type (site exit, tab close, etc.), formatted
 *   timestamp, and individual cookie name/domain lines. Limits display to 8 most recent events.
 * INPUT: feed (Array) — array of purge event objects from globalPurgeFeed.
 * OUTPUT: string — HTML of audit blocks (or empty-state message).
 */
function renderPurgeAudit(feed) {
  if (!Array.isArray(feed) || !feed.length) {
    return `<div class="audit-empty">No Session Guard activity yet. Enable Session Guard, leave a site, then check back.</div>`;
  }
  const triggerLabel = t => {
    if (t === "site_exit") return "left site";
    if (t === "tab_close") return "tab closed";
    if (t === "browser_close") return "browser closed";
    return t || "unknown";
  };
  const items = feed.slice(0, 8).map(event => {
    const statusColor = event.status === "removed" ? "#00e5a0" : event.status === "attempted" ? "#ffb700" : "#8899bb";
    const statusLabel = event.status === "removed" ? "removed" : event.status === "attempted" ? "attempted" : "skipped";
    const cookieLines = Array.isArray(event.cookies) && event.cookies.length
      ? `<div class="audit-list">${event.cookies.map(c => {
          return `<div class="audit-item"><span class="audit-cookie-name">${escapeHtml(c.name) || "(unnamed)"}</span><span class="audit-cookie-domain">@ ${escapeHtml(c.domain) || "unknown"}</span></div>`;
        }).join("")}</div>`
      : `<div class="audit-empty audit-empty-inner">No cookies were removed in this run</div>`;
    return `
      <div class="audit-block">
        <div class="audit-meta">
          <span class="audit-pill" style="border-color:${statusColor};color:${statusColor}">${statusLabel}</span>
          <span class="audit-pill">${Number(event.removedCount || 0)} removed</span>
        </div>
        <div class="audit-site">${event.siteKey || "unknown"}</div>
        <div class="audit-time">${triggerLabel(event.trigger)} &middot; ${formatPurgeTime(event.timestamp)}</div>
        ${cookieLines}
      </div>
    `;
  }).join("");
  return items;
}

/**
 * scheduleScan: Debounces scan requests so rapid navigation doesn't flood the background with requests.
 * WHY IT EXISTS: Tab events (onActivated, onUpdated) can fire in rapid succession during navigation,
 *   back/forward, or reload. Without debouncing, each event would trigger a full scan, causing
 *   unnecessary processing and UI flicker. This ensures only the last scan in a burst executes.
 * HOW IT WORKS: Clears any pending refresh timer, then sets a new 250ms timer that calls doScan().
 *   If another scheduleScan call arrives within 250ms, the previous timer is canceled.
 * INPUT: tabId (number) — Chrome tab ID; url (string) — tab URL.
 * OUTPUT: Schedules a doScan call after 250ms debounce.
 */
function scheduleScan(tabId, url) {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    doScan(tabId, url);
  }, 250);
}

// â”€â”€ Render â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// ── Targeted update functions ──────────────────────────────────
let panelRendered = false;
let tableDebounceTimer = null;

/**
 * updateScoreRing: Performs a targeted update of the SVG score ring and surrounding score display
 *   without re-rendering the entire panel.
 * WHY IT EXISTS: The score ring, verdict label, tracking note, stats, and risk composition bar all
 *   need to reflect the latest score. A full re-render would destroy scroll position and open panels.
 *   This function updates only the score-related DOM elements, preserving user state.
 * HOW IT WORKS: Computes the SVG circumference constant and color, generates a risk breakdown
 *   segment bar from the score's breakdown object, then updates individual DOM elements by ID:
 *   score number, verdict label, tracking note, total count, third-party percentage, and risk
 *   segments. Finally, animates the SVG ring's stroke-dashoffset via requestAnimationFrame.
 * INPUT: sr (Object) — {score, label, breakdown, total, tpPct}.
 * OUTPUT: Modifies DOM elements in-place.
 */
function updateScoreRing(sr) {
  const C = 2 * Math.PI * 29, sc = scoreColor(sr.score);
  const noteText = sr.score === 0 ? "excessive tracking" : sr.score < 25 ? "heavy tracking" : sr.score < 50 ? "significant tracking" : sr.score < 70 ? "some tracking" : "no tracking detected";
  const totalBD = Object.values(sr.breakdown).reduce((a, b) => a + b, 0) || 1;
  const riskSegs = Object.entries(sr.breakdown)
    .filter(([, v]) => v > 0)
    .map(([cat, v]) => `<div class="risk-seg" style="width:${Math.round(v / totalBD * 100)}%;background:${CAT_META[cat]?.color || "#8899bb"}"></div>`)
    .join("");

  const el = (id) => document.getElementById(id);
  const scoreNum = el("score-number");
  const verdict = el("score-verdict");
  const note = el("score-note");
  const statsTotal = el("stats-total");
  const statsTp = el("stats-tp");
  const riskTrack = el("risk-segments");

  if (scoreNum) { scoreNum.textContent = sr.score; scoreNum.style.color = sc; }
  if (verdict) { verdict.textContent = sr.label; verdict.style.color = sc; }
  if (note) note.textContent = noteText;
  if (statsTotal) { statsTotal.textContent = sr.total; statsTotal.style.color = sc; }
  if (statsTp) statsTp.textContent = sr.tpPct + "%";
  if (riskTrack) riskTrack.innerHTML = riskSegs || `<div style="width:100%;background:var(--c0)"></div>`;

  requestAnimationFrame(() => {
    const ring = el("ring-fg");
    if (ring) {
      ring.style.transition = "stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)";
      ring.setAttribute("stroke", sc);
      ring.style.strokeDashoffset = (C - (sr.score / 100) * C).toString();
    }
  });
}

/**
 * updateSummary: Performs a targeted update of the summary panel (paragraph, sent-to).
 * WHY IT EXISTS: The summary section needs to reflect the latest cookie data without a full re-render.
 *   This function updates only the two summary sub-elements, preserving any open/closed state.
 * HOW IT WORKS: Sets the summary paragraph text via generateSummaryParagraph(), then rebuilds the
 *   sent-to HTML via buildSummaryData() and injects it into its container.
 * INPUT: enriched (Array) — enriched cookie items; sr (Object) — score result.
 * OUTPUT: Modifies DOM elements #sum-paragraph, #sum-sent.
 */
function updateSummary(enriched, sr) {
  const para = document.getElementById("sum-paragraph");
  const sent = document.getElementById("sum-sent");
  if (para) para.textContent = generateSummaryParagraph(enriched, sr);
  if (sent) {
    const { dH } = buildSummaryData(enriched);
    sent.innerHTML = dH;
  }
}

/**
 * updateCategoryTabs: Updates tab count badges and active state for all category tabs.
 * WHY IT EXISTS: After a scan, each category's cookie count may change and the active tab may need
 *   to update. This function synchronizes the tab bar DOM with the latest categories data without
 *   rebuilding the entire tab bar.
 * HOW IT WORKS: Queries all .cat-tab buttons, reads each tab's data-cat attribute, updates the
 *   .tab-count span with the current count from categories, and toggles the "active" class based
 *   on whether this tab matches openCategory.
 * INPUT: categories (Object) — map of category name → array of cookies.
 * OUTPUT: Modifies DOM elements (count text, active class).
 */
function updateCategoryTabs(categories) {
  const container = document.getElementById("cat-tabs");
  if (!container) return;
  const buttons = container.querySelectorAll(".cat-tab");
  buttons.forEach(btn => {
    const cat = btn.getAttribute("data-cat");
    const countEl = btn.querySelector(".tab-count");
    if (countEl) countEl.textContent = (categories[cat] || []).length;
    btn.classList.toggle("active", openCategory === cat);
  });
}

/**
 * updateCategoryTabsActive: Updates only the active state of category tabs (no count update).
 * WHY IT EXISTS: When the user simply switches between category tabs, the cookie counts don't
 *   change — only which tab is highlighted. This lighter function avoids unnecessary DOM writes
 *   for the common case of tab switching.
 * INPUT: None (reads from globals openCategory).
 * OUTPUT: Modifies DOM (toggles "active" class on tab buttons).
 */
function updateCategoryTabsActive() {
  const container = document.getElementById("cat-tabs");
  if (!container) return;
  container.querySelectorAll(".cat-tab").forEach(btn => {
    const cat = btn.getAttribute("data-cat");
    btn.classList.toggle("active", openCategory === cat);
  });
}

/**
 * buildTableHtml: Generates the full HTML for the cookie table, including rows and any open intel panel.
 * WHY IT EXISTS: The cookie table is the primary data display. It needs to render cookie name, origin,
 *   lifespan, classification method, and security flags for each cookie, plus an expandable intel
 *   panel for the selected cookie. This function produces the complete HTML so the DOM can be swapped.
 * HOW IT WORKS: Selects cookies based on openCategory ("All" flattens all categories, otherwise filters
 *   to the selected category). Builds a category explanation sentence if a specific category is open.
 *   Iterates cookies to build table rows with escapeHtml-safe names, origin labels, lifespan,
 *   method badges, and H/S flags. If a cookie is the openCookieKey, its intel panel is inlined.
 *   Also populates _intelCookieMap for click handling.
 * INPUT: categories (Object) — map of category name → array of enriched cookie items.
 * OUTPUT: string — complete HTML string for the cookie table.
 */
function buildTableHtml(categories) {
  const selectedCookies = openCategory === "All"
    ? flattenCookies(categories)
    : (categories[openCategory] || []).map((c, i) => ({ ...c, cat: openCategory, _idx: i }));
  const catColor = CAT_META[openCategory]?.color || "#8899bb";
  const catSentence = openCategory !== "All" && CAT_SENTENCE[openCategory]
    ? `<div class="cat-explain" style="border-left:3px solid ${catColor}"><span style="color:#153f95">${CAT_SENTENCE[openCategory]}</span></div>`
    : "";
  if (!selectedCookies.length) return `${catSentence}<div class="no-ck">// no cookies</div>`;
  _intelCookieMap = {};
  selectedCookies.forEach((c, i) => {
    const ck = c.key || `${c.cat}:${i}`;
    _intelCookieMap[ck] = c;
  });
  return `${catSentence}<table>
    <thead>
      <tr><th>Name</th><th>Origin</th><th>Life</th><th>Via</th><th>Flags</th></tr>
    </thead>
    <tbody>${
      selectedCookies.map((c, i) => {
        const flags = [c.httpOnly ? `<span class="flag fH">H</span>` : "", c.secure ? `<span class="flag fS">S</span>` : ""].filter(Boolean).join("");
        const ck = c.key || `${c.cat}:${i}`, io = openCookieKey === ck;
        const safeName = escapeHtml(c.name);
        const safeKey = escapeHtml(ck);
        const intel = io ? buildIntelPanel(c) : "";
        return `<tr class="ck-row ${io ? "active" : ""}" data-key="${safeKey}">
          <td><div class="ck-name" title="${safeName}">${safeName}</div></td>
          <td class="${c.origin === "Third-party" ? "ck-3p" : "ck-1p"}">${c.origin === "Third-party" ? "3rd" : "1st"}</td>
          <td class="ck-life">${c.lifespan}</td>
          <td>${methodBadge(c.method, c.confidence)}</td>
          <td><div class="flags">${flags}</div></td>
        </tr>${intel ? `<tr class="intel-row"><td colspan="5" style="padding:0">${intel}</td></tr>` : ""}`;
      }).join("")
    }</tbody>
  </table>`;
}

/**
 * updateCookieTable: Replaces the cookie table DOM and re-attaches click listeners.
 * WHY IT EXISTS: After new cookie data arrives, the entire table needs to be rebuilt with fresh HTML.
 *   This function handles the DOM swap and ensures click handlers for row expand/collapse work
 *   on the newly created elements.
 * HOW IT WORKS: Gets the #cookie-card container, sets its innerHTML to the output of buildTableHtml(),
 *   then calls attachCookieRowListeners() to wire up click events on the new rows.
 * INPUT: categories (Object) — map of category name → array of enriched cookies.
 * OUTPUT: Replaces #cookie-card innerHTML.
 */
function updateCookieTable(categories) {
  const container = document.getElementById("cookie-card");
  if (!container) return;
  container.innerHTML = buildTableHtml(categories);
  attachCookieRowListeners(container);
}

/**
 * attachCookieRowListeners: Wires up click handlers for cookie table rows to toggle intel panel expansion.
 * WHY IT EXISTS: Each cookie row needs to expand/collapse an intel detail panel when clicked. Since
 *   rows are rebuilt on every update, this function re-attaches those handlers to the new DOM elements.
 *   It also enforces single-expand behavior (only one panel open at a time).
 * HOW IT WORKS: Queries all .ck-row elements, attaches click listeners that: read the row's data-key,
 *   find the next sibling .intel-row, toggle its display, manage the "active" class, and update
 *   the global openCookieKey. If no intel row exists (row not yet built with panel), triggers a
 *   full table rebuild to generate it.
 * INPUT: root (Element) — the container element holding the table rows.
 * OUTPUT: Attaches event listeners to DOM elements; modifies openCookieKey global.
 */
function attachCookieRowListeners(root) {
  root.querySelectorAll(".ck-row").forEach(row => {
    row.addEventListener("click", () => {
      const key = row.getAttribute("data-key");
      const intelRow = row.nextElementSibling;
      if (intelRow && intelRow.classList.contains("intel-row")) {
        const isOpen = intelRow.style.display !== "table-row";
        root.querySelectorAll(".intel-row").forEach(r => r.style.display = "none");
        root.querySelectorAll(".ck-row").forEach(r => r.classList.remove("active"));
        if (isOpen) {
          intelRow.style.display = "table-row";
          row.classList.add("active");
          openCookieKey = key;
        } else {
          openCookieKey = null;
        }
      } else {
        openCookieKey = key;
        const container = document.getElementById("cookie-card");
        if (container) {
          container.innerHTML = buildTableHtml(lastCategories);
          attachCookieRowListeners(container);
        }
      }
    });
  });
}

/**
 * updateAll: Convenience function that triggers all targeted update functions at once.
 * WHY IT EXISTS: Some code paths (like initial render or full re-scan) need to update the score ring,
 *   summary, tabs, and table simultaneously. Rather than calling each individually, this function
 *   bundles them into one call.
 * HOW IT WORKS: Calls updateScoreRing, updateSummary, updateCategoryTabs, and updateCookieTable
 *   in sequence with the provided data.
 * INPUT: sr (Object) — score result; categories (Object) — category map; enriched (Array) — enriched cookies.
 * OUTPUT: Delegates to four update functions.
 */
function updateAll(sr, categories, enriched) {
  updateScoreRing(sr);
  updateSummary(enriched, sr);
  updateCategoryTabs(categories);
  updateCookieTable(categories);
}

/**
 * debouncedUpdateTable: Debounces cookie table DOM updates to avoid rapid successive rebuilds.
 * WHY IT EXISTS: Rapid data updates (e.g., multiple COOKIES_UPDATED messages in quick succession)
 *   would each trigger a full table rebuild, causing janky rendering. This function batches them
 *   so only the latest state is rendered after a 300ms quiet period.
 * HOW IT WORKS: Clears any pending timer, then sets a 300ms timer that calls updateCookieTable().
 * INPUT: categories (Object) — category map to render.
 * OUTPUT: Schedules updateCookieTable after 300ms.
 */
function debouncedUpdateTable(categories) {
  clearTimeout(tableDebounceTimer);
  tableDebounceTimer = setTimeout(() => {
    tableDebounceTimer = null;
    updateCookieTable(categories);
  }, 300);
}

/**
 * renderSettingsPage: Generates the full HTML for the settings page view.
 * WHY IT EXISTS: The settings page is a separate view from the main cookie analysis panel. It
 *   provides toggle buttons for the three main protection features (CC master, consent analysis,
 *   widget) with proper labels and descriptions. This function builds that view so it can be
 *   injected into the main container when the user clicks the settings gear icon.
 * HOW IT WORKS: Reads current toggle states from protectionSettings, then generates a settings-page
 *   HTML structure with a back button, title, and three settings rows. Each row has a label,
 *   description, and a toggle button styled ON/OFF with data-setting attribute for event binding.
 *   Consent and widget toggles are disabled when CC master is off.
 * INPUT: None (reads from globals protectionSettings).
 * OUTPUT: string — HTML for the settings page.
 */
function renderSettingsPage() {
  const ccOn = protectionSettings.ccEnabled !== false;
  const consentOn = protectionSettings.consentAnalysisEnabled !== false;
  const widOn = protectionSettings.widgetEnabled !== false;
  const tbList = Array.isArray(protectionSettings.tbSiteWhitelist) ? protectionSettings.tbSiteWhitelist : [];
  const sgList = Array.isArray(protectionSettings.sgSiteWhitelist) ? protectionSettings.sgSiteWhitelist : [];
  const wlBlock = (engine, label, desc, list) => `
    <div class="wl-block">
      <div class="wl-block-label">${label} — exempt sites</div>
      <div class="wl-block-desc">${desc}</div>
      <div class="wl-add">
        <input class="wl-input" type="text" data-engine="${engine}" id="wl-${engine}-input" placeholder="e.g. google.com" autocomplete="off" spellcheck="false">
        <button class="wl-add-btn" data-engine="${engine}">Add</button>
      </div>
      <ul class="wl-list" id="wl-${engine}-list">${list.map((entry, i) => `<li class="wl-item"><span>${escapeHtml(entry)}</span><button class="wl-remove" data-engine="${engine}" data-index="${i}" title="Remove">&times;</button></li>`).join("")}</ul>
    </div>`;
  return `<div class="settings-page">
    <button class="settings-back" id="settings-back">&#8592; Back</button>
    <div class="settings-title">Settings</div>
    <div class="settings-row">
      <div class="settings-row-info">
        <div class="settings-row-label">Cookie Crumbs</div>
        <div class="settings-row-desc">Turns the entire extension on or off.</div>
      </div>
      <button class="settings-toggle ${ccOn ? 'on' : ''}" data-setting="ccEnabled" aria-pressed="${ccOn}">${ccOn ? 'ON' : 'OFF'}</button>
    </div>
    <div class="settings-row">
      <div class="settings-row-info">
        <div class="settings-row-label">Cookie Consent</div>
        <div class="settings-row-desc">Analyzes cookie consent banners before you accept.</div>
      </div>
      <button class="settings-toggle ${consentOn ? 'on' : ''}" data-setting="consentAnalysisEnabled" aria-pressed="${consentOn}" ${!ccOn ? 'disabled' : ''}>${consentOn ? 'ON' : 'OFF'}</button>
    </div>
    <div class="settings-row">
      <div class="settings-row-info">
        <div class="settings-row-label">Widget</div>
        <div class="settings-row-desc">Shows a score badge on every page you visit.</div>
      </div>
      <button class="settings-toggle ${widOn ? 'on' : ''}" data-setting="widgetEnabled" aria-pressed="${widOn}" ${!ccOn ? 'disabled' : ''}>${widOn ? 'ON' : 'OFF'}</button>
    </div>
    <div class="wl-section-title">Site whitelists</div>
    ${wlBlock("tb", "Tracking Protection", "Cookies and tracker requests are never blocked on these sites. Independent of Session Guard.", tbList)}
    ${wlBlock("sg", "Session Guard", "Session cookies are never purged when leaving these sites. Independent of Tracking Protection.", sgList)}
    <div class="wl-hint">Entries are registrable domains: add google.com once and every subdomain (mail.google.com, accounts.google.com) is covered — no subdomain lists needed.</div>
  </div>`;
}

/**
 * render: Full-panel render function that rebuilds the entire side panel HTML from scratch.
 * WHY IT EXISTS: On initial load, first scan, or when the view mode changes (settings ↔ analysis),
 *   the entire panel DOM needs to be reconstructed. This is the "nuclear option" — it replaces
 *   everything. For incremental updates, the targeted update functions (updateScoreRing, etc.) are used.
 * HOW IT WORKS: If in settings view or CC is disabled, renders the settings page. Otherwise, captures
 *   panel state (scroll, summary open), then builds the full HTML: score ring with SVG animation,
 *   domain bar, risk composition segments, protection toggles (session lock, tracker blocking),
 *   expandable summary card with paragraph/collected/sent-to, Session Guard audit history, category
 *   tabs, cookie table, and footer. Restores panel state after render and attaches all event listeners.
 * INPUT: categories (Object) — category map; sr (Object) — score result; domain (string) — site domain.
 * OUTPUT: Replaces #main innerHTML; attaches listeners; restores UI state.
 */
function render(categories, sr, domain) {
  const main = document.getElementById("main");
  if (settingsViewOpen || !ccEnabled) {
    main.innerHTML = renderSettingsPage();
    return;
  }
  const panelState = getPanelState();
  const C = 2 * Math.PI * 29, sc = scoreColor(sr.score);
  const sessionLockEnabled = protectionSettings.sessionLockEnabled !== false;
  // Whitelist chip state: is the site shown in the panel on each engine's list?
  const wlSiteNow = normalizeSiteWhitelistEntry(currentDomain || "");
  const tbWlActive = !!wlSiteNow && siteMatchesWhitelist(wlSiteNow, protectionSettings.tbSiteWhitelist);
  const sgWlActive = !!wlSiteNow && siteMatchesWhitelist(wlSiteNow, protectionSettings.sgSiteWhitelist);
  const totalBD = Object.values(sr.breakdown).reduce((a, b) => a + b, 0) || 1;
  const riskSegs = Object.entries(sr.breakdown)
    .filter(([, v]) => v > 0)
    .map(([cat, v]) => `<div class="risk-seg" style="width:${Math.round(v / totalBD * 100)}%;background:${CAT_META[cat]?.color || "#8899bb"}"></div>`)
    .join("");
  const noteText = sr.score === 0 ? "excessive tracking" : sr.score < 25 ? "heavy tracking" : sr.score < 50 ? "significant tracking" : sr.score < 70 ? "some tracking" : "no tracking detected";
  const { dH } = buildSummaryData(lastEnriched);
  const summaryParagraph = generateSummaryParagraph(lastEnriched, sr);
  const totalCookies = CATEGORY_ORDER.reduce((sum, cat) => sum + (categories[cat] || []).length, 0);

  const tabsHtml = CATEGORY_ORDER.map(cat => {
    const count = (categories[cat] || []).length;
    const active = openCategory === cat;
    const color = TAB_COLORS[cat];
    return `<button class="cat-tab ${active ? "active" : ""}" data-cat="${cat}" style="--tab:${color}">
      <span class="tab-name">${cat}</span>
      <span class="tab-count">${count}</span>
    </button>`;
  }).join("");

  const tableHtml = buildTableHtml(categories);

  main.innerHTML = `
    <div class="score-wrap">
      <button class="hdr-btn pc-btn" id="settings-btn" title="Settings">&#9881;</button>
      <div class="score-row">
        <div class="ring-wrap">
          <svg viewBox="0 0 74 74"><circle class="ring-track" cx="37" cy="37" r="29"/>
          <circle class="ring-fill" id="ring-fg" cx="37" cy="37" r="29"
            stroke="${sc}" stroke-dasharray="${C}" stroke-dashoffset="${C}"/></svg>
          <div class="ring-center"><span class="ring-score" id="score-number" style="color:${sc}">${sr.score}</span><span class="ring-label">/ 100</span></div>
        </div>
        <div class="score-meta">
          <div class="verdict" id="score-verdict" style="color:${sc}">${sr.label}</div>
          <div class="score-note" id="score-note">${noteText}</div>
          <div class="stats-row" id="stats-row">
            <div class="stat-chip"><b id="stats-total" style="color:${sc};font-size:16px">${sr.total}</b> cookies</div>
            <div class="stat-chip">3rd party <b id="stats-tp" style="color:#ff4d6e">${sr.tpPct}%</b></div>
          </div>
        </div>
      </div>
      <div class="domain-bar"><div class="domain-dot"></div><span>${domain}</span></div>
      <div class="risk-label">RISK COMPOSITION</div>
      <div class="risk-track" id="risk-segments">${riskSegs || `<div style="width:100%;background:var(--c0)"></div>`}</div>
      <div class="protection-row">
        <div class="protection-card ${sessionLockEnabled ? "card-on" : ""}">
          <div class="protection-label">Session Guard <button class="help-btn" data-help="sessionLock">?</button></div>
          <div class="protection-controls">
            <button class="wl-chip ${sgWlActive ? "on" : ""}" data-whitelist="sg" ${wlSiteNow ? "" : "disabled"} title="${wlChipTitle(wlSiteNow, "sg")}">${wlChipText(sgWlActive)}</button>
            <button class="settings-toggle ${sessionLockEnabled ? "on" : ""}" data-setting="sessionLockEnabled" aria-pressed="${sessionLockEnabled ? "true" : "false"}">${sessionLockEnabled ? "ON" : "OFF"}</button>
          </div>
        </div>
        <div class="protection-card card-on">
          <div class="protection-label">Tracking Protection <button class="help-btn" data-help="riskBlocking">?</button></div>
          <div class="protection-controls">
            <button class="wl-chip ${tbWlActive ? "on" : ""}" data-whitelist="tb" ${wlSiteNow ? "" : "disabled"} title="${wlChipTitle(wlSiteNow, "tb")}">${wlChipText(tbWlActive)}</button>
            <button class="settings-toggle on" data-active-info="tracking" aria-pressed="true" title="Tracking Protection is always on">ACTIVE</button>
          </div>
        </div>
        <div class="help-popover" id="help-popover"></div>
      </div>
    </div>

    <div class="summary-card">
      <button class="section-trigger" id="sum-trigger">
        <span class="trigger-icon">*</span>
        <span class="trigger-label">Data Summary</span>
        <span class="trigger-chevron">&gt;</span>
      </button>
      <div class="summary-body" id="sum-body" style="display:none;padding-right:8px;scrollbar-gutter:stable">
        <div class="sum-paragraph" id="sum-paragraph" style="font-size:14px;line-height:1.65;font-weight:500;letter-spacing:.01em;margin:0 0 14px;padding:14px 14px 12px;border:1px solid rgba(255,255,255,.10);border-radius:14px;background:rgba(255,255,255,.04);color:var(--white)">${escapeHtml(summaryParagraph)}</div>
        <div class="sum-section">
          <div class="sum-lbl">Sent to</div>
          <div class="sum-list" id="sum-sent">${dH}</div>
        </div>
      </div>
    </div>

    <div class="cat-tabs" id="cat-tabs">${tabsHtml}</div>

    <div class="cookie-card" id="cookie-card">${tableHtml}</div>

    <footer class="footer">
      <div class="leg"><div class="leg-sq" style="background:#00aeff"></div>HttpOnly</div>
      <div class="leg"><div class="leg-sq" style="background:#00e5a0"></div>Secure</div>
      <button class="debug-toggle" id="debug-toggle-btn">Cookie List</button>
    </footer>`;

  requestAnimationFrame(() => {
    const ring = document.getElementById("ring-fg");
    if (ring) {
      ring.style.transition = "stroke-dashoffset 1.2s cubic-bezier(.22,1,.36,1)";
      ring.style.strokeDashoffset = (C - (sr.score / 100) * C).toString();
    }
  });
  attachListeners();
  restorePanelState(panelState);
}

/**
 * attachListeners: Binds all event listeners for the main panel UI elements.
 * WHY IT EXISTS: After every full render (which replaces innerHTML), all previously attached
 *   event listeners are destroyed. This function re-attaches them: summary expand/collapse toggle,
 *   category tab click handlers, cookie row click handlers,
 *   and the back-to-top scroll button. It must be called after every render() to keep the UI interactive.
 * HOW IT WORKS: Attaches click listeners to #sum-trigger (toggles summary body and hides other sections),
 *   all .cat-tab buttons (switch openCategory and re-render table),
 *   cookie row listeners via attachCookieRowListeners(), and a scroll listener on .cookie-card to
 *   show/hide a back-to-top button.
 * INPUT: None (operates on DOM elements).
 * OUTPUT: Attaches event listeners to DOM elements.
 */
function attachListeners(){
  document.getElementById("sum-trigger")?.addEventListener("click",()=>{
    const body=document.getElementById("sum-body"),btn=document.getElementById("sum-trigger");
    if(!body||!btn) return;
    const o=body.style.display==="block";
    body.style.display=o?"none":"block";
    btn.classList.toggle("open",!o);
    const auditCard=document.querySelector(".audit-card");
    const catTabsEl=document.querySelector(".cat-tabs");
    const cookieCardEl=document.querySelector(".cookie-card");
    if(auditCard) auditCard.style.display=o?"":"none";
    if(catTabsEl) catTabsEl.style.display=o?"":"none";
    if(cookieCardEl) cookieCardEl.style.display=o?"":"none";
    const summaryCard=document.querySelector(".summary-card");
    if(summaryCard) summaryCard.style.flex=o?"0 0 auto":"1";
  });
    document.querySelectorAll(".cat-tab").forEach(btn=>{
      btn.addEventListener("click",()=>{
        const cat=btn.getAttribute("data-cat");
        if(!lastCategories || !lastScore) return;
        openCategory = openCategory === cat ? "All" : (cat || "All");
        openCookieKey = null;
        updateCategoryTabsActive();
        updateCookieTable(lastCategories);
      });
  });
  attachCookieRowListeners(document.getElementById("cookie-card") || document);

  const main = document.querySelector(".cookie-card");
  const topBtn = document.getElementById("back-top-btn");
  if (main && topBtn) {
    if (main._backTopHandler) {
      main.removeEventListener("scroll", main._backTopHandler);
    }
    const syncTopButton = () => {
      const show = main.scrollTop > 180;
      topBtn.classList.toggle("show", show);
    };
    main._backTopHandler = syncTopButton;
    main.addEventListener("scroll", syncTopButton, { passive: true });
    syncTopButton();
    topBtn.onclick = () => {
      main.scrollTo({ top: 0, behavior: "smooth" });
    };
  }
  syncDebugButton();
}

// â”€â”€ Toast â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * showToast: Displays a brief toast notification at the bottom of the panel.
 * WHY IT EXISTS: The extension needs to provide transient feedback to the user — e.g., "+3 new cookies
 *   detected" or "Session Guard removed 2 risky cookies" — without interrupting their workflow with
 *   a modal or blocking dialog.
 * HOW IT WORKS: Gets the #toast element, clears any existing hide timer, sets the message text, adds
 *   the "show" CSS class to make it visible, then sets a 2500ms timer to remove the class (fade out).
 *   Rapid successive calls cancel the previous timer so only the latest message is shown.
 * INPUT: msg (string) — message to display.
 * OUTPUT: Modifies DOM (toast text and class); sets a timeout.
 */
function showToast(msg){
  const t=document.getElementById("toast");
  if(!t) return;
  clearTimeout(toastTimer);
  t.textContent=msg;
  t.classList.add("show");
  toastTimer=setTimeout(()=>t.classList.remove("show"),2500);
}

/**
 * refreshActiveTabFromMessage: Handles tab-change messages by resetting state and triggering a scan.
 * WHY IT EXISTS: When the user switches tabs or navigates to a new domain, the panel must reset its
 *   display state (open category, open cookie, counts) and perform a fresh scan. This function
 *   detects whether the tab or domain actually changed from the current values to avoid unnecessary resets.
 * HOW IT WORKS: Validates the message has tabId and URL, checks if the tab or domain changed from
 *   the current values, and if so resets lastCookieCount, openCategory, and openCookieKey. Then
 *   calls doScan() to fetch and display data for the new tab.
 * INPUT: msg (Object) — {tabId: number, url: string}.
 * OUTPUT: Resets globals; calls doScan.
 */
function refreshActiveTabFromMessage(msg={}){
  if (!Number.isInteger(msg.tabId) || !msg.url) return;
  const tabChanged = currentTabId !== msg.tabId;
  const domainChanged = (() => {
    try { return currentDomain !== new URL(msg.url).hostname; }
    catch { return false; }
  })();
  if (tabChanged || domainChanged) {
    lastCookieCount = 0;
    openCategory = "All";
    openCookieKey = null;
  }
  doScan(msg.tabId, msg.url);
}

// â”€â”€ Process â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * processRawCookies: Core data pipeline that transforms raw cookie arrays into enriched, categorized,
 *   scored, and displayed data. This is the heart of the extension's data flow.
 * WHY IT EXISTS: Raw cookies from the background script lack display metadata (origin, lifespan,
 *   classification method, etc.). This function enriches each cookie with computed fields, organizes
 *   them into categories, computes the privacy score, and updates or renders the UI accordingly.
 * HOW IT WORKS: Initializes empty category buckets, iterates raw cookies to build enriched items
 *   with: category (from background or "Unknown"), origin (first/third-party), formatted lifespan,
 *   stable dedup key, HTTP-only/Secure flags, classification method. Computes score using either
 *   background-provided score or client-side computeScore(). If the panel is already rendered,
 *   performs targeted DOM updates; otherwise does a full render. Shows toast on new cookie detection.
 * INPUT: rawCookies (Array) — raw cookie objects from background; bgScore (Object|null) — {score, scoreLabel}.
 * OUTPUT: Populates globals lastCategories, lastScore, lastEnriched; updates DOM.
 */
function processRawCookies(rawCookies, bgScore){
  const CATS=["Strict","Performance","Functionality","Advertising","Unknown"];
  const categories=Object.fromEntries(CATS.map(c=>[c,[]]));
  const enriched=[];
  rawCookies.forEach(cookie=>{
    const usedBg = !!cookie.cat;
    const result = { cat: cookie.cat || "Unknown", method: cookie.classMethod || "Unknown", desc: "", platform: "" };
    let cat=result.cat; if(!categories[cat]) cat="Unknown";
    const cookieDomain = normalizeHost(cookie?.domain || "");
    const displayDomain = cookieDomain || (cookie?.fromDocCookie ? currentDomain : "") || "unknown";
    if (!cookieDomain && !cookie?.fromDocCookie) {
      console.warn("[CC] cookie missing domain; showing unknown in UI", cookie);
    }
    const origin = cookie.origin
      || (cookieDomain
        ? getCookieOrigin(cookieDomain, currentDomain)
        : (cookie?.fromDocCookie ? "First-party" : "Third-party"));
    const lifespan=formatLifespan(cookie);
    const item = {
      cookie,
      cat,
      key:stableCookieKey(cookie),
      name:cookie.name,
      domain:displayDomain,
      path:cookie.path || "/",
      origin,
      lifespan,
      httpOnly:cookie.httpOnly,
      secure:cookie.secure,
      sameSite: cookie.sameSite === "No Restriction" ? "None" : (cookie.sameSite || "unspecified"),
      method:result.method,
      confidence:result.confidence,
      desc: result.desc || "",
      source: usedBg ? "BG" : "SP",
      keepReason: cookie.keepReason || cookie._keepReason || "",
      sessionLike: !!cookie.sessionLike,
    };
    categories[cat].push(item);
    enriched.push(item);
  });
  let sr;
  if (bgScore && Number.isInteger(bgScore.score)) {
    let tpCount = 0;
    const bd = {};
    for (const item of enriched) {
      const cat = item.cat || "Unknown";
      bd[cat] = (bd[cat] || 0) + 1;
      if (item.origin !== "First-party") tpCount++;
    }
    sr = {
      score: bgScore.score,
      label: bgScore.scoreLabel || "Good",
      breakdown: bd,
      total: enriched.length,
      tpPct: enriched.length ? Math.round(tpCount / enriched.length * 100) : 0,
    };
  } else {
    sr = computeScore(enriched);
  }
  lastCategories = categories;
  lastScore = sr;
  lastEnriched = enriched;
  if (panelRendered) {
    updateScoreRing(sr);
    updateSummary(enriched, sr);
    updateCategoryTabs(categories);
    debouncedUpdateTable(categories);
    const domainSpan = document.querySelector(".domain-bar span");
    if (domainSpan && currentDomain) domainSpan.textContent = currentDomain;
    // Chips are site-dependent like the domain bar: this branch skips the full
    // render() that builds them, so patch them here or they keep the previous
    // site's whitelist state after navigation.
    updateWhitelistChips();
  } else {
    render(categories,sr,currentDomain);
    panelRendered = true;
  }
  const total=rawCookies.length;
  if(total>lastCookieCount&&lastCookieCount>0) showToast(`+${total-lastCookieCount} new cookie${total-lastCookieCount>1?"s":""} detected`);
  lastCookieCount=total;
}

// â”€â”€ Scan â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * doScan: Entry point for scanning a tab's cookies and displaying results in the side panel.
 * WHY IT EXISTS: Every time the user navigates or switches tabs, the panel needs to fetch the latest
 *   cookie data from the background script and process it. This function coordinates that flow:
 *   validating the URL, updating global state, sending a message to the background, and feeding
 *   the response into processRawCookies().
 * HOW IT WORKS: Rejects non-http URLs (chrome://, about:) with a "not available" message. For valid
 *   URLs, sets currentTabId and currentDomain, increments _scanId to handle race conditions, then
 *   sends a GET_STATE message to the background. On response, updates the global purge feed and
 *   calls processRawCookies() with the returned cookies and score. Uses scan ID comparison to
 *   discard stale responses from superseded scans.
 * INPUT: tabId (number) — Chrome tab ID; url (string) — tab URL.
 * OUTPUT: Updates globals; calls processRawCookies() to update DOM.
 */
function doScan(tabId,url){
  if(!url||url.startsWith("chrome://")||url.startsWith("about:")){
    // Bind to this tab and drop the previous site's data, so a later
    // navigation in the SAME tab still matches currentTabId downstream.
    currentTabId = tabId;
    currentDomain = "";
    lastEnriched = [];
    lastCategories = null;
    lastScore = null;
    lastCookieCount = 0;
    document.getElementById("main").innerHTML=`<div class="scanning"><div class="scan-ring"></div><div class="scan-text">not available on this page</div></div>`;
    panelRendered = false;
    return;
  }
  currentTabId = tabId;
  try{currentDomain=new URL(url).hostname;}catch{return;}
  // Refresh chip state the moment the site changes — don't wait for the
  // GET_STATE response (a slow or failed response would otherwise leave the
  // previous site's whitelist state on screen).
  updateWhitelistChips();
  const thisScan = ++_scanId;
  // Panel-open refresh (M2): reading state to compare must not show stale
  // data. Request a fresh background scan alongside the state read; fresh
  // rows arrive via the normal COOKIES_UPDATED notification. Fire-and-forget.
  try{chrome.runtime.sendMessage({type:"REQUEST_SCAN",tabId,url},()=>{void chrome.runtime.lastError;});}catch{}
  chrome.runtime.sendMessage({type:"GET_STATE",tabId},resp=>{
    if(thisScan !== _scanId) return;
    if(chrome.runtime.lastError||!resp){processRawCookies([]);return;}
    globalPurgeFeed = resp.purgeFeed || [];
    processRawCookies(resp.cookies||[], { score: resp.score, scoreLabel: resp.scoreLabel });
  });
}

// â”€â”€ Banner button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// â”€â”€ Messages â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * chrome.runtime.onMessage listener: Central message handler for all background-to-sidepanel communication.
 * WHY IT EXISTS: The background script sends messages to the side panel for tab changes, cookie updates,
 *   vendor updates, and protection events. This listener dispatches each message type to the appropriate
 *   handler so the panel stays in sync with the extension's runtime state.
 * HANDLES:
 *   ACTIVE_TAB_CHANGED — Refreshes the panel when the user switches tabs or navigates. For navigation
 *     events (not tab activation), only acts if the tab is the current foreground tab.
 *   COOKIES_UPDATED — Processes new cookie data from the background, updates the display.
 *   VENDORS_UPDATED — Re-processes existing cookies with updated vendor resolution data.
 *   SESSION_LOCK_PURGED / RISK_BLOCKING_REMOVED — Shows toast notifications for automated actions.
 * INPUT: msg (Object) — message with .type field identifying the event.
 * OUTPUT: Dispatches to handler functions; modifies DOM via processRawCookies or showToast.
 */
chrome.runtime.onMessage.addListener(msg=>{
  if(msg.type==="ACTIVE_TAB_CHANGED"){
    if (msg.reason && msg.reason !== "tab_activated") {
      // navigation_complete fires for EVERY tab (including background tabs
      // reloaded by tracker blocking) — only honor it for the foreground tab.
      if (!Number.isInteger(msg.tabId) || !msg.url) return;
      const wantTab = msg.tabId, wantUrl = msg.url;
      chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
        if (tabs && tabs[0] && tabs[0].id === wantTab) {
          refreshActiveTabFromMessage({ tabId: wantTab, url: wantUrl });
        }
      });
      return;
    }
    refreshActiveTabFromMessage(msg);
    return;
  }
  if(msg.type==="COOKIES_UPDATED"||msg.type==="VENDORS_UPDATED"){
    if (msg.type === "COOKIES_UPDATED" && Array.isArray(msg.cookies)) {
      if (Number.isInteger(msg.tabId) && Number.isInteger(currentTabId) && msg.tabId !== currentTabId) return;
      if (Number.isInteger(msg.tabId)) currentTabId = msg.tabId;
      if (msg.url) {
        try { currentDomain = new URL(msg.url).hostname; } catch {}
      }
      if (Array.isArray(msg.mlDiag)) lastMlDiag = msg.mlDiag;
      processRawCookies(msg.cookies, { score: msg.score, scoreLabel: msg.scoreLabel });
      return;
    }
    if (msg.type === "VENDORS_UPDATED" && lastEnriched.length) {
      processRawCookies(lastEnriched.map(e => e.cookie), { score: lastScore?.score, scoreLabel: lastScore?.scoreLabel });
      return;
    }
    return;
  }
  if(msg.type==="SESSION_LOCK_PURGED"){
    showToast(`Session Guard removed ${msg.count} risky cookie${msg.count>1?"s":""}`);
  }
  if(msg.type==="RISK_BLOCKING_REMOVED"){
    showToast(`Risk blocking removed ${msg.count} high-risk cookie${msg.count>1?"s":""}`);
  }
});

/**
 * chrome.storage.onChanged listener: Keeps side panel state in sync when storage values change externally.
 * WHY IT EXISTS: Protection settings can be changed from the options page, popup, or background script.
 *   Without this listener, the side panel's in-memory state would drift out of sync with storage.
 *   It also re-renders the panel when the CC master toggle changes and refreshes the purge feed.
 * HANDLES:
 *   widgetEnabled — Syncs the widgetEnabled global.
 *   ccEnabled — Syncs ccEnabled and cascades off consent/widget if disabled; triggers full re-render.
 *   consentAnalysisEnabled — Syncs the consentAnalysisEnabled global.
 *   All PROTECTION_DEFAULTS keys — Updates protectionSettings object and refreshes settings panel UI.
 *   ccGlobalPurgeFeed — Updates the purge feed array and re-renders if data is loaded.
 * INPUT: changes (Object) — storage change records; area (string) — "local" for extension storage.
 * OUTPUT: Updates globals; may trigger re-render and updateSettingsPanel().
 */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.widgetEnabled) {
    widgetEnabled = changes.widgetEnabled.newValue !== false;
  }
  if (area === "local" && changes.ccEnabled) {
    ccEnabled = changes.ccEnabled.newValue !== false;
    if (!ccEnabled) {
      consentAnalysisEnabled = false;
      widgetEnabled = false;
    }
    render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
  }
  if (area === "local" && changes.consentAnalysisEnabled) {
    consentAnalysisEnabled = changes.consentAnalysisEnabled.newValue !== false;
  }
  if (area === "local") {
    let changed = false;
    let wlChanged = false;
    for (const key of Object.keys(PROTECTION_DEFAULTS)) {
      if (changes[key]) {
        protectionSettings[key] = changes[key].newValue;
        changed = true;
        if (key === "tbSiteWhitelist" || key === "sgSiteWhitelist") wlChanged = true;
      }
    }
    if (changed) updateSettingsPanel();
    // Whitelist changes alter chip active-state (main panel) and the settings
    // list contents. Chips can be patched in place; the settings view needs a
    // full re-render to rebuild its lists.
    if (wlChanged) {
      if (settingsViewOpen) {
        // Lists rebuild from scratch on re-render: preserve each list's
        // scroll position (jump to bottom when entries were added so the
        // new entry is visible, hold position when removed).
        const sc = {};
        document.querySelectorAll(".wl-list").forEach(ul => { sc[ul.id] = ul.scrollTop; });
        render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
        for (const key of ["tbSiteWhitelist", "sgSiteWhitelist"]) {
          const ch = changes[key];
          if (!ch) continue;
          const ul = document.getElementById(key === "tbSiteWhitelist" ? "wl-tb-list" : "wl-sg-list");
          if (!ul) continue;
          const grew = (ch.newValue || []).length > (ch.oldValue || []).length;
          ul.scrollTop = grew ? ul.scrollHeight : (sc[ul.id] || 0);
        }
      }
      else updateWhitelistChips();
    }
  }
  if (area === "local" && changes.ccGlobalPurgeFeed) {
    globalPurgeFeed = Array.isArray(changes.ccGlobalPurgeFeed.newValue) ? changes.ccGlobalPurgeFeed.newValue : [];
    if (lastCategories && lastScore) render(lastCategories, lastScore, currentDomain);
  }
});

// â”€â”€ Tab events â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
/**
 * chrome.tabs.onActivated listener: Triggers a scan when the user switches to a different browser tab.
 * WHY IT EXISTS: When the user activates a new tab, the side panel must immediately show that tab's
 *   cookie data. This listener resets the UI state and initiates a scan for the newly active tab.
 * HOW IT WORKS: Resets lastCookieCount, openCategory, and openCookieKey. Uses chrome.tabs.get() to
 *   retrieve the tab's URL and calls doScan() with the new tab ID and URL.
 * INPUT: info (Object) — {tabId: number} from Chrome.
 * OUTPUT: Resets globals; calls doScan.
 */
chrome.tabs.onActivated.addListener(info=>{
  lastCookieCount=0;openCategory="All";openCookieKey=null;
  chrome.tabs.get(info.tabId,tab=>{if(tab?.url){doScan(info.tabId,tab.url);}});
});

/**
 * chrome.tabs.onUpdated listener: Triggers a scan when the current tab finishes navigating.
 * WHY IT EXISTS: When a page finishes loading (status === "complete"), new cookies may have been set.
 *   This listener ensures the panel refreshes with the latest cookie data for the current tab.
 *   Only fires for the tab matching currentTabId to avoid scanning background tabs.
 * HOW IT WORKS: Checks that the navigation status is "complete" and the tabId matches currentTabId,
 *   then resets lastCookieCount and calls doScan() with the updated URL.
 * INPUT: tabId (number), changeInfo (Object — {status}), tab (Object — {url}).
 * OUTPUT: Resets lastCookieCount; calls doScan.
 */
chrome.tabs.onUpdated.addListener((tabId,changeInfo,tab)=>{
  if(changeInfo.status==="complete" && tabId===currentTabId){
    lastCookieCount=0;
    doScan(tabId,tab.url);
  }
});

/**
 * syncDebugButton: Synchronizes the debug panel toggle button's visual state with the debugOpen flag.
 * WHY IT EXISTS: The debug panel can be opened/closed via the footer button or programmatically on
 *   startup (from stored state). This function ensures the button's CSS class and text label match
 *   the actual debug panel state.
 * HOW IT WORKS: Toggles the "on" class and sets the button text to "Cookie List *" when open,
 *   or "Cookie List" when closed.
 * INPUT: None (reads from global debugOpen).
 * OUTPUT: Modifies DOM (button class and text).
 */
function syncDebugButton() {
  const btn = document.getElementById("debug-toggle-btn");
  if (btn) {
    btn.classList.toggle("on", debugOpen);
    btn.textContent = debugOpen ? "Cookie List *" : "Cookie List";
  }
}

/**
 * buildCookieListText: Generates a pipe-delimited text export of all enriched cookies for clipboard copy.
 * WHY IT EXISTS: Users and developers need to export cookie data for analysis, debugging, or reporting.
 *   This function formats the enriched cookie list as a readable text table that can be copied to
 *   the clipboard via the debug panel's copy button.
 * HOW IT WORKS: Builds a header row with all field names, then maps each enriched cookie to a pipe-
 *   separated row with: index, name, domain, path, origin, category, method, source, keep reason,
 *   description, httpOnly, secure, sameSite, session/persistent, and expiry date.
 * INPUT: None (reads from globals lastEnriched, currentDomain).
 * OUTPUT: string — pipe-delimited text table.
 */
function buildCookieListText() {
  if (!lastEnriched || !lastEnriched.length) return "No cookies detected for this site.";
  const header = "# | Name | Domain | Path | Origin | Category | Method | Source | KeepReason | Description | HttpOnly | Secure | SameSite | Session | Expiry";
  const rows = lastEnriched.map((item, i) => {
    const expiry = item.cookie.session ? "session"
      : item.cookie.expirationDate ? new Date(item.cookie.expirationDate * 1000).toISOString().slice(0,10)
      : "-";
    return [
      i + 1,
      item.name || "-",
      item.domain || "-",
      item.path || "/",
      item.origin || "-",
      item.cat || "-",
      item.method || "-",
      item.source || "-",
      item.keepReason || "-",
      (item.desc || "-").replace(/\|/g, "/"),
      item.httpOnly ? "true" : "false",
      item.secure ? "true" : "false",
      item.sameSite || "unspecified",
      item.cookie.session ? "session" : "persistent",
      expiry
    ].join(" | ");
  });
  return "=== Cookie Crumbs Export ===\nSite: " + (currentDomain || "unknown") + "\nTotal: " + lastEnriched.length + " cookies\n\n" + header + "\n" + rows.join("\n");
}

/**
 * renderDiagPanel: Renders the debug panel content (Cookie List export).
 * WHY IT EXISTS: The debug panel shows the copy-paste cookie export.
 *   ML Diag, Churn and Decisions tabs were removed here to make room for
 *   replacement diagnostics; they plug into this dispatcher.
 * HOW IT WORKS: Renders buildCookieListText() output in a <pre> block.
 *   The mode parameter is accepted for caller compatibility and ignored.
 * INPUT: mode (string) - ignored.
 * OUTPUT: Replaces #debug-panel innerHTML.
 */
function renderDiagPanel(mode) {
  const dbgPanel = document.getElementById("debug-panel");
  const dbgBar = document.getElementById("debug-bar");
  if (!dbgPanel || !dbgBar) return;
  if (typeof srRenderDiagnostics === "function") { srRenderDiagnostics(dbgPanel, dbgBar, mode); return; }
  void mode;
  const text = buildCookieListText();
  dbgPanel.innerHTML = '<pre class="cookie-export">' + escapeHtml(text) + '</pre>';
}

document.addEventListener("click",e=>{
  if(e.target.closest("#settings-btn")){
    settingsViewOpen = true;
    render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
    return;
  }
  if(e.target.closest("#settings-back")){
    settingsViewOpen = false;
    render(lastCategories || {}, lastScore || { score: 0, label: "Excellent", total: 0, tpPct: 0, breakdown: {} }, currentDomain || "");
    return;
  }
  const toggle = e.target.closest("[data-setting]");
  if(toggle){
    const key = toggle.getAttribute("data-setting");
    setProtectionSetting(key, !(protectionSettings[key] !== false)).catch(()=>{});
  }
  // Whitelist chip (main panel) — toggles the CURRENT site on that engine's list.
  const wlChip = e.target.closest("[data-whitelist]");
  if(wlChip){
    toggleSiteWhitelist(wlChip.getAttribute("data-whitelist")).catch(()=>{});
    return;
  }
  // Whitelist Add button (settings page).
  const wlAddBtn = e.target.closest(".wl-add-btn");
  if(wlAddBtn){
    const engine = wlAddBtn.getAttribute("data-engine");
    const input = document.getElementById(`wl-${engine}-input`);
    if(input){ addWhitelistEntry(engine, input.value).catch(()=>{}); input.value = ""; }
    return;
  }
  // Whitelist per-entry remove (settings page).
  const wlRemoveBtn = e.target.closest(".wl-remove");
  if(wlRemoveBtn){
    const engine = wlRemoveBtn.getAttribute("data-engine");
    const key = whitelistKeyFor(engine);
    const list = Array.isArray(protectionSettings[key]) ? protectionSettings[key] : [];
    const entry = list[Number(wlRemoveBtn.getAttribute("data-index"))];
    if(entry) removeWhitelistEntry(engine, entry).catch(()=>{});
    return;
  }
  if(e.target.closest("#debug-toggle-btn")){
    debugOpen = !debugOpen;
    syncDebugButton();
    const dbgBar = document.getElementById("debug-bar");
    const dbgPanel = document.getElementById("debug-panel");
    if (dbgBar) dbgBar.classList.toggle("open", debugOpen);
    if (dbgPanel) {
      dbgPanel.classList.toggle("open", debugOpen);
      if (debugOpen) {
        diagTab = "cookie";
        renderDiagPanel(diagTab);
      }
    }
  }
  if(e.target.closest("#debug-copy-btn")){
    const text = buildCookieListText();
    navigator.clipboard.writeText(text).then(() => showToast("Copied")).catch(() => showToast("Copy failed — check permissions"));
  }
  const activeInfo = e.target.closest("[data-active-info]");
  if(activeInfo){
    const popover = document.getElementById("help-popover");
    if(!popover) return;
    const key = "trackingAlwaysOn";
    const isOpen = popover.classList.contains("open") && popover.dataset.helpKey === key;
    if(isOpen) { popover.classList.remove("open"); return; }
    const row = activeInfo.closest(".protection-row");
    const btnRect = activeInfo.getBoundingClientRect();
    if(row){
      const rowRect = row.getBoundingClientRect();
      popover.style.setProperty("--arrow-x", (btnRect.left + btnRect.width / 2 - rowRect.left) + "px");
    }
    popover.dataset.helpKey = key;
    popover.textContent = PROTECTION_HELP[key] || "";
    popover.classList.add("open");
    return;
  }
  const helpBtn = e.target.closest(".help-btn");
  if(helpBtn){
    const key = helpBtn.getAttribute("data-help");
    const popover = document.getElementById("help-popover");
    if(!popover) return;
    const isOpen = popover.classList.contains("open") && popover.dataset.helpKey === key;
    if(isOpen) { popover.classList.remove("open"); return; }
    const row = helpBtn.closest(".protection-row");
    const rowRect = row.getBoundingClientRect();
    const btnRect = helpBtn.getBoundingClientRect();
    const arrowX = btnRect.left + btnRect.width / 2 - rowRect.left;
    popover.style.setProperty("--arrow-x", arrowX + "px");
    popover.dataset.helpKey = key;
    popover.innerHTML = PROTECTION_HELP[key] || "";
    popover.classList.add("open");
    return;
  }
  const popover = document.getElementById("help-popover");
  if(popover) popover.classList.remove("open");
});

// Enter key submits a whitelist entry from the settings-page inputs.
document.addEventListener("keydown",e=>{
  if(e.key !== "Enter") return;
  const inp = e.target.closest(".wl-input");
  if(!inp) return;
  e.preventDefault();
  const engine = inp.getAttribute("data-engine");
  addWhitelistEntry(engine, inp.value).catch(()=>{});
  inp.value = "";
});

// â”€â”€ Init â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
(async ()=>{
  await loadProtectionSettings();
  await loadData();
  updateSettingsPanel();
  chrome.tabs.query({active:true,currentWindow:true},tabs=>{
    if(tabs[0]){doScan(tabs[0].id,tabs[0].url);}
  });

  chrome.storage.local.get("ccDebugOpen", data => {
    if (data.ccDebugOpen) {
      debugOpen = true;
      syncDebugButton();
      const dbgBar = document.getElementById("debug-bar");
      const dbgPanel = document.getElementById("debug-panel");
      if (dbgBar) dbgBar.classList.add("open");
      if (dbgPanel) {
        dbgPanel.classList.add("open");
        diagTab = "cookie";
        renderDiagPanel(diagTab);
      }
    }
  });
})();

