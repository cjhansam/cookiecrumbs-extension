// ============================================================
// Cookie Crumbs v5.16 — site_record.js
// Five-tab diagnostics site recorder (TB-OFF / TB-ON / SG / SG-History
// / Cookie List / Logout Diag) + site cross-match master tables.
//
// WHY IT EXISTS: The 200-site evaluation captures frozen table inputs
//   per site visit: jar totals, per-class and per-method mixes, privacy
//   score (TB tabs); session counts (SG tab); purge counts + trigger +
//   considered (History tab, imported from the existing Session Guard
//   history feed). Later, records cross-match on site name into the
//   panel-facing master tables. No click = no write: every capture is a
//   human "ready" judgment; the recorder never auto-snapshots.
//
// SAFETY RULES (locked):
//   - Condition gating: TB-OFF records only while blocking is OFF (and
//     mirror for ON); History imports only with a matching feed event,
//     except the proven-empty derived zero.
//   - No-history rule: snapshot session 0 + no event -> derived-zero row
//     labeled as such; session > 0 + no event -> re-run list, never a 0.
//   - Overwrite: re-recording a site replaces its entry (latest wins).
//   - Counts only: cookie names/values are never read, stored, or copied.
//   - Removed = OFF total minus ON total, clamped at zero (table time).
//
// WIRING: classic script loaded AFTER sidepanel.js. Owns its tab state
//   (SR.tab) and binds one delegated document listener (installed once).
//   sidepanel.js delegates renderDiagPanel() here and hosts the master
//   tables section; both hooks are typeof-guarded. Pure logic (tallies,
//   gating, pairing, TSV) is chrome-free and Node-testable.
// ============================================================

const SR_CATS = ["Strict", "Performance", "Functionality", "Advertising", "Unknown"];
const SR_CAT_ABBR = { Strict: "Str", Performance: "Per", Functionality: "Fun", Advertising: "Adv", Unknown: "Unk" };
const SR_METHODS = ["DB", "DM", "BL", "ML", "UN"];
const SR_TASKS = ["render", "login", "video", "cart", "banner"];
const SR_STORE_KEY = "ccSiteRecords";
const SR_TABS = [
  { id: "tboff", label: "TB-OFF" },
  { id: "tbon", label: "TB-ON" },
  { id: "sg", label: "SG" },
  { id: "hist", label: "SG-History" },
  { id: "cookie", label: "Cookie List" },
  { id: "logout", label: "Logout Diag" },
  { id: "scan", label: "Scan Diag" },
];
const SR_CYCLE = { "\u2013": "\u2705", "\u2705": "\u274C", "\u274C": "\u2013" };
const SR_LOGIN_CYCLE = { "\u2013": "yes", "yes": "no", "no": "\u2013" };
const SR_TRIGGER_LABEL = { site_exit: "left site", tab_close: "tab closed", browser_close: "browser closed" };

// ── Pure helpers (no chrome, no DOM) ─────────────────────────

function srFoldCat(cat) {
  return SR_CATS.indexOf(cat) >= 0 ? cat : "Unknown";
}

function srFoldMethod(m) {
  if (m === "DB" || m === "DB-wild") return "DB";
  if (m === "Domain") return "DM";
  if (m === "Blocklist") return "BL";
  if (m === "ML") return "ML";
  return "UN";
}

function srEmptyCounts(keys) {
  const o = {};
  keys.forEach(k => { o[k] = 0; });
  return o;
}

function srSiteOf(hostname) {
  try {
    if (typeof getRegistrableDomain === "function") return getRegistrableDomain(hostname) || "";
  } catch (_) {}
  try {
    return String(hostname || "").trim().toLowerCase().replace(/^\./, "").replace(/^www\./, "");
  } catch (_) { return ""; }
}

// Tally a jar snapshot into counts. Names/values never read.
function srTally(enriched, score) {
  const cls = srEmptyCounts(SR_CATS);
  const mth = srEmptyCounts(SR_METHODS);
  let total = 0, session = 0;
  (enriched || []).forEach(e => {
    total++;
    cls[srFoldCat(e && e.cat)]++;
    mth[srFoldMethod(e && e.method)]++;
    // "session" = S1-candidacy count (session-shaped isSessionLike PLUS
    // importance-admitted protectedAuth, which carries the flag via the forced
    // E1 analysis return), NOT Chrome's expiry flag. It answers "what SG would
    // evaluate at exit," matching the purge-feed sessionLikeCount definition.
    // Never-analyzed cookies carry no flag and read as 0.
    try { if (e && (e.sessionLike === true || (e.cookie && e.cookie.sessionLike === true))) session++; } catch (_) {}
  });
  let sc = null;
  try { sc = (score && typeof score.score === "number") ? score.score : null; } catch (_) {}
  return { total, cls, mth, score: sc, session };
}

// Gating: is this tab's Record clickable right now?
// blockingOn: true/false/null(unknown). Returns {ok, why}.
function srGate(tab, blockingOn, site, feed) {
  if (!site) return { ok: false, why: "no site in panel" };
  if (tab === "tboff") {
    if (blockingOn === true) return { ok: false, why: "blocking is ON — flip it OFF first" };
    return { ok: true, why: "" };
  }
  if (tab === "tbon") {
    if (blockingOn === false) return { ok: false, why: "blocking is OFF — flip it ON first" };
    return { ok: true, why: "" };
  }
  if (tab === "sg") return { ok: true, why: "" };
  // Logout Diag records in any mode (logout can happen with blocking OFF);
  // only a site in the panel is required.
  if (tab === "logout") {
    if (!site) return { ok: false, why: "no site in panel" };
    return { ok: true, why: "" };
  }
  // Scan Diag is a read-only view of Tracker Blocking decision receipts —
  // no toggle dependency and no recording; only a site is required.
  if (tab === "scan") {
    if (!site) return { ok: false, why: "no site in panel" };
    return { ok: true, why: "" };
  }
  if (tab === "hist") {
    if (srPickHistoryEvent(feed, site)) return { ok: true, why: "" };
    return { ok: false, why: "no history event for this site yet" };
  }
  return { ok: false, why: "unknown tab" };
}

// Latest purge-history event for a site: exact siteKey, then
// registrable-equal fallback. Counts only — cookies[] never touched.
function srPickHistoryEvent(feed, site) {
  const list = (feed || []).filter(e => e && e.siteKey);
  for (const e of list) {
    try { if (String(e.siteKey).toLowerCase() === site) return e; } catch (_) {}
  }
  for (const e of list) {
    try { if (srSiteOf(e.siteKey) === site) return e; } catch (_) {}
  }
  return null;
}

// History record resolution: imported event | derived zero (snapshot
// proves empty) | refuse (evidence lost -> re-run, never a zero).
// The imported sessionLike is the merged S1-candidacy count (session-shaped
// plus importance-admitted); the event's sessionAuthCount field (when present)
// decomposes the admitted-only part for audit. Whitelist-skipped events carry
// null for both, exactly like before.
function srResolveHistory(site, sgEntry, event) {
  if (event) {
    return {
      entry: {
        site,
        removed: Number(event.removedCount || 0),
        trigger: event.trigger || "?",
        considered: Number(event.consideredCount || 0),
        sessionLike: (event && event.sessionLikeCount !== undefined && event.sessionLikeCount !== null)
          ? Number(event.sessionLikeCount)
          : null,
        derived: false,
      },
      refused: null,
    };
  }
  const sess = (sgEntry && typeof sgEntry.session === "number") ? sgEntry.session : null;
  if (sess === 0) {
    return {
      entry: { site, removed: 0, trigger: "n/a — empty jar", considered: 0, derived: true },
      refused: null,
    };
  }
  return {
    entry: null,
    refused: sess === null
      ? "record the SG tab first, then import history"
      : "no history event but session cookies existed — revisit the site",
  };
}

// Table build: pair latest OFF+ON per site; removed = OFF-ON clamped.
function srBuildBlocking(off, on, manual) {
  const m = manual || {};
  const removed = Math.max(0, (off.total || 0) - (on.total || 0));
  const d = (typeof off.score === "number" && typeof on.score === "number")
    ? (on.score - off.score) : null;
  return {
    site: off.site, off, on, removed, scoreDelta: d,
    tasks: m.tasks || { render: "\u2013", login: "\u2013", video: "\u2013", cart: "\u2013", banner: "\u2013" },
    note: m.note || "",
  };
}

function srMixStr(counts, abbr) {
  return Object.keys(abbr).map(k => (abbr[k] + " " + (counts[k] || 0))).join(" \u00B7 ");
}

// Shared display string: "{class mix} + {method mix}". One builder feeds
// both the tab entries list and the Copy TSV column, so screen and Sheet
// can never disagree.
function srMixDisplay(cls, mth) {
  return srMixStr(cls || {}, SR_CAT_ABBR) + " + " + srMixStr(mth || {}, srMethodAbbr());
}

// Mirror text: byte-identical to what the entries list shows, as plain
// text. Copy output uses these builders, so Docs receives exactly what
// the panel displayed (line breaks included, no markup).
function srMirrorTb(site, r) {
  const sc = (r.score === null || r.score === undefined) ? "-" : r.score;
  return site + " " + (r.total || 0) + " cookies, score " + sc + "\n" + srMixDisplay(r.cls, r.mth);
}

function srMirrorSg(site, r) {
  return site + " " + (r.total || 0) + " cookies, " + (r.session || 0) + " session";
}

function srMirrorHist(site, r) {
  return site + " " + (r.removed || 0) + " removed [" + (SR_TRIGGER_LABEL[r.trigger] || r.trigger || "?") + "]" + (r.derived ? " (derived)" : "") + srSessionLikeSuffix(r);
}

// Shared session-like suffix for history display: one builder feeds both the
// entries list and the mirror text, so screen and copy can never disagree.
// Unknown (legacy / derived-zero / skipped events carry no count) contributes
// nothing — unknown is never rendered as a zero.
function srSessionLikeSuffix(r) {
  return (r && r.sessionLike !== null && r.sessionLike !== undefined) ? ", " + r.sessionLike + " session-like" : "";
}

// Logout-diag one-line summary for the entries list: totals only.
function srLogoutSummary(b) {
  try {
    const k = ((b && b.kills) || []).reduce((s, g) => s + (Number(g.count) || 0), 0);
    const p = ((b && b.purges) || []).length;
    const n = (b && b.net) || {};
    const dm = (n.dnrMatching === null || n.dnrMatching === undefined) ? "?" : n.dnrMatching;
    const dt = (n.dnrTotal === null || n.dnrTotal === undefined) ? "?" : n.dnrTotal;
    return "kills " + k + " \u00B7 purges " + p + " \u00B7 DNR " + dm + "/" + dt;
  } catch (_) { return "kills ? \u00B7 purges ?"; }
}

// Logout-diag mirror text: byte-identical to the entries-list expansion,
// as plain text for Docs. Bundle holds tallies + reason codes only — no
// cookie names/values ever stored or copied.
function srMirrorLogout(site, r) {
  try {
    const b = (r && r.bundle) || {};
    let ts = "";
    try { ts = " @" + new Date(Number(r.t) || 0).toLocaleTimeString(); } catch (_) {}
    const tg = b.toggles || {};
    const fl = b.flags || null;
    const head = site + ts + " (blocking " + (tg.tb ? "ON" : "OFF") + ", guard " + (tg.sg ? "ON" : "OFF")
      + (fl ? ", authMode " + (fl.authMode ? "yes" : "no") : "") + ")";
    const kills = (b.kills || []).map(g =>
      (g.verdict || "?") + "|" + (g.reason || "?") + "|" + (g.cat || "?") + "|" + (g.origin || "?") + "|" + (g.trigger || "?")
      + " \u00D7" + (g.count || 0) + (g.jsSet ? " (js " + g.jsSet + ")" : "")).join("; ");
    const survived = (b.survived || []).map(g =>
      (g.reason || "?") + "|" + (g.cat || "?") + " \u00D7" + (g.count || 0)).join("; ");
    const c = b.churn || {};
    const causes = Object.keys(c.causeTally || {}).sort().map(k => k + " \u00D7" + c.causeTally[k]).join(", ");
    const churn = (c.removals || 0) + " removed, " + (c.readds || 0) + " re-added, " + (c.rotations || 0)
      + " rotations, " + (c.multiRemoved || 0) + " removed 2+\u00D7" + (causes ? " [" + causes + "]" : "");
    const purges = (b.purges || []).map(p => {
      let pt = "";
      try { if (p.t) pt = " @" + new Date(Number(p.t)).toLocaleTimeString(); } catch (_) {}
      return (SR_TRIGGER_LABEL[p.trigger] || p.trigger || "?") + " " + (p.considered || 0) + "\u2192" + (p.removed || 0)
        + pt + " (" + (p.status || "?") + ")";
    }).join("; ");
    const n = b.net || {};
    const dm = (n.dnrMatching === null || n.dnrMatching === undefined) ? "?" : n.dnrMatching;
    const dt = (n.dnrTotal === null || n.dnrTotal === undefined) ? "?" : n.dnrTotal;
    let tel = "";
    try { if (n.latestRemoval) tel = ", latest @" + new Date(Number(n.latestRemoval)).toLocaleTimeString(); } catch (_) {}
    const net = "DNR " + dm + "/" + dt + " matching, sticky " + (n.sticky || 0)
      + ", suppressed " + (n.suppressedEntries || 0) + " entries (" + (n.suppressedRemovals || 0) + " removals)"
      + ", removed 3+\u00D7: " + (n.freq3plus || 0) + " entries" + tel;
    return head + "\nkills: " + (kills || "none")
      + "\nsurvived: " + (survived || "none")
      + "\nchurn: " + churn
      + "\npurges: " + (purges || "none")
      + "\nnet: " + net;
  } catch (_) { return site + " (diag failed)"; }
}

function srMirrorTab(tab, rows) {
  const sites = Object.keys(rows || {}).sort();
  return sites.map(site => {
    const r = rows[site];
    if (tab === "sg") return srMirrorSg(site, r);
    if (tab === "hist") return srMirrorHist(site, r);
    if (tab === "logout") return srMirrorLogout(site, r);
    return srMirrorTb(site, r);
  }).join("\n\n");
}

function srTsvEsc(v) {
  const s = (v === null || v === undefined) ? "" : String(v);
  return (/[\t\n"]/.test(s)) ? ('"' + s.replace(/"/g, '""') + '"') : s;
}

function srTsvLine(cells) {
  return cells.map(srTsvEsc).join("\t");
}

// NOTE (dormant): TSV builders below are unused by Copy (which mirrors the
// panel text for Docs). Kept for the later spreadsheet-conversion phase.
function srTbTsv(rows) {
  const head = ["site", "total", "str", "per", "fun", "adv", "unk", "db", "dm", "bl", "ml", "un", "score", "mix"];
  const lines = [srTsvLine(head)];
  Object.keys(rows || {}).sort().forEach(site => {
    const r = rows[site] || {};
    const c = r.cls || {}, m = r.mth || {};
    lines.push(srTsvLine([site, r.total, c.Strict, c.Performance, c.Functionality, c.Advertising, c.Unknown,
      m.DB, m.DM, m.BL, m.ML, m.UN, (r.score === null || r.score === undefined) ? "" : r.score,
      srMixDisplay(c, m)]));
  });
  return lines.join("\n");
}

function srSgTsv(rows) {
  const lines = [srTsvLine(["site", "total", "session"])];
  Object.keys(rows || {}).sort().forEach(site => {
    const r = rows[site] || {};
    lines.push(srTsvLine([site, r.total, r.session]));
  });
  return lines.join("\n");
}

function srHistTsv(rows) {
  const lines = [srTsvLine(["site", "removed", "trigger", "considered", "sessionLike", "derived"])]; 
  Object.keys(rows || {}).sort().forEach(site => {
    const r = rows[site] || {};
    lines.push(srTsvLine([site, r.removed, r.trigger, r.considered, (r.sessionLike !== null && r.sessionLike !== undefined) ? r.sessionLike : "", r.derived ? "derived-zero" : "imported"]));
  });
  return lines.join("\n");
}

function srMasterBlockingTsv(tableRows) {
  const head = ["site", "off", "on", "removed", "score_off", "score_on", "delta",
    "render", "login", "video", "cart", "banner", "note"];
  const lines = [srTsvLine(head)];
  (tableRows || []).forEach(r => {
    const t = r.tasks || {};
    lines.push(srTsvLine([r.site, r.off.total, r.on.total, r.removed,
      (r.off.score === null || r.off.score === undefined) ? "" : r.off.score,
      (r.on.score === null || r.on.score === undefined) ? "" : r.on.score,
      (r.scoreDelta === null || r.scoreDelta === undefined) ? "" : r.scoreDelta,
      t.render || "\u2013", t.login || "\u2013", t.video || "\u2013", t.cart || "\u2013", t.banner || "\u2013",
      r.note || ""]));
  });
  return lines.join("\n");
}

function srMasterGuardTsv(tableRows) {
  const head = ["site", "trigger", "logged_in", "at_exit", "purged", "preserved", "return_ok", "note"];
  const lines = [srTsvLine(head)];
  (tableRows || []).forEach(r => {
    lines.push(srTsvLine([r.site, r.trigger, r.loggedIn, r.atExit, r.purged, r.preserved,
      r.returnOk || "\u2013", r.note || ""]));
  });
  return lines.join("\n");
}

// ── Store (chrome-guarded; memory cache for sync render) ────

const SR = {
  tab: "cookie",
  off: {}, on: {}, sg: {}, hist: {}, logout: {},
  tables: { blocking: {}, guard: {} },
  loaded: false, open: false, bound: false,
};

function srSave(cb) {
  try {
    chrome.storage.local.set({ [SR_STORE_KEY]: {
      off: SR.off, on: SR.on, sg: SR.sg, hist: SR.hist, logout: SR.logout, tables: SR.tables,
    } }, () => { if (cb) cb(); });
  } catch (_) { if (cb) cb(); }
}

function srLoad(cb) {
  try {
    chrome.storage.local.get(SR_STORE_KEY, data => {
      try {
        const s = (data && data[SR_STORE_KEY]) || {};
        if (s.off && typeof s.off === "object") SR.off = s.off;
        if (s.on && typeof s.on === "object") SR.on = s.on;
        if (s.sg && typeof s.sg === "object") SR.sg = s.sg;
        if (s.hist && typeof s.hist === "object") SR.hist = s.hist;
        if (s.logout && typeof s.logout === "object") SR.logout = s.logout;
        if (s.tables && typeof s.tables === "object") {
          if (s.tables.blocking) SR.tables.blocking = s.tables.blocking;
          if (s.tables.guard) SR.tables.guard = s.tables.guard;
        }
      } catch (_) {}
      SR.loaded = true;
      if (cb) cb();
    });
  } catch (_) { if (cb) cb(); }
}

// ── Panel reads (guarded globals) ────────────────────────────

function srPanelSite() {
  try {
    if (typeof currentDomain === "string") return srSiteOf(currentDomain);
  } catch (_) {}
  return "";
}

function srPanelBlockingOn() {
  try {
    if (typeof protectionSettings === "object" && protectionSettings)
      return protectionSettings.riskBlockingEnabled !== false;
  } catch (_) {}
  return null;
}

function srPanelTally() {
  try {
    const e = (typeof lastEnriched !== "undefined") ? lastEnriched : [];
    const s = (typeof lastScore !== "undefined") ? lastScore : null;
    return srTally(e, s);
  } catch (_) { return srTally([], null); }
}

function srFeed() {
  try {
    if (typeof globalPurgeFeed !== "undefined" && Array.isArray(globalPurgeFeed)) return globalPurgeFeed;
  } catch (_) {}
  return [];
}

function srToast(msg) {
  try {
    if (typeof showToast === "function") showToast(msg);
  } catch (_) {}
}

function srEsc(s) {
  try {
    if (typeof escapeHtml === "function") return escapeHtml(s);
  } catch (_) {}
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

// ── Record actions ───────────────────────────────────────────

function srRecord(tab) {
  const site = srPanelSite();
  const blockingOn = srPanelBlockingOn();
  const gate = srGate(tab, blockingOn, site, srFeed());
  if (!gate.ok) { srToast("Record refused: " + gate.why); return; }
  if (tab === "tboff" || tab === "tbon") {
    const t = srPanelTally();
    const rec = { site, total: t.total, cls: t.cls, mth: t.mth, score: t.score, blockingOn: blockingOn !== false };
    if (tab === "tboff") SR.off[site] = rec; else SR.on[site] = rec;
    srSave(() => { srToast("Recorded " + (tab === "tboff" ? "TB-OFF" : "TB-ON") + " for " + site + " (" + t.total + " cookies)"); srRefreshPanel(); });
    return;
  }
  if (tab === "sg") {
    const t = srPanelTally();
    SR.sg[site] = { site, total: t.total, session: t.session };
    srSave(() => { srToast("Recorded SG for " + site + " (" + t.session + " session cookies)"); srRefreshPanel(); });
    return;
  }
  if (tab === "hist") {
    const event = srPickHistoryEvent(srFeed(), site);
    const res = srResolveHistory(site, SR.sg[site] || null, event);
    if (!res.entry) { srToast("Record refused: " + res.refused); return; }
    SR.hist[site] = res.entry;
    srSave(() => {
      srToast(res.entry.derived
        ? "Recorded derived zero for " + site + " (jar empty at leave)"
        : "Imported history for " + site + ": " + res.entry.removed + " removed");
      srRefreshPanel();
    });
    return;
  }
  if (tab === "logout") {
    // Async bundle fetch from the background logout diagnostic. Manual
    // record only — no auto-snapshots, same rule as every other tab.
    try {
      if (typeof chrome === "undefined" || !chrome || !chrome.runtime || !chrome.runtime.sendMessage) { srToast("Diag unavailable"); return; }
      srToast("Capturing logout diag for " + site + "…");
      chrome.runtime.sendMessage({ type: "GET_LOGOUT_DIAG", site }, resp => {
        try {
          if (!resp || resp.error || !Array.isArray(resp.kills)) { srToast("Diag failed"); return; }
          const bundle = resp;
          SR.logout[site] = { site, t: bundle.t || Date.now(), bundle };
          srSave(() => { srToast("Recorded logout diag for " + site); srRefreshPanel(); });
        } catch (_) { srToast("Diag failed"); }
      });
    } catch (_) { srToast("Diag failed"); }
    return;
  }
}

function srCopyTab(tab) {
  let text = "", label = tab;
  try {
    if (tab === "scan") {
      if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) { srToast("Storage unavailable"); return; }
      chrome.storage.local.get("ccDecisionReceipts", data => {
        try {
          const site = srPanelSite();
          const rows = srTrackerDiagRows((data && data.ccDecisionReceipts) || [], site);
          if (!rows.length) { srToast("No Tracking Protection decisions recorded for this site yet"); return; }
          const out = "Site: " + (site || "unknown") + "\n" + srScanDiagText(rows, site);
          if (!out) { srToast("Nothing to copy yet"); return; }
          navigator.clipboard.writeText(out).then(() => srToast("Copied tracking protection diag (" + rows.length + " decisions)")).catch(() => srToast("Copy failed — check permissions"));
        } catch (_) { srToast("Copy failed"); }
      });
      return;
    }
    if (tab === "tboff") text = srMirrorTab(tab, SR.off);
    else if (tab === "tbon") text = srMirrorTab(tab, SR.on);
    else if (tab === "sg") text = srMirrorTab(tab, SR.sg);
    else if (tab === "hist") text = srMirrorTab(tab, SR.hist);
    else if (tab === "logout") text = srMirrorTab(tab, SR.logout);
    else if (tab === "cookie") {
      if (typeof buildCookieListText === "function") text = buildCookieListText();
    }
    if (!text) { srToast("Nothing to copy yet"); return; }
    const n = (tab === "cookie") ? text.split("\n").length : Object.keys(tab === "tboff" ? SR.off : tab === "tbon" ? SR.on : tab === "sg" ? SR.sg : tab === "logout" ? SR.logout : SR.hist).length;
    navigator.clipboard.writeText(text).then(() => srToast("Copied " + label + " (" + n + " sites)")).catch(() => srToast("Copy failed — check permissions"));
  } catch (_) { srToast("Copy failed"); }
}

function srDeleteEntry(tab, site) {
  if (tab === "tboff") delete SR.off[site];
  else if (tab === "tbon") delete SR.on[site];
  else if (tab === "sg") delete SR.sg[site];
  else if (tab === "hist") delete SR.hist[site];
  else if (tab === "logout") delete SR.logout[site];
  else return;
  srSave(() => { srRefreshPanel(); });
}

// ── Table build (site cross-match) ───────────────────────────

function srBlockingTable() {
  const sites = {};
  Object.keys(SR.off).forEach(s => { sites[s] = 1; });
  Object.keys(SR.on).forEach(s => { sites[s] = 1; });
  return Object.keys(sites).sort().map(site => {
    const off = SR.off[site], on = SR.on[site];
    if (!off || !on) return null;
    const manual = (SR.tables.blocking && SR.tables.blocking[site]) || {};
    return srBuildBlocking(off, on, manual);
  }).filter(Boolean);
}

function srGuardTable() {
  const rows = [], rerun = [];
  Object.keys(SR.sg).sort().forEach(site => {
    const s = SR.sg[site] || {};
    const h = SR.hist[site];
    const manual = (SR.tables.guard && SR.tables.guard[site]) || {};
    if (!h) {
      if ((s.session || 0) > 0) rerun.push({ site, cause: "no history event — revisit the site" });
      return;
    }
    // preserved = session-like set at exit minus purged. Prefer the event's
    // exact session-like count (same run, same rules); fall back to the SG
    // snapshot, then to the event's considered count only for legacy rows
    // with neither (considered counts weak purge candidates, a subset of the
    // session-like set).
    const base = (h && h.sessionLike !== null && h.sessionLike !== undefined) ? h.sessionLike
      : (s && typeof s.session === "number") ? s.session : (h.considered || 0);
    const preserved = Math.max(0, base - (h.removed || 0));
    rows.push({
      site, trigger: h.trigger || "?", loggedIn: manual.loggedIn || "\u2013",
      atExit: s.session || 0, purged: h.removed || 0, preserved,
      returnOk: manual.returnOk || "\u2013", note: manual.note || "",
      derived: !!h.derived,
    });
  });
  return { rows, rerun };
}

// ── Rendering ────────────────────────────────────────────────

function srMethodAbbr() {
  const a = {};
  SR_METHODS.forEach(k => { a[k] = k; });
  return a;
}

function srEntriesHtml(tab, rows, fmt) {
  const sites = Object.keys(rows || {}).sort();
  if (!sites.length) return '<div class="tr-empty">No records yet — press Record on a site.</div>';
  return sites.map(site => {
    const r = rows[site];
    return '<div class="tr-strip-row"><span><b>' + srEsc(site) + "</b> " + fmt(r) + "</span>"
      + ' <button class="tr-mini" data-sr-copy-one="' + tab + "|" + srEsc(site) + '">copy</button>'
      + ' <button class="tr-mini" data-sr-del="' + tab + "|" + srEsc(site) + '">\u00D7</button></div>';
  }).join("");
}

function srTbEntryFmt(r) {
  const sc = (r.score === null || r.score === undefined) ? "-" : r.score;
  return srEsc((r.total || 0) + " cookies, score " + sc)
    + '<br><span class="tr-mix">' + srEsc(srMixDisplay(r.cls, r.mth)) + "</span>";
}

// ── Scan Diag tab (read-only view over Tracker Blocking receipts) ──

// A receipt belongs to the panel's site when its recorded site matches; the
// URL fallback covers TB receipts whose enforcement path had no siteKey.
function srDecisionSite(r) {
  const direct = srSiteOf(r && r.site);
  if (direct) return direct;
  try { return srSiteOf(new URL(String((r && r.url) || "")).hostname); } catch (_) { return ""; }
}

// Keep one row for each cookie identity and decision. Repeated scans can add
// duplicate receipts, so the newest matching site/name/domain/path/origin/
// verdict/reason is retained. Distinct domain/path cookies stay separate.
function srTrackerDiagRows(rows, site) {
  const targetSite = srSiteOf(site);
  if (!targetSite || !Array.isArray(rows)) return [];
  const unique = new Map();
  for (const r of rows) {
    if (!r || r.trigger !== "tb-enforce" || r.tb !== true || srDecisionSite(r) !== targetSite) continue;
    const verdict = String(r.verdict || "KEPT").replace(/[|\r\n]/g, " ").trim().toUpperCase();
    const name = String(r.name || "?").replace(/[|\r\n]/g, " ").trim();
    const reason = String(r.reason || "NOT_BLOCKED").replace(/[|\r\n]/g, " ").trim();
    const domain = String(r.domain || "").trim().toLowerCase();
    const path = String(r.path || "/").trim();
    const origin = String(r.origin || "").trim();
    const key = JSON.stringify([verdict, name, domain, path, origin, reason]);
    const previous = unique.get(key);
    if (!previous || (Number(r.t) || 0) >= (Number(previous.t) || 0)) unique.set(key, r);
  }
  return Array.from(unique.values()).sort((a, b) => (Number(b.t) || 0) - (Number(a.t) || 0));
}

// Copy/paste format requested for the tracking protection diagnostic. Cookie
// values are never read or included; repeated decisions for the same cookie
// identity are collapsed while cookies on distinct domains/paths stay visible.
function srScanDiagText(rows, site) {
  const list = srTrackerDiagRows(rows, site);
  if (list.length === 0) return "(no Tracking Protection decisions recorded for this site while blocking was enabled)";
  return list.map(r => {
    const verdict = String(r.verdict || "KEPT").replace(/[|\r\n]/g, " ").trim().toUpperCase();
    const name = String(r.name || "?").replace(/[|\r\n]/g, " ").trim();
    const reason = String(r.reason || "NOT_BLOCKED").replace(/[|\r\n]/g, " ").trim();
    const origin = r.origin === "Third-party" ? "3rd party" : r.origin === "First-party" ? "1st party" : "unknown";
    const domain = String(r.domain || "?").replace(/[|\r\n]/g, " ").trim();
    return verdict.padEnd(8) + " | " + name.padEnd(16) + " | " + reason.padEnd(30)
      + " | " + origin.padEnd(9) + " | " + domain;
  }).join("\n");
}

// Async fill: reads the persisted decision receipt ring and paints the
// site-scoped diagnostic. No-op when the tab isn't visible.
function srFillScanBody() {
  try {
    const el = document.getElementById("sr-list-scan");
    if (!el) return;
    if (typeof chrome === "undefined" || !chrome.storage || !chrome.storage.local) {
      el.innerHTML = '<pre class="block-diag">storage unavailable</pre>';
      return;
    }
    chrome.storage.local.get("ccDecisionReceipts", data => {
      try {
        const target = document.getElementById("sr-list-scan");
        if (!target) return;
        const site = srPanelSite();
        const rows = srTrackerDiagRows((data && data.ccDecisionReceipts) || [], site);
        target.innerHTML = '<pre class="block-diag">' + srEsc(srScanDiagText(rows, site)) + "</pre>";
      } catch (_) {}
    });
  } catch (_) {}
}

function srTabBody(tab) {
  const site = srPanelSite();
  const gate = (tab === "cookie") ? { ok: true, why: "" } : srGate(tab, srPanelBlockingOn(), site, srFeed());
  const dis = gate.ok ? "" : " disabled";
  const why = gate.ok ? "" : (" title=\"" + srEsc(gate.why) + "\"");
  let list = "";
  if (tab === "tboff") list = srEntriesHtml(tab, SR.off, srTbEntryFmt);
  else if (tab === "tbon") list = srEntriesHtml(tab, SR.on, srTbEntryFmt);
  else if (tab === "sg") list = srEntriesHtml(tab, SR.sg, r => srEsc((r.total || 0) + " cookies, " + (r.session || 0) + " session"));
  else if (tab === "hist") list = srEntriesHtml(tab, SR.hist, r => srEsc((r.removed || 0) + " removed [" + (SR_TRIGGER_LABEL[r.trigger] || r.trigger || "?") + "]" + (r.derived ? " (derived)" : "") + srSessionLikeSuffix(r)));
  else if (tab === "logout") list = srEntriesHtml(tab, SR.logout, r => srEsc(srLogoutSummary(r.bundle)));
  else if (tab === "cookie") {
    let text = "";
    try { if (typeof buildCookieListText === "function") text = buildCookieListText(); } catch (_) {}
    try { if (typeof escapeHtml === "function") text = escapeHtml(text); } catch (_) {}
    list = '<pre class="cookie-export">' + text + "</pre>";
  }
  else if (tab === "scan") {
    list = '<div id="sr-list-scan"><pre class="block-diag">loading Tracking Protection decisions…</pre></div>';
  }
  const status = gate.ok
    ? ("site: <b>" + srEsc(site || "—") + "</b>")
    : ("site: <b>" + srEsc(site || "—") + "</b> — " + srEsc(gate.why));
  const btnrow = (tab === "scan")
    ? '<div class="tr-btnrow"><button class="tr-btn" data-sr-refresh="scan">Refresh</button>'
      + '<button class="tr-btn" data-sr-copy="scan">Copy</button></div>'
    : '<div class="tr-btnrow"><button class="tr-btn" data-sr-record="' + tab + '"' + dis + why + ">Record</button>"
      + '<button class="tr-btn" data-sr-copy="' + tab + '">Copy</button></div>';
  return btnrow
    + '<div class="tr-pend">' + status + "</div>"
    + '<div id="sr-list-' + tab + '">' + list + "</div>";
}

function srTabsBarHtml(active) {
  // Display filter (count-debugging focus): only Cookie List + Scan Diag
  // buttons render. Hidden tabs' data, saved records, history, and record
  // functions are untouched — revert this filter to restore them. Accepted
  // gap: no SG Record button while hidden (saved SG snapshots persist).
  const visible = SR_TABS.filter(t => t.id === "cookie" || t.id === "scan");
  return '<div class="diag-tabs">' + visible.map(t =>
    '<button class="diag-tab' + (t.id === active ? " active" : "") + '" data-sr-tab="' + t.id + '">' + t.label + "</button>"
  ).join("") + "</div>";
}

// Called by sidepanel renderDiagPanel(). Renders tabs + active body.
function srRenderDiagnostics(dbgPanel, dbgBar, mode) {
  if (!dbgPanel) return;
  if (SR_TABS.some(t => t.id === mode)) SR.tab = mode;
  if (SR.tab !== "cookie" && SR.tab !== "scan") SR.tab = "cookie";
  dbgPanel.innerHTML = srTabsBarHtml(SR.tab)
    + '<div class="block-diag" id="sr-body">' + srTabBody(SR.tab) + "</div>";
  if (SR.tab === "scan") { try { srFillScanBody(); } catch (_) {} }
}

function srRefreshPanel() {
  try {
    const dbgPanel = document.getElementById("debug-panel");
    if (dbgPanel && dbgPanel.classList.contains("open")) {
      if (SR.tab !== "cookie" && SR.tab !== "scan") SR.tab = "cookie";
      dbgPanel.innerHTML = srTabsBarHtml(SR.tab)
        + '<div class="block-diag" id="sr-body">' + srTabBody(SR.tab) + "</div>";
      if (SR.tab === "scan") { try { srFillScanBody(); } catch (_) {} }
    }
  } catch (_) {}
}

// ── Delegated events (one listener, installed once) ──────────





// ── Delegated events (one listener, installed once) ──────────


function srOnDocClick(e) {
  try {
    const t = e.target;
    if (!t || !t.closest) return;
    const tabBtn = t.closest("[data-sr-tab]");
    if (tabBtn) {
      SR.tab = tabBtn.getAttribute("data-sr-tab") || SR.tab;
      srRefreshPanel();
      return;
    }
    const rec = t.closest("[data-sr-record]");
    if (rec && !rec.disabled) { srRecord(rec.getAttribute("data-sr-record")); return; }
    const cp = t.closest("[data-sr-copy]");
    if (cp) { srCopyTab(cp.getAttribute("data-sr-copy")); return; }
    const rf = t.closest("[data-sr-refresh]");
    if (rf && rf.getAttribute("data-sr-refresh") === "scan") { try { srFillScanBody(); } catch (_) {} return; }
    const del = t.closest("[data-sr-del]");
    if (del) {
      const parts = (del.getAttribute("data-sr-del") || "").split("|");
      srDeleteEntry(parts[0], parts[1]);
      return;
    }
    const cone = t.closest("[data-sr-copy-one]");
    if (cone) {
      const parts = (cone.getAttribute("data-sr-copy-one") || "").split("|");
      const tab = parts[0], site = parts[1];
      let text = "";
      if (tab === "tboff") { const r = SR.off[site]; if (r) text = srMirrorTb(site, r); }
      else if (tab === "tbon") { const r = SR.on[site]; if (r) text = srMirrorTb(site, r); }
      else if (tab === "sg") { const r = SR.sg[site]; if (r) text = srMirrorSg(site, r); }
      else if (tab === "hist") { const r = SR.hist[site]; if (r) text = srMirrorHist(site, r); }
      else if (tab === "logout") { const r = SR.logout[site]; if (r) text = srMirrorLogout(site, r); }
      if (!text) { srToast("Nothing to copy"); return; }
      navigator.clipboard.writeText(text).then(() => srToast("Copied " + site)).catch(() => srToast("Copy failed — check permissions"));
      return;
    }
  } catch (_) {}
}


// ── Init (browser only; skipped under Node) ────────────────

if (typeof document !== "undefined" && document && document.addEventListener && !SR.bound) {
  SR.bound = true;
  try { document.addEventListener("click", srOnDocClick); } catch (_) {}
  // Live gate re-render: flipping the blocking toggle re-renders the tab
  // body immediately, so a Record button can never stay dead (or live)
  // after the condition changed. Self-contained — no sidepanel edits.
  try {
    if (typeof chrome !== "undefined" && chrome && chrome.storage && chrome.storage.onChanged) {
      chrome.storage.onChanged.addListener((changes, area) => {
        try {
          if (area !== "local" || !changes) return;
          if (changes.riskBlockingEnabled) srRefreshPanel();
          // Repaint Scan Diag when new decision receipts persist.
          if (changes.ccDecisionReceipts && SR.tab === "scan") { try { srFillScanBody(); } catch (_) {} }
        } catch (_) {}
      });
    }
  } catch (_) {}
}
if (typeof chrome !== "undefined" && chrome && chrome.storage && chrome.storage.local) {
  srLoad(() => { try { srRefreshPanel(); } catch (_) {} });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    SR_CATS, SR_METHODS, SR_TASKS, SR_TABS,
    srFoldCat, srFoldMethod, srTally, srSiteOf, srGate,
    srPickHistoryEvent, srResolveHistory, srBuildBlocking, srMixStr, srMixDisplay,
    srMirrorTb, srMirrorSg, srMirrorHist, srMirrorTab, srLogoutSummary, srMirrorLogout,
    srTsvEsc, srTsvLine, srTbTsv, srSgTsv, srHistTsv,
    srMasterBlockingTsv, srMasterGuardTsv,
    srTrackerDiagRows, srScanDiagText, srFillScanBody,
  };
}
