// ============================================================
// Cookie Crumbs v5.3 — content.js (no alerts, consent check disabled, bad selector filtered)
// ============================================================

/**
 * SKIP_HOSTS: List of hostnames where Cookie Crumbs should not run.
 * WHY IT EXISTS: Certain sites (AI assistants, browser stores) either break or
 *   are irrelevant for consent analysis. Running on them wastes resources and
 *   can cause errors on pages that do not use standard CMP flows.
 * HOW IT WORKS: On load, the content script checks location.hostname against
 *   this list. If any entry matches, the entire script throws and exits early
 *   via `throw new Error("[CC] skip")`.
 * INPUT: None (static constant).
 * OUTPUT: N/A — used as a guard at script startup.
 */
const SKIP_HOSTS = [
  "claude.ai", "anthropic.com", "chat.openai.com",
  "gemini.google.com", "chrome.google.com",
];
if (SKIP_HOSTS.some(d => location.hostname.includes(d)) ||
    location.protocol === "chrome-extension:" ||
    location.protocol === "moz-extension:")
  throw new Error("[CC] skip");

/**
 * FALLBACK_SELECTORS: Hardcoded CSS selectors for known CMP consent banners and dialogs.
 * WHY IT EXISTS: Provides a baseline set of selectors so the extension can detect
 *   popular CMPs (OneTrust, Cookiebot, Didomi, Usercentrics, TrustArc, etc.)
 *   even before the database has been loaded. The DB may add or override these
 *   with higher-scored selectors. Without this list, the extension would have no
 *   detection capability on first install before syncing remote data.
 * HOW IT WORKS: Each selector targets a known CMP's root DOM element. These are
 *   used by `scoreSelectors()` to scan the page for visible consent UIs.
 *   Selectors are scored via `fallbackSelectorEntry()` — generic attribute
 *   selectors (containing `*=`, `[class`, `[id`) get score 1; specific ID
 *   selectors get score 2.
 * INPUT: None (static constant array of CSS selector strings).
 * OUTPUT: N/A — consumed by `loadDB()` to build `CMP_SELECTOR_ENTRIES`.
 * Source: Consent-O-Matic project's CMP selector database; manual audit of
 *   top CMPs per Cookiefilter.org rankings.
 */
const FALLBACK_SELECTORS = [
  "#onetrust-banner-sdk", "#onetrust-consent-sdk", "[data-testid='ot-banner']",
  "#onetrust-pc-sdk", ".ot-sdk-container", ".ot-sdk-row",
  "#CybotCookiebotDialog", "#CybotCookiebotDialogBodyButtonAccept",
  "#CookiebotWidget", "#CookiebotDialog",
  "#sp_message_container", "[id^='sp_message_container_']", "[id*='sp_message']",
  "#sourcepoint-popup", "[data-testid='sp_message_iframe']",
  "#didomi-popup", "#didomi-notice",
  "#didomi-host", ".didomi-popup-container",
  "#usercentrics-root", "[data-testid='uc-banner']",
  "#uc-main-dialog", "#usercentrics-cmp-ui",
  ".qc-cmp2-container", ".qc-cmp-showing",
  ".qc-cmp-cleanslate", ".qc-cmp-ui-container",
  "#truste-consent-track", "#trustarc-banner-overlay",
  "#teconsent", ".truste_box_overlay", ".trustarc-banner",
  "#BorlabsCookieBox", "#cookieyes-banner",
  "#cookieyes-consent", ".cky-consent-container",
  "#cookie-law-info-bar", "#gdpr-cookie-notice", "#cookie-notice",
  "#cliSettingsPopup", ".cli-bar-container",
  "#tarteaucitron", "#cmpbox", "#cmpwrapper",
  "#axeptio_overlay", "#Ax_cookie_bar",
  "#cookie-information-template-wrapper",
  "#snigel-cmp-framework", "#hs-eu-cookie-confirmation",
  "#iubenda-cs-banner", ".iubenda-cs-container",
  "#osano-cm-window", ".osano-cm-dialog",
  "#CookieConsent", ".cc-window", ".cc-banner",
  "#termly-cookie-preferences", ".termly-styles-root",
  "#consent-banner", "#consentDialog", "#cookie-banner", "#cookie-consent-banner",
  "[aria-label*='cookie consent']", "[aria-label*='consent']",
  ".consent-banner", ".cookie-banner", ".privacy-banner",
  "[class*='consent']", "[id*='consent']", "#globalCookieBanner",
];

/**
 * fallbackSelectorEntry: Wrap a CSS selector string into a scored entry object.
 * WHY IT EXISTS: Each CMP selector needs a reliability score so that when
 *   multiple selectors match, the most specific (highest-scored) one is
 *   preferred. Without scoring, a vague `[class*='consent']` match would carry
 *   the same weight as a precise `#onetrust-banner-sdk` match, leading to false
 *   positives from generic class/attribute selectors.
 * HOW IT WORKS: Checks if the selector contains generic patterns (`*=`,
 *   `[class`, `[id`). If so, assigns score 1 (low specificity). Otherwise
 *   assigns score 2 (ID-based or high specificity).
 * INPUT: selector (string) — a CSS selector from FALLBACK_SELECTORS or the DB.
 * OUTPUT: Object `{ selector: string, score: number }`.
 */
function fallbackSelectorEntry(selector) {
  const generic = selector.includes("*=") || selector.includes("[class") || selector.includes("[id");
  return { selector, score: generic ? 1 : 2 };
}

let CMP_SELECTORS   = [...FALLBACK_SELECTORS];
let CMP_SELECTOR_ENTRIES = FALLBACK_SELECTORS.map(fallbackSelectorEntry);
let TRACKER_DOMAINS = {};
let PRIVACY_DB = null;
let ML = null;
let widgetEl = null;
let widgetNewBadgeTimer = null;
let lastWidgetCookieCount = 0;
let widgetPos = null;
let widgetDragging = false;
let widgetDragMoved = false;
let widgetPanelOpen = false;
let prePanelWidgetPos = null;
let widgetEnabled = false;
let ccEnabled = true;
let consentAnalysisEnabled = true;
let _onWidgetMouseMove = null;
let _onWidgetMouseUp = null;
let currentTabId = null;
let docCookieRefreshTimer = null;
let authContextTimer = null;
let lastAuthContextState = null;
let widgetRefreshTimer = null;
const IS_TOP_FRAME = window.top === window;
const AUTH_CONTEXT_URL_RE = /(^|[/?#&=._-])(account|accounts|auth|authorize|login|signin|signon|sso|oauth|openid|idp|identity|security|secure|verify|verification|challenge|mfa|2fa|password)([/?#&=._-]|$)/i;

/**
 * requestLocalData: Request the privacy database and ML model weights from the
 *   background service worker via Chrome messaging.
 * WHY IT EXISTS: The content script runs in an isolated world and cannot directly
 *   access IndexedDB or files stored by the extension. The background script
 *   owns the DB and model, so this function bridges the gap by sending a
 *   `GET_LOCAL_DATA` message and wrapping the response in a Promise for
 *   convenient `await` usage. Without it, the content script would have no way
 *   to load the CMP selector database or ML classifier needed for detection.
 * HOW IT WORKS: Sends a Chrome runtime message of type `GET_LOCAL_DATA` to the
 *   background script. The background responds with `{ cookieDb, modelWeights }`.
 *   Wraps the callback-based API in a Promise so callers can use async/await.
 *   On error (e.g., extension context invalidated), resolves with null values
 *   rather than rejecting, so downstream code can gracefully fall back.
 * INPUT: None.
 * OUTPUT: Promise resolving to `{ cookieDb: Object|null, modelWeights: Object|null }`.
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

/**
 * loadDB: Merge CMP selectors from the remote database with the hardcoded
 *   fallbacks, and load the tracker domain blocklist.
 * WHY IT EXISTS: The hardcoded `FALLBACK_SELECTORS` are static and become
 *   stale as new CMPs emerge. The remote database provides updated selectors
 *   with empirically-derived scores. This function merges both sources so the
 *   extension always has the best available detection set. It also loads the
 *   `tracker_domains` map used later by the consent overlay to identify known
 *   tracker domains. Without this, detection would miss newer CMPs and the
 *   overlay could not show accurate tracker information.
 * HOW IT WORKS:
 *   1. Reads `data.cookieDb` — throws if absent.
 *   2. Extracts `cmp_selector_entries` (or converts legacy `cmp_selectors`).
 *   3. Filters out a known problematic Didomi selector.
 *   4. Creates a Map seeded with fallback selectors, then overwrites/upgrades
 *      entries where the DB has a higher score.
 *   5. Sorts the merged entries by descending score.
 *   6. Extracts `domains` from the DB into `TRACKER_DOMAINS`.
 * INPUT: data (Object) — `{ cookieDb, modelWeights }` from `requestLocalData()`.
 * OUTPUT: Modifies globals `CMP_SELECTOR_ENTRIES`, `CMP_SELECTORS`,
 *   `TRACKER_DOMAINS`, and `PRIVACY_DB`. Returns nothing (async).
 */
async function loadDB(data) {
  try {
    const db = data.cookieDb;
    if (!db) throw new Error("missing cookie db");
    PRIVACY_DB = db;
    let dbEntries = Array.isArray(db.cmp_selector_entries)
      ? db.cmp_selector_entries
      : (db.cmp_selectors || []).map(selector => ({ selector, score: 2 }));
    dbEntries = dbEntries.filter(entry => !entry.selector.includes(':not(.didomi-components-radio__option--selected)'));
    const merged = new Map();
    for (const entry of FALLBACK_SELECTORS.map(fallbackSelectorEntry)) {
      merged.set(entry.selector, entry);
    }
    for (const entry of dbEntries) {
      const current = merged.get(entry.selector);
      if (!current || (entry.score || 0) > (current.score || 0)) {
        merged.set(entry.selector, { selector: entry.selector, score: entry.score || 1 });
      }
    }
    CMP_SELECTOR_ENTRIES = [...merged.values()].sort((a, b) => (b.score || 0) - (a.score || 0));
    CMP_SELECTORS = CMP_SELECTOR_ENTRIES.map(entry => entry.selector);
    TRACKER_DOMAINS = db.domains || {};
  } catch(e) {
    console.warn("[CC] DB load failed, using fallback selectors", e);
  }
}

/**
 * loadModel: Instantiate the ML-based cookie classifier from saved weights.
 * WHY IT EXISTS: The heuristic-only classification of cookies is limited in
 *   accuracy. A lightweight ML model (loaded from bundled weights) can improve
 *   cookie category predictions. This function creates a `CookieMLClassifier`
 *   instance from the weights so that `widgetClassify()` can use it for more
 *   accurate cookie classification. Without it, the system falls back to
 *   heuristic-only classification.
 * HOW IT WORKS: Reads `data.modelWeights` and instantiates `CookieMLClassifier`
 *   with those weights. On any error (missing weights, invalid format), logs a
 *   warning and leaves `ML` as null, causing `classifyCookie()` to use
 *   heuristic fallback.
 * INPUT: data (Object) — `{ cookieDb, modelWeights }` from `requestLocalData()`.
 * OUTPUT: Sets global `ML` to a `CookieMLClassifier` instance, or leaves it null.
 */
async function loadModel(data) {
  try {
    const w = data.modelWeights;
    if (!w) throw new Error("missing model weights");
    ML = new CookieMLClassifier(w);
  } catch(e) {
    console.warn("[CC] model load failed", e);
  }
}

/**
 * removeWidget: Remove the floating score widget from the DOM and clean up
 *   associated event listeners.
 * WHY IT EXISTS: When settings change (e.g., user disables the widget, or
 *   the extension is turned off), the widget must be removed to stop visual
 *   clutter and prevent stale event listeners from leaking memory. Without
 *   this function, the widget would persist on-screen even when disabled,
 *   and drag-related mouse listeners would accumulate across enable/disable
 *   cycles.
 * HOW IT WORKS:
 *   1. If `widgetEl` exists, calls `widgetEl.remove()` to detach from DOM.
 *   2. Sets `widgetEl = null`.
 *   3. Removes document-level `mousemove` and `mouseup` listeners used for
 *      drag behavior, then nulls their references.
 * INPUT: None (operates on global `widgetEl` and listener references).
 * OUTPUT: Modifies DOM (removes widget) and cleans up global state.
 */
function removeWidget() {
  if (widgetEl) {
    widgetEl.remove();
    widgetEl = null;
  }
  if (_onWidgetMouseMove) { document.removeEventListener("mousemove", _onWidgetMouseMove); _onWidgetMouseMove = null; }
  if (_onWidgetMouseUp) { document.removeEventListener("mouseup", _onWidgetMouseUp); _onWidgetMouseUp = null; }
}

/**
 * stopWidgetPolling: Cancel the periodic widget refresh timer.
 * WHY IT EXISTS: The widget polls for updated cookie data every 2.5 seconds
 *   via `startWidgetPolling()`. When the widget is removed or disabled, this
 *   timer must be cleared to avoid unnecessary CPU usage and potential errors
 *   from trying to update a removed DOM element. Without it, the interval
 *   would keep firing indefinitely after disable.
 * HOW IT WORKS: Checks if `widgetRefreshTimer` is set; if so, calls
 *   `clearInterval()` and nulls the reference.
 * INPUT: None (operates on global `widgetRefreshTimer`).
 * OUTPUT: Sets `widgetRefreshTimer` to null.
 */
function stopWidgetPolling() {
  if (widgetRefreshTimer) {
    clearInterval(widgetRefreshTimer);
    widgetRefreshTimer = null;
  }
}

/**
 * startWidgetPolling: Start a 2.5-second interval that refreshes the widget's
 *   displayed privacy score.
 * WHY IT EXISTS: Cookies can be set dynamically by scripts after page load.
 *   A periodic refresh ensures the widget reflects the current cookie state
 *   without requiring the user to manually reload. Without this polling, the
 *   score would freeze at whatever it was when the widget first appeared,
 *   missing late-arriving tracking cookies. The 2.5s interval balances
 *   responsiveness with performance.
 * HOW IT WORKS: Guards against running in non-top frames or when already
 *   polling. Sets a 2500ms interval that calls `refreshWidget()` on each tick,
 *   but only if the widget is enabled and the page is the top frame.
 * INPUT: None (operates on globals `IS_TOP_FRAME`, `widgetRefreshTimer`).
 * OUTPUT: Sets `widgetRefreshTimer` to the interval ID.
 */
function startWidgetPolling() {
  if (!IS_TOP_FRAME || widgetRefreshTimer) return;
  widgetRefreshTimer = setInterval(() => {
    if (!widgetEnabled || !IS_TOP_FRAME) return;
    refreshWidget();
  }, 2500);
}

/**
 * applySettings: Synchronize widget visibility and consent analysis with the
 *   current extension settings.
 * WHY IT EXISTS: The extension has three toggle states — `ccEnabled` (master),
 *   `widgetEnabled` (floating widget), and `consentAnalysisEnabled` (consent
 *   interception). Changes to any of these require immediate UI updates. This
 *   function is the single entry point that reconciles all settings into the
 *   correct widget/analysis state. Without it, toggling settings would have no
 *   visible effect until a page reload.
 * HOW IT WORKS:
 *   1. If not the top frame, removes the widget and stops polling (widgets only
 *      run in the top frame).
 *   2. If `ccEnabled` is false, disables everything and removes the widget.
 *   3. If `widgetEnabled` is false, removes the widget but keeps consent
 *      analysis if `ccEnabled` is true.
 *   4. Otherwise, ensures the widget exists via `ensureWidget()`, restores
 *      panel state if it was open, starts polling, and triggers an immediate
 *      refresh.
 * INPUT: None (reads globals `IS_TOP_FRAME`, `ccEnabled`, `widgetEnabled`).
 * OUTPUT: Modifies DOM (creates/removes widget) and starts/stops polling.
 */
function applySettings() {
  if (!IS_TOP_FRAME) {
    removeWidget();
    stopWidgetPolling();
    return;
  }
  if (!ccEnabled) {
    widgetEnabled = false;
    consentAnalysisEnabled = false;
    removeWidget();
    stopWidgetPolling();
    return;
  }
  if (!widgetEnabled) {
    removeWidget();
    stopWidgetPolling();
    return;
  }
  if (document.body || document.documentElement) {
    const existed = !!document.getElementById("cc-score-widget");
    ensureWidget();
    if (!existed && widgetPanelOpen) updateWidgetPanelState(true);
  }
  startWidgetPolling();
  refreshWidget();
}

/**
 * loadSettings: Load widget, consent analysis, and master toggle settings from
 *   Chrome storage and apply them.
 * WHY IT EXISTS: On content script initialization, the extension must read the
 *   user's saved preferences to decide whether to show the widget, enable
 *   consent interception, or do nothing. Chrome storage is asynchronous, so
 *   this function wraps it in an async flow and feeds results to
 *   `applySettings()`. Without it, the content script would start with default
 *   values, ignoring the user's choices made in the options page.
 * HOW IT WORKS: Reads `widgetEnabled`, `ccEnabled`, and `consentAnalysisEnabled`
 *   from `chrome.storage.local` with defaults of `true`. Applies the master
 *   toggle: if `ccEnabled` is false, both sub-features are forced off. Then
 *   calls `applySettings()`. On error, still calls `applySettings()` to ensure
 *   defaults are applied.
 * INPUT: None (reads from `chrome.storage.local`).
 * OUTPUT: Sets globals `ccEnabled`, `consentAnalysisEnabled`, `widgetEnabled`,
 *   then calls `applySettings()`.
 */
async function loadSettings() {
  try {
    const data = await chrome.storage.local.get({
      widgetEnabled: true,
      ccEnabled: true,
      consentAnalysisEnabled: true,
    });
    ccEnabled = data.ccEnabled !== false;
    consentAnalysisEnabled = data.consentAnalysisEnabled !== false;
    widgetEnabled = data.widgetEnabled !== false;
    if (!ccEnabled) {
      widgetEnabled = false;
      consentAnalysisEnabled = false;
    }
    applySettings();
  } catch(e) {
    applySettings();
  }
}

/**
 * installDocCookieHook: Inject a content-script-accessible hook that monitors
 *   `document.cookie` changes by intercepting the page's native cookie setter.
 * WHY IT EXISTS: Content scripts run in an isolated world and cannot directly
 *   observe page-level `document.cookie` mutations. The injected script
 *   (`doc_cookie_hook.js`) monkey-patches the page's `Document.prototype.cookie`
 *   setter to fire a `CC_DOC_COOKIE_CHANGED` message whenever the page writes
 *   a cookie. Without this hook, the extension could only see cookies at
 *   initialization and would miss dynamically-set cookies (e.g., from CMPs that
 *   set consent cookies after user interaction). This is critical for the
 *   consent overlay to show accurate "what cookies will be set" information.
 * HOW IT WORKS:
 *   1. Uses a guard flag (`__ccDocCookieHookRequested`) to prevent double-injection.
 *   2. Creates a `<script>` element whose `src` points to `doc_cookie_hook.js`
 *      from the extension's web-accessible resources.
 *   3. Appends it to `<html>` (or waits for `DOMContentLoaded` if the DOM is
 *      not ready yet). The script self-removes on load.
 *   4. The injected script posts `CC_DOC_COOKIE_CHANGED` messages back.
 * INPUT: None (operates on DOM and extension resources).
 * OUTPUT: Injects a `<script>` tag into the page. The hook communicates via
 *   `window.postMessage`.
 * Source: OWASP建议 — 使用内容脚本注入来监控页面API变更，而非直接注入页面上下文。
 */
function installDocCookieHook() {
  if (window.__ccDocCookieHookRequested) return;
  window.__ccDocCookieHookRequested = true;
  const inject = () => {
    try {
      const script = document.createElement("script");
      script.src = chrome.runtime.getURL("doc_cookie_hook.js");
      script.async = false;
      script.dataset.ccHook = "doc-cookie";
      script.onload = () => script.remove();
      (document.documentElement || document.head || document.body)?.appendChild(script);
    } catch(e) { console.warn("[CC]", e.message); }
  };
  if (document.documentElement) inject();
  else window.addEventListener("DOMContentLoaded", inject, { once: true });
}

/**
 * scheduleDocCookieRefresh: Debounce rapid `document.cookie` change events
 *   before reading and sending cookies to the background script.
 * WHY IT EXISTS: The `doc_cookie_hook.js` interceptor fires a message on every
 *   page-level cookie write. During CMP initialization, pages may write dozens
 *   of cookies in rapid succession. Reading `document.cookie` on every write
 *   would be wasteful and could cause performance issues. Debouncing at 120ms
 *   ensures we read once after a burst of writes settles, capturing all
 *   cookies that were set. Without debouncing, the content script could send
 *   partial cookie snapshots to the background, causing incorrect scoring.
 * HOW IT WORKS: Clears any pending timer, then sets a 120ms timeout to call
 *   `readAndSendDocCookies()`. If another change arrives within 120ms, the
 *   timer resets, pushing the read further out until the burst stops.
 * INPUT: None (triggered by `CC_DOC_COOKIE_CHANGED` messages from the hook).
 * OUTPUT: Calls `readAndSendDocCookies()` after 120ms of silence.
 */
function scheduleDocCookieRefresh() {
  clearTimeout(docCookieRefreshTimer);
  docCookieRefreshTimer = setTimeout(() => {
    docCookieRefreshTimer = null;
    readAndSendDocCookies();
  }, 120);
}

/**
 * detectAuthContext: Detect whether the current page is a login, signup, or
 *   authentication page.
 * WHY IT EXISTS: The extension should avoid showing consent overlays or
 *   modifying UI on authentication pages, where user trust is critical and
 *   interfering could break login flows or leak credentials. Additionally,
 *   cookies set during authentication are functional/essential, not tracking
 *   cookies, so the scoring algorithm should treat them differently. This
 *   function provides a fast heuristic to flag auth pages. Without it, the
 *   extension might intercept clicks on "Sign In" buttons or flag essential
 *   session cookies as tracking cookies.
 * HOW IT WORKS:
 *   1. Checks the URL (hostname + pathname + query + hash) against
 *      `AUTH_CONTEXT_URL_RE`, which matches common auth-related URL segments
 *      like "login", "signin", "oauth", "mfa", etc.
 *   2. Checks for password input fields (`input[type='password']`).
 *   3. Checks for autocomplete attributes associated with credential fields.
 * INPUT: None (reads `location` and queries DOM).
 * OUTPUT: `true` if the page appears to be an auth page, `false` otherwise.
 */
function detectAuthContext() {
  try {
    const urlBlob = `${location.hostname} ${location.pathname} ${location.search} ${location.hash}`.toLowerCase();
    if (AUTH_CONTEXT_URL_RE.test(urlBlob)) return true;
    if (document.querySelector("input[type='password']")) return true;
    if (document.querySelector("input[autocomplete='current-password'], input[autocomplete='new-password']")) return true;
    return false;
  } catch (e) {
    return false;
  }
}

/**
 * reportAuthContext: Detect and report the current authentication context to
 *   the background script, deduplicating repeated reports.
 * WHY IT EXISTS: The background script needs to know whether the current page
 *   is an auth page so it can adjust cookie scoring and suppression logic
 *   globally (e.g., suppress cookie notifications during login). This function
 *   sends that signal, but only when the auth state actually changes, to avoid
 *   flooding the message channel with redundant reports. Without deduplication,
 *   every MutationObserver callback would trigger a message, causing
 *   unnecessary background processing.
 * HOW IT WORKS:
 *   1. Calls `detectAuthContext()` to get the current boolean state.
 *   2. Compares with `lastAuthContextState` — if unchanged, returns early.
 *   3. If changed, sends `AUTH_CONTEXT_CHANGED` message to the background script
 *      with the new state and current URL.
 * INPUT: None (reads globals `lastAuthContextState`, `location`).
 * OUTPUT: Sends a Chrome runtime message. Updates `lastAuthContextState`.
 */
function reportAuthContext() {
  const authMode = detectAuthContext();
  if (authMode === lastAuthContextState) return;
  lastAuthContextState = authMode;
  try {
    chrome.runtime.sendMessage(
      { type: "AUTH_CONTEXT_CHANGED", authMode, url: location.href },
      () => void chrome.runtime.lastError
    );
  } catch (e) { console.warn("[CC]", e.message); }
}

/**
 * scheduleAuthContextReport: Debounce auth context detection to avoid
 *   excessive DOM reads during rapid mutations.
 * WHY IT EXISTS: The MutationObserver that triggers auth detection can fire
 *   hundreds of times per second during dynamic page loads. Each mutation could
 *   change the auth state, but checking on every mutation is wasteful. A 150ms
 *   debounce ensures we only evaluate once the DOM has settled, preventing
 *   performance degradation on complex pages. Without debouncing, the content
 *   script could become a bottleneck during SPA navigation.
 * HOW IT WORKS: Clears any pending timer, then sets a 150ms timeout to call
 *   `reportAuthContext()`. Rapid mutations reset the timer, so only the final
 *   state after a quiet period is reported.
 * INPUT: None (triggered by MutationObserver and DOM events).
 * OUTPUT: Calls `reportAuthContext()` after 150ms of DOM silence.
 */
function scheduleAuthContextReport() {
  clearTimeout(authContextTimer);
  authContextTimer = setTimeout(() => {
    authContextTimer = null;
    reportAuthContext();
  }, 150);
}

/**
 * installAuthContextWatcher: Set up a MutationObserver and event listeners to
 *   detect when the page transitions into or out of an authentication state.
 * WHY IT EXISTS: Single-page applications (SPAs) dynamically load login forms,
 *   password fields, and auth-related UI without full page reloads. A static
 *   check at load time would miss these transitions. This function installs a
 *   persistent observer that re-evaluates the auth context whenever the DOM
 *   changes in ways that could indicate an auth form appeared or disappeared.
 *   Without it, the extension would not detect mid-session transitions to login
 *   pages (e.g., clicking "Sign In" in an SPA).
 * HOW IT WORKS:
 *   1. Waits for `document.documentElement` to be available (or listens for
 *      `DOMContentLoaded`).
 *   2. Creates a `MutationObserver` that watches for changes to `childList`,
 *      `subtree`, and selected attributes (`href`, `action`, `type`, `value`,
 *      `aria-label`, `role`, `class`, `id`).
 *   3. On each mutation, schedules `scheduleAuthContextReport()`.
 *   4. Also listens for `focusin` and `submit` events as additional signals.
 *   5. Uses a guard flag (`__ccAuthWatcherInstalled`) to prevent double-install.
 * INPUT: None (operates on DOM).
 * OUTPUT: Attaches a MutationObserver and event listeners to the document.
 */
function installAuthContextWatcher() {
  const attach = () => {
    try {
      const root = document.documentElement || document.body;
      if (!root || window.__ccAuthWatcherInstalled) return;
      window.__ccAuthWatcherInstalled = true;
      const observer = new MutationObserver(scheduleAuthContextReport);
      observer.observe(root, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ["href", "action", "type", "value", "aria-label", "role", "class", "id"],
      });
      window.addEventListener("focusin", scheduleAuthContextReport, true);
      window.addEventListener("submit", scheduleAuthContextReport, true);
      scheduleAuthContextReport();
    } catch (e) { console.warn("[CC]", e.message); }
  };
  if (document.documentElement) attach();
  else window.addEventListener("DOMContentLoaded", attach, { once: true });
}

installDocCookieHook();
installAuthContextWatcher();

/**
 * isVisible: Check whether a DOM element is visually visible to the user.
 * WHY IT EXISTS: Many CMPs render consent banners but keep them hidden via CSS
 *   (`display:none`, `visibility:hidden`, zero opacity, or positioning offscreen)
 *   until triggered. Detecting a hidden element as "present" would produce false
 *   positives in the banner detection pipeline. This function filters out
 *   invisible elements so only actually-displayed consent UIs count toward the
 *   CMP score. Without it, every page with a pre-loaded but hidden CMP would
 *   be flagged as having an active consent banner.
 * HOW IT WORKS: Reads the element's computed styles (`display`, `visibility`,
 *   `opacity`) and bounding rect (`width`, `height`, vertical position). Returns
 *   `true` only if the element is not `display:none`, not `visibility:hidden`,
 *   opacity > 0.05, dimensions > 10px, and at least partially within the
 *   viewport. Uses try/catch because getComputedStyle can throw on detached nodes.
 * INPUT: el (Element|null) — the DOM element to check.
 * OUTPUT: `boolean` — true if the element is visible.
 */
function isVisible(el) {
  if (!el) return false;
  try {
    const s = window.getComputedStyle(el);
    const r = el.getBoundingClientRect();
    return s.display !== "none"
        && s.visibility !== "hidden"
        && parseFloat(s.opacity) > 0.05
        && r.width > 10 && r.height > 10
        && r.bottom > 0 && r.top < window.innerHeight;
  } catch(e) { return false; }
}

/**
 * getSearchRoots: Collect the main document and all same-origin iframe documents
 *   for CMP searching.
 * WHY IT EXISTS: Many CMPs (Didomi, Usercentrics, Sourcepoint) render their
 *   consent banners inside iframes rather than directly in the page DOM. If we
 *   only search `document`, we would miss these iframe-based consent dialogs.
 *   This function builds a list of all accessible document roots — the main
 *   document plus any same-origin iframe contentDocuments — so that
 *   `scoreSelectors()` can query across all of them. Cross-origin iframes are
 *   inaccessible (contentDocument is null), so they are safely skipped.
 * HOW IT WORKS:
 *   1. Starts with `document` in the roots array.
 *   2. Iterates all `<iframe>` elements on the page.
 *   3. For each, tries to access `frame.contentDocument`. If accessible (same
 *      origin), adds it to the roots array. If cross-origin, the access throws
 *      and is caught silently.
 * INPUT: None (queries the DOM).
 * OUTPUT: Array of Document objects — `[document, iframeDoc1, iframeDoc2, ...]`.
 */
function getSearchRoots() {
  const roots = [document];
  for (const frame of document.querySelectorAll("iframe")) {
    try {
      const doc = frame.contentDocument;
      if (doc?.documentElement) roots.push(doc);
    } catch(e) { console.warn("[CC]", e.message); }
  }
  return roots;
}

/**
 * isFrameVisible: Check whether an iframe element is visually rendered on screen.
 * WHY IT EXISTS: Similar to `isVisible()` but with iframe-specific thresholds.
 *   CMPs often inject small tracking or consent iframes that are invisible or
 *   very small (1x1 pixel trackers). This function ensures we only score
 *   iframes that are large enough to plausibly contain a consent banner (>40px
 *   in both dimensions). Without this filter, invisible tracking iframes would
 *   inflate the iframe consent score, leading to false banner detection.
 * HOW IT WORKS: Same pattern as `isVisible()` but requires minimum 40x40px
 *   dimensions instead of 10x10px. Checks display, visibility, opacity, and
 *   viewport position.
 * INPUT: frame (Element) — an `<iframe>` element.
 * OUTPUT: `boolean` — true if the iframe is visible and large enough.
 */
function isFrameVisible(frame) {
  try {
    const s = window.getComputedStyle(frame);
    const r = frame.getBoundingClientRect();
    return s.display !== "none"
        && s.visibility !== "hidden"
        && parseFloat(s.opacity) > 0.05
        && r.width > 40 && r.height > 40
        && r.bottom > 0 && r.top < window.innerHeight;
  } catch(e) { return false; }
}

/**
 * scoreFrameShell: Score an iframe element (0–3) based on how likely it is to
 *   be a CMP consent banner, without accessing its contents.
 * WHY IT EXISTS: Cross-origin iframes cannot be inspected for text content, but
 *   we can still infer their purpose from metadata (title, name, id, className,
 *   src URL, aria-label, data-testid) and geometric properties (size, position,
 *   proximity to viewport edges). This "shell" analysis provides a non-invasive
 *   scoring mechanism for iframes we cannot read. Without it, cross-origin CMP
 *   iframes (which are the majority — most CMPs use cross-origin iframes for
 *   security) would receive a score of 0, causing missed detections.
 * HOW IT WORKS:
 *   1. Returns 0 if the frame is not visible.
 *   2. Concatenates all metadata into a single string and checks it against
 *      known CMP names (consent, cookie, didomi, onetrust, etc.).
 *   3. Checks geometric properties: near-edge positioning (within 120px of
 *      viewport top/bottom), large banner shape (≥60% width, ≥80px height),
 *      and modal-like shape (≥35% width, ≥180px height).
 *   4. Checks parent element text for cookie-related keywords.
 *   5. Returns a score: 0 (no signal), 2 (CMP metadata match), or 3
 *      (strong signal: CMP match + banner/modal geometry).
 * INPUT: frame (Element) — an `<iframe>` element.
 * OUTPUT: `number` — 0, 2, or 3.
 */
function scoreFrameShell(frame) {
  if (!isFrameVisible(frame)) return 0;
  try {
    const meta = [
      frame.title || "",
      frame.name || "",
      frame.id || "",
      frame.className || "",
      frame.src || "",
      frame.getAttribute("aria-label") || "",
      frame.getAttribute("data-testid") || "",
    ].join(" ").toLowerCase();

    const srcHit = /consent|cookie|privacy|didomi|onetrust|usercentrics|trustarc|cookiebot|sourcepoint|quantcast|osano|iubenda|termly|axeptio|cassie/.test(meta);
    const r = frame.getBoundingClientRect();
    const nearEdge = r.bottom >= window.innerHeight - 120 || r.top <= 120;
    const largeBanner = r.width >= Math.min(window.innerWidth * 0.6, 600) && r.height >= 80;
    const modalLike = r.width >= Math.min(window.innerWidth * 0.35, 360) && r.height >= 180;

    let score = 0;
    if (srcHit) score = Math.max(score, 2);
    if (srcHit && nearEdge && largeBanner) score = Math.max(score, 3);
    if (srcHit && modalLike) score = Math.max(score, 3);

    const parent = frame.parentElement;
    if (parent && isVisible(parent)) {
      const parentText = (parent.innerText || parent.textContent || "").toLowerCase();
      if (srcHit && /cookie|consent|privacy|preferences/.test(parentText)) {
        score = Math.max(score, 3);
      }
    }
    return score;
  } catch(e) { return 0; }
}

/**
 * scoreSelectors: Scan all document roots (main + iframes) for known CMP CSS
 *   selectors and return the best matching score.
 * WHY IT EXISTS: The primary detection mechanism — known CMP selectors are the
 *   most reliable way to identify consent banners because they target specific
 *   DOM elements that CMPs create. This function queries every selector in
 *   `CMP_SELECTOR_ENTRIES` against every accessible document root, tracking
 *   both the highest individual score and the number of matches. Multiple
 *   matches (e.g., both a banner and an accept button) indicate a stronger
 *   signal. Without this, the extension would rely solely on heuristics, which
 *   are less precise.
 * HOW IT WORKS:
 *   1. Iterates every document root from `getSearchRoots()`.
 *   2. For each root, tries every selector in `CMP_SELECTOR_ENTRIES`.
 *   3. If a selector matches a visible element, increments `matched` count and
 *      updates `best` with the selector's score.
 *   4. If ≥2 selectors match and the best score > 0, returns `min(best + 1, 4)`
 *      as a boost for corroboration. Otherwise returns `best`.
 * INPUT: None (reads globals `CMP_SELECTOR_ENTRIES`).
 * OUTPUT: `number` — score from 0 to 4 indicating CMP presence confidence.
 */
function scoreSelectors() {
  let best = 0;
  let matched = 0;
  for (const root of getSearchRoots()) {
    for (const entry of CMP_SELECTOR_ENTRIES) {
      try {
        const el = root.querySelector(entry.selector);
        if (el && isVisible(el)) {
          matched += 1;
          best = Math.max(best, entry.score || 1);
        }
      } catch(e) { console.warn("[CC]", e.message); }
    }
  }
  if (matched >= 2 && best > 0) return Math.min(best + 1, 4);
  return best;
}

/**
 * scoreIframes: Score all iframes on the page for CMP consent detection,
 *   combining shell analysis with accessible content inspection.
 * WHY IT EXISTS: CMPs increasingly render consent banners in iframes (for
 *   isolation, security, and cross-origin compliance). This function provides
 *   a comprehensive iframe analysis by combining `scoreFrameShell()` (metadata
 *   and geometry) with content-based detection (reading the iframe's body text
 *   for cookie/consent keywords and action buttons). Without this, the extension
 *   would miss iframe-based CMPs that are the dominant implementation pattern
 *   for major CMPs like OneTrust, Cookiebot, and Sourcepoint.
 * HOW IT WORKS:
 *   1. Iterates all `<iframe>` elements on the page.
 *   2. For each, runs `scoreFrameShell()` for metadata-based scoring.
 *   3. Checks the iframe's title/name/src for known CMP keywords.
 *   4. If the iframe is same-origin and has a body, reads its text content
 *      for cookie-related keywords combined with action words (accept, reject,
 *      consent, preferences).
 *   5. Returns the maximum score across all iframes.
 * INPUT: None (queries DOM).
 * OUTPUT: `number` — 0 to 3 indicating iframe-based CMP presence.
 */
function scoreIframes() {
  let score = 0;
  for (const frame of document.querySelectorAll("iframe")) {
    score = Math.max(score, scoreFrameShell(frame));
    try {
      const title = `${frame.title || ""} ${frame.name || ""} ${(frame.src || "")}`.toLowerCase();
      if (/consent|cookie|privacy|didomi|onetrust|usercentrics|trustarc|cookiebot|sourcepoint/.test(title)) {
        score = Math.max(score, 2);
      }
      const doc = frame.contentDocument;
      if (!doc?.body) continue;
      const text = (doc.body.innerText || doc.body.textContent || "").toLowerCase();
      if (text.includes("cookie") && /accept|reject|consent|preferences|privacy/.test(text)) {
        score = Math.max(score, 3);
      }
    } catch(e) { console.warn("[CC]", e.message); }
  }
  return score;
}

/**
 * scoreTCF: Query the background script for a TCF (Transparency & Consent
 *   Framework) API detection score.
 * WHY IT EXISTS: The TCF is the European standard for CMP consent APIs. Many
 *   CMPs expose a `__tcfapi` function on the window object. Detecting this API
 *   is a strong signal that a CMP is active, even if the visual banner hasn't
 *   loaded yet or is rendered in a cross-origin iframe we cannot access. The
 *   background script performs this detection because it can access the page's
 *   main world via scripting injection. Without TCF detection, the extension
 *   would miss CMPs that are technically active but have no visible DOM presence
 *   (e.g., pre-consent mode where the banner is loaded lazily).
 * HOW IT WORKS: Sends a `GET_TCF_SCORE` message to the background script. The
 *   background checks for `window.__tcfapi` and returns a numeric score. The
 *   callback receives this score, defaulting to 0 on error.
 * INPUT: cb (Function) — callback that receives the TCF score as a number.
 * OUTPUT: Calls `cb(score)` where score is 0 (no TCF) or > 0 (TCF detected).
 * Source: IAB Europe TCF v2.2 specification — `__tcfapi` is the standard
 *   interface for CMPs to communicate consent status.
 */
function scoreTCF(cb) {
  try {
    chrome.runtime.sendMessage({ type: "GET_TCF_SCORE" }, resp => {
      if (chrome.runtime.lastError) { cb(0); return; }
      cb(Number.isFinite(resp?.score) ? resp.score : 0);
    });
  } catch(e) { cb(0); }
}

/**
 * ACCEPT_PATTERNS: Regex matching common "accept all cookies" button labels.
 * WHY IT EXISTS: Consent banners contain buttons with varying text across CMPs
 *   and languages. This regex unifies common English accept-button variants so
 *   the consent interception system can identify the accept action regardless
 *   of exact wording. Without it, each CMP's button text would require a
 *   separate match, making the system brittle.
 * Source: Manual audit of top 50 CMPs' English-language button labels.
 */
const ACCEPT_PATTERNS = /accept|agree|allow all|allow cookies|got it|continue|dismiss|i understand|i accept|ok, i agree|that's ok|enable all|yes, i agree|accept all/i;

/**
 * STRONG_ACCEPT_PATTERNS: Subset of accept patterns indicating unambiguous
 *   "accept all" consent (e.g., "Accept All", "Allow Cookies").
 * WHY IT EXISTS: Some accept buttons are ambiguous — "Continue" might mean
 *   "continue without accepting" in some CMPs. Strong patterns indicate the
 *   user is explicitly consenting to all tracking. The consent overlay uses
 *   this distinction: strong accepts trigger the interception overlay, while
 *   weak accepts are only flagged when corroborated by additional context.
 * Source: Same as ACCEPT_PATTERNS.
 */
const STRONG_ACCEPT_PATTERNS = /accept all|accept cookies|allow cookies|allow all|agree to all|yes,\s*i agree|i accept|ok,\s*i agree/i;

/**
 * WEAK_ACCEPT_PATTERNS: Accept patterns that are ambiguous and may not
 *   constitute full consent (e.g., "Got it", "Continue", "Dismiss").
 * WHY IT EXISTS: Buttons like "Got it" or "Continue" are sometimes used for
 *   non-consent dismissals. These require stronger corroboration (e.g., must
 *   appear in a confirmed consent container with both accept and reject options)
 *   before the extension intercepts the click. This prevents false positives
 *   on non-consent dialogs.
 * Source: Same as ACCEPT_PATTERNS.
 */
const WEAK_ACCEPT_PATTERNS = /accept|agree|got it|continue|dismiss|i understand|that's ok|enable all/i;

/**
 * REJECT_PATTERNS: Regex matching common "reject cookies" or "manage settings"
 *   button labels.
 * WHY IT EXISTS: The presence of both accept AND reject buttons is a strong
 *   signal that a UI element is a consent banner (as opposed to a generic
 *   dialog). This pattern also identifies the reject/decline action, which the
 *   extension might want to auto-click in the future. Without tracking reject
 *   patterns, the extension could not distinguish consent banners from other
 *   dialogs with only a single "OK" button.
 * Source: Same as ACCEPT_PATTERNS.
 */
const REJECT_PATTERNS = /reject|decline|refuse|only necessary|deny|no thanks|manage|preferences|settings|customize|customise|manage choices|cookie settings/i;

/**
 * textMatchesBanner: Check if text content contains sufficient cookie/consent
 *   keywords to be considered a consent banner.
 * WHY IT EXISTS: Heuristic banner detection needs to distinguish consent
 *   banners from other page elements (footers, navigation, popups). A simple
 *   keyword check alone would produce many false positives — any page with the
 *   word "privacy" in a footer would match. This function requires either ≥2
 *   policy keywords (cookie, consent, privacy, GDPR, tracking, preferences) or
 *   ≥1 keyword plus an action pattern (accept/reject button text). This
 *   two-factor requirement significantly reduces false positives while
 *   maintaining recall for legitimate consent banners.
 * HOW IT WORKS:
 *   1. Lowercases the input text.
 *   2. Counts how many of the 8 policy keywords appear in the text.
 *   3. Checks if the text also contains an accept or reject action pattern.
 *   4. Returns true if: ≥2 policy keywords present, OR ≥1 keyword + an action.
 * INPUT: text (string) — the text content of a candidate element.
 * OUTPUT: `boolean` — true if the text is consistent with a consent banner.
 */
function textMatchesBanner(text) {
  const t = (text || "").toLowerCase();
  const policyWords = ["cookie","consent","privacy","gdpr","tracking","preference","preferences","personalised","personalized"];
  const policyHits = policyWords.filter(k => t.includes(k)).length;
  const actionHit = ACCEPT_PATTERNS.test(t) || REJECT_PATTERNS.test(t);
  return policyHits >= 2 || (policyHits >= 1 && actionHit);
}

/**
 * isBannerLikeGeometry: Check if a bounding rectangle matches typical consent
 *   banner dimensions and positioning.
 * WHY IT EXISTS: Consent banners have characteristic shapes — full-width
 *   bottom/top bars, or centered modals. Many false-positive elements (headers,
 *   footers, inline content) have different geometries. This function applies
 *   geometric heuristics to filter out elements that don't match known banner
 *   patterns, reducing false positives in the heuristic scoring pipeline.
 * HOW IT WORKS: Checks two patterns:
 *   1. "Edge banner": width ≥ 55% of viewport AND height ≥ 80px AND positioned
 *      within 120px of the top or bottom edge of the viewport.
 *   2. "Modal-like": width ≥ 28% of viewport AND height ≥ 18% of viewport AND
 *      height ≥ 160px.
 *   Returns true if either pattern matches.
 * INPUT: rect (DOMRect) — the element's bounding rectangle.
 * OUTPUT: `boolean` — true if the geometry matches a consent banner pattern.
 */
function isBannerLikeGeometry(rect) {
  const widthRatio = rect.width / Math.max(window.innerWidth, 1);
  const heightRatio = rect.height / Math.max(window.innerHeight, 1);
  const nearBottom = rect.bottom >= window.innerHeight - 120;
  const nearTop = rect.top <= 120;
  const edgeBanner = widthRatio >= 0.55 && rect.height >= 80 && (nearBottom || nearTop);
  const modalLike = widthRatio >= 0.28 && heightRatio >= 0.18 && rect.height >= 160;
  return edgeBanner || modalLike;
}

/**
 * heuristicPositiveScore: Compute a positive evidence score (0–N) for a DOM
 *   element being a consent banner, based on UI heuristics.
 * WHY IT EXISTS: Not all consent banners are detected by CMP selectors (some
 *   CMPs use custom implementations, or the selectors may be outdated). This
 *   heuristic analysis provides a fallback detection path by examining visual
 *   and structural properties common to consent banners. It checks position
 *   (fixed/sticky/dialog), geometry (banner-like shape), button labels
 *   (accept/reject patterns), text content (cookie keywords), z-index
 *   (overlays are typically z-index > 1000), background contrast, and
 *   attribute/class naming. Without this, the extension would miss custom-built
 *   consent UIs that don't use any of the known CMP selectors.
 * HOW IT WORKS: Applies a series of filters and point accumulators:
 *   1. Filters out non-fixed/non-dialog elements (consent banners are overlays).
 *   2. Filters out invisible, too-small, or fullscreen elements.
 *   3. Requires banner-like geometry.
 *   4. Requires either banner-matching text or accept/reject buttons.
 *   5. Accumulates points for: "cookie" keyword (+2), ≥2 policy keywords (+1),
 *      ≥3 keywords (+1), action buttons (+1), both accept+reject (+1), corner
 *      positioning (+1), edge-banner shape (+1), dialog role (+1), contrasting
 *      background (+1), high z-index (+1), cookie-related attributes (+1).
 * INPUT: el (Element) — the DOM element to score.
 * OUTPUT: `number` — positive evidence score (0–11).
 */
function heuristicPositiveScore(el) {
  try {
    const s = window.getComputedStyle(el);
    const isDialog = el.matches?.("[role='dialog'], dialog, [aria-modal='true']");
    if (s.position !== "fixed" && s.position !== "sticky" && !isDialog) return 0;
    if (!isVisible(el)) return 0;
    const r = el.getBoundingClientRect();
    if (r.height < 50) return 0;
    if ((r.width * r.height) / (window.innerWidth * window.innerHeight) > 0.92) return 0;
    if (!isBannerLikeGeometry(r)) return 0;

    const btns = [...el.querySelectorAll(
      "button, a[role=button], input[type=button], input[type=submit], " +
      "[class*=btn], [class*=button], [class*=Button], [role=button]"
    )];
    const btnText = btns.map(b => (b.innerText || b.textContent || b.value || "").toLowerCase()).join(" ");
    const text = (el.innerText || el.textContent || "").toLowerCase();
    const actionCount = [
      ACCEPT_PATTERNS.test(btnText),
      REJECT_PATTERNS.test(btnText),
    ].filter(Boolean).length;
    if (!textMatchesBanner(text) && actionCount === 0) return 0;

    let points = 0;
    if (text.includes("cookie")) points += 2;
    const kwCount = ["cookie","consent","privacy","gdpr","tracking","preference","preferences"].filter(k => text.includes(k)).length;
    if (kwCount >= 2) points += 1;
    if (kwCount >= 3) points += 1;
    if (actionCount >= 1) points += 1;
    if (ACCEPT_PATTERNS.test(btnText) && REJECT_PATTERNS.test(btnText)) points += 1;
    const isCorner = (r.right >= window.innerWidth - 50 && r.top <= 50) ||
                     (r.right >= window.innerWidth - 50 && r.bottom >= window.innerHeight - 50) ||
                     (r.left <= 50 && r.top <= 50) ||
                     (r.left <= 50 && r.bottom >= window.innerHeight - 50);
    if (isCorner) points += 1;
    const isEdgeBanner = r.bottom >= window.innerHeight - 120 || r.top <= 120;
    if (isEdgeBanner && r.width >= window.innerWidth * 0.55) points += 1;
    if (isDialog) points += 1;
    const bg = s.backgroundColor;
    if (bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent") {
      const bodyBg = window.getComputedStyle(document.body).backgroundColor;
      if (bg !== bodyBg) points += 1;
    }
    const zi = Number.parseInt(s.zIndex, 10);
    if (Number.isFinite(zi) && zi >= 1000) points += 1;
    const attrs = `${el.id || ""} ${el.className || ""} ${el.getAttribute?.("aria-label") || ""}`.toLowerCase();
    if (/cookie|consent|privacy|preferences/.test(attrs)) points += 1;
    return points;
  } catch(e) { return 0; }
}

/**
 * negativeScore: Compute a penalty score for a DOM element that reduces the
 *   likelihood it is a consent banner.
 * WHY IT EXISTS: Some elements match positive heuristics but are clearly not
 *   consent banners — e.g., a fixed footer navigation bar with cookie links,
 *   or a dialog with a transparent background. Without penalty scoring, these
 *   would produce false positives. This function applies negative signals to
 *   counterbalance `heuristicPositiveScore()`, so that the net score accurately
 *   reflects consent-banner likelihood. The net score (positive - negative) is
 *   what `getUiEvidenceScore()` uses.
 * HOW IT WORKS: Accumulates penalties for:
 *   1. Being inside a `<header>`, `<footer>`, or `<nav>` (+1).
 *   2. Having class names containing "header", "footer", "nav" (+1).
 *   3. Text not matching banner patterns (+1).
 *   4. Transparent or body-matching background (+1).
 *   5. No accept or reject buttons in child elements (+2).
 *   6. Height < 50px (+1).
 *   7. Geometry not matching banner shape (+2).
 * INPUT: el (Element) — the DOM element to penalize.
 * OUTPUT: `number` — penalty score (0–9).
 */
function negativeScore(el) {
  let neg = 0;
  try {
    const s = window.getComputedStyle(el);
    const text = (el.innerText || el.textContent || "").toLowerCase();
    if (el.closest("header, footer, nav")) neg += 1;
    const className = (el.className || "").toLowerCase();
    if (className.includes("header") || className.includes("footer") || className.includes("nav")) neg += 1;
    if (!textMatchesBanner(text)) neg += 1;
    const bg = s.backgroundColor;
    if (bg === "rgba(0, 0, 0, 0)" || bg === "transparent") neg += 1;
    else {
      const bodyBg = window.getComputedStyle(document.body).backgroundColor;
      if (bg === bodyBg) neg += 1;
    }
    const btns = [...el.querySelectorAll("button, a[role=button]")];
    const btnText = btns.map(b => (b.innerText || "").toLowerCase()).join(" ");
    if (!ACCEPT_PATTERNS.test(btnText) && !REJECT_PATTERNS.test(btnText)) neg += 2;
    const r = el.getBoundingClientRect();
    if (r.height < 50) neg += 1;
    if (!isBannerLikeGeometry(r)) neg += 2;
  } catch(e) { console.warn("[CC]", e.message); }
  return neg;
}

/**
 * getUiEvidenceScore: Scan all candidate DOM elements and return the highest
 *   net UI evidence score for consent banner presence.
 * WHY IT EXISTS: Individual element scoring via `heuristicPositiveScore()` and
 *   `negativeScore()` produces per-element scores. This function orchestrates
 *   the full scan across all candidate elements (divs, sections, asides,
 *   dialogs, footers, mains, and ARIA role/dialog elements) in all accessible
 *   document roots, computing the net score (positive - negative) for each and
 *   returning the best. Without this aggregation, the system would need to
 *   manually evaluate each element type separately.
 * HOW IT WORKS:
 *   1. Iterates all document roots from `getSearchRoots()`.
 *   2. For each root, queries candidate element types.
 *   3. For each element, computes `heuristicPositiveScore()`. Skips if 0.
 *   4. Computes `negativeScore()` and calculates net = max(0, positive - negative).
 *   5. Tracks and returns the highest net score.
 * INPUT: None (scans DOM).
 * OUTPUT: `number` — best net UI evidence score (0+).
 */
function getUiEvidenceScore() {
  let bestNet = 0;
  for (const root of getSearchRoots()) {
    for (const el of root.querySelectorAll("div,section,aside,dialog,footer,main,[role='dialog'],[aria-modal='true']")) {
      const pos = heuristicPositiveScore(el);
      if (pos === 0) continue;
      const neg = negativeScore(el);
      const net = Math.max(0, pos - neg);
      if (net > bestNet) bestNet = net;
    }
  }
  return bestNet;
}

/**
 * decideBannerPresence: Make the final decision on whether a consent banner is
 *   present on the page, combining CMP selector, iframe, UI heuristic, and TCF
 *   evidence.
 * WHY IT EXISTS: Each detection method (selectors, iframes, UI heuristics, TCF)
 *   has its own strengths and weaknesses. Selectors are precise but limited to
 *   known CMPs. Heuristics cover unknown CMPs but have false positives. TCF
 *   detects the API but not the visual presence. This function combines all
 *   signals using a multi-family corroboration model: a single strong signal
 *   (cmpScore ≥ 3 or uiScore ≥ 5) is sufficient, but weaker signals require
 *   corroboration across ≥2 evidence families with a total score ≥ 4. This
 *   approach maximizes recall (catching all real banners) while controlling
 *   precision (minimizing false positives).
 * HOW IT WORKS:
 *   1. Runs `scoreSelectors()` and `scoreIframes()`, takes the max as `cmpScore`.
 *   2. Runs `getUiEvidenceScore()` for `uiScore`.
 *   3. `tcfScore` is passed in (async from `scoreTCF()`).
 *   4. Counts how many of the three families (CMP, UI, TCF) have non-zero scores.
 *   5. Decision rules:
 *      - cmpScore ≥ 3 → banner present (strong CMP signal)
 *      - uiScore ≥ 5 → banner present (strong UI signal)
 *      - families ≥ 2 AND total ≥ 4 → banner present (corroborated)
 *      - Otherwise → no banner
 * INPUT: tcfScore (number) — the TCF detection score from `scoreTCF()`.
 * OUTPUT: `boolean` — true if a consent banner is deemed present.
 * Source: Multi-signal detection approach inspired by academic work on
 *   privacy tool detection (e.g., "WhoTracksMe" methodology).
 */
function decideBannerPresence(tcfScore) {
  const selectorScore = scoreSelectors();
  const iframeScore = scoreIframes();
  const cmpScore = Math.max(selectorScore, iframeScore);
  const uiScore = getUiEvidenceScore();
  const families = [
    cmpScore > 0,
    uiScore >= 2,
    tcfScore > 0,
  ].filter(Boolean).length;
  const total = cmpScore + uiScore + tcfScore;

  // One strong CMP signal or a very strong on-screen consent UI is enough.
  if (cmpScore >= 3) return true;
  if (uiScore >= 5) return true;

  // Otherwise require corroboration across evidence families.
  if (families >= 2 && total >= 4) return true;

  return false;
}

/**
 * fullCheck: Run the complete banner detection pipeline and report the result
 *   via callback.
 * WHY IT EXISTS: `scoreTCF()` is async (requires a Chrome message round-trip),
 *   so `decideBannerPresence()` cannot be called synchronously with the TCF
 *   score. This function wraps the full detection pipeline in an async callback
 *   pattern: it requests the TCF score, then passes it to `decideBannerPresence()`.
 *   Without this wrapper, callers would need to manually coordinate the TCF
 *   async call with the synchronous detection functions.
 * HOW IT WORKS: Calls `scoreTCF()` with a callback that receives the TCF score,
 *   then calls `decideBannerPresence(tcfScore)` and passes the boolean result
 *   to the provided callback.
 * INPUT: cb (Function) — callback that receives `boolean` (banner present or not).
 * OUTPUT: Calls `cb(boolean)` with the detection result.
 */
function fullCheck(cb) {
  scoreTCF(tcfScore => {
    cb(decideBannerPresence(tcfScore));
  });
}

/**
 * readAndSendDocCookies: Parse `document.cookie` and send the structured
 *   cookie list to the background script for scoring and storage.
 * WHY IT EXISTS: `document.cookie` only exposes non-HttpOnly cookies. These
 *   cookies are set by the page's JavaScript and are visible to the content
 *   script, but the content script cannot directly access the browser's cookie
 *   store (which includes HttpOnly cookies). This function bridges the gap by
 *   reading the page-visible cookies, structuring them with metadata (name,
 *   value, domain, `docCookie: true` flag), and sending them to the background
 *   for inclusion in the tab's cookie state. Without this, the widget score
 *   would be missing all JavaScript-set cookies, which include many consent
 *   cookies set by CMPs (e.g., `OptanonAlertBoxClosed`, `CookieConsent`).
 * HOW IT WORKS:
 *   1. Reads `document.cookie` (raw string).
 *   2. Splits on `;` and parses each pair into `{ name, value, domain, docCookie }`.
 *   3. Filters out entries with empty names.
 *   4. Sends `DOC_COOKIES` message to the background with the parsed array.
 * INPUT: None (reads `document.cookie`).
 * OUTPUT: Sends a Chrome runtime message with `{ type: "DOC_COOKIES", cookies, url }`.
 */
function readAndSendDocCookies() {
  try {
    const raw = document.cookie;
    if (!raw.trim()) return;
    const parsed = raw.split(";").map(p => {
      const idx = p.indexOf("=");
      const name = idx === -1 ? p.trim() : p.slice(0, idx).trim();
      const val = idx === -1 ? "" : p.slice(idx + 1).trim();
      return { name, value: val, domain: location.hostname, docCookie: true };
    }).filter(c => c.name);
    if (parsed.length)
      chrome.runtime.sendMessage({ type: "DOC_COOKIES", cookies: parsed, url: location.href })
        .catch(() => {});
  } catch(e) { console.warn("[CC]", e.message); }
}

/**
 * widgetIsHighRisk: Check if a cookie's domain is on the high-risk blocklist.
 * WHY IT EXISTS: Some domains are known to be highly invasive trackers (e.g.,
 * cross-site trackers, fingerprinting services). Cookies from these domains
 *   should receive a higher penalty multiplier in the score computation, even
 *   if they are session cookies or first-party proxied. The blocklist is
 *   maintained in the privacy database and loaded by `loadDB()`. Without this
 *   check, all domains would be treated equally, underweighting the most
 *   harmful trackers.
 * HOW IT WORKS: Normalizes the domain (strips leading dot, lowercases), then
 *   checks if it exactly matches or is a subdomain of any entry in
 *   `PRIVACY_DB.blocklist`.
 * INPUT: domain (string) — the cookie's domain attribute.
 * OUTPUT: `boolean` — true if the domain is on the blocklist.
 */
function widgetIsHighRisk(domain) {
  if (!PRIVACY_DB) return false;
  const d = String(domain || "").replace(/^\./,"").toLowerCase();
  return (PRIVACY_DB.blocklist || []).some(h => {
    const n = String(h || "").replace(/^\./, "").toLowerCase();
    return d === n || d.endsWith("." + n);
  });
}

/**
 * widgetGetCookiePersistence: Determine if a cookie is a session cookie or
 *   persistent, and compute remaining days until expiry.
 * WHY IT EXISTS: Persistent cookies (with expiration dates) are more privacy-
 *   invasive than session cookies because they survive browser restarts and
 *   enable long-term tracking. The score computation uses persistence as a
 *   multiplier — persistent cookies from third-party advertising domains
 *   receive the highest penalties. Without this classification, the scoring
 *   model would treat a 1-day session cookie the same as a 1-year tracking
 *   cookie, producing inaccurate privacy scores.
 * HOW IT WORKS:
 *   1. Checks for `session` boolean flag (from browser extension cookie API).
 *   2. If no `session` flag, checks for `expirationDate`.
 *   3. A cookie is considered a session cookie if `session === true` or if
 *      `expirationDate` is absent/NaN.
 *   4. For persistent cookies, calculates days remaining from now until expiry.
 * INPUT: cookie (Object) — a cookie object with `session`, `expirationDate` fields.
 * OUTPUT: `{ isSession: boolean, daysRemaining: number|null }`.
 */
function widgetGetCookiePersistence(cookie) {
  const hasSessionFlag = typeof cookie?.session === "boolean";
  const hasExpiry = Number.isFinite(cookie?.expirationDate);
  const isSession = hasSessionFlag ? cookie.session : !hasExpiry;
  const daysRemaining = !isSession && hasExpiry
    ? (cookie.expirationDate - Date.now()/1000)/86400
    : null;
  return { isSession, daysRemaining };
}

/**
 * widgetClassify: Classify a cookie into a privacy category (Strict,
 *   Performance, Functionality, Advertising, Unknown).
 * WHY IT EXISTS: Different cookie categories have different privacy
 *   implications. Strict cookies are essential for site functionality and
 *   should not penalize the score. Advertising cookies are invasive and
 *   should heavily penalize it. This function delegates to `classifyCookie()`,
 *   which combines heuristic rules with the optional ML model to produce
 *   a category label. Without classification, the scoring system would have
 *   no way to differentiate a session ID cookie from a cross-site tracking
 *   cookie.
 * HOW IT WORKS: Passes the cookie, current hostname, privacy database, and ML
 *   model to `classifyCookie()` (defined externally). Returns the classification
 *   result which includes `.cat` (category label).
 * INPUT: cookie (Object) — a cookie object with `name`, `domain`, etc.
 * OUTPUT: `{ cat: string }` — category label (Strict, Performance, Functionality,
 *   Advertising, or Unknown).
 */
function widgetClassify(cookie) {
  return classifyCookie(cookie, location.hostname, PRIVACY_DB, ML);
}

/**
 * widgetComputeScore: Compute a 0–100 privacy score for a tab based on its
 *   cookies, penalizing invasive tracking cookies.
 * WHY IT EXISTS: The widget displays a single score that represents the
 *   privacy health of the current page. This score must be derived from the
 *   actual cookies present, weighted by their category (Advertising > Functionality
 *   > Strict), persistence (persistent > session), first-party status
 *   (third-party > first-party), and blocklist membership. Without this
 *   function, the widget would have no data to display, and users would have
 *   no way to compare privacy across sites.
 * HOW IT WORKS:
 *   1. If no cookies, returns score 100 ("Excellent").
 *   2. For each cookie:
 *      a. Classifies it via `widgetClassify()` to get the category.
 *      b. Determines first-party vs third-party via `getCookieOrigin()`.
 *      c. Gets persistence info via `widgetGetCookiePersistence()`.
 *      d. Computes a base weight `w` based on category + party + persistence:
 *         - Strict/Performance: w=0 (no penalty)
 *         - Functionality: w=1-4 (first-party persistent=3, third-party persistent=4)
 *         - Advertising: w=2-6 (highest for third-party persistent)
 *         - Unknown: w=0-4
 *      e. Computes a lifetime multiplier `l`: persistent third-party < 7 days = 1x,
 *         > 30 days = 2x; first-party persistent > 60 days = 2x.
 *      f. Computes a blocklist multiplier `b`: high-risk third-party = 2x.
 *      g. Accumulates penalty = w × l × b.
 *   3. Final score = max(0, 100 - total_penalty).
 *   4. Maps score to a label: 0=Dangerous, <25=Critical, <50=Poor, <70=Fair,
 *      <90=Good, ≥100=Excellent.
 * INPUT: rawCookies (Array) — list of cookie objects.
 * OUTPUT: `{ score: number, label: string, total: number }`.
 */
function widgetComputeScore(rawCookies) {
  if (!rawCookies.length) return { score: 100, label: "Excellent", total: 0 };
  let penalty = 0;
  for (const cookie of rawCookies) {
    const cat = widgetClassify(cookie).cat;
    // TODO: request the top-level page URL from background.js for more accurate
    // iframe origin detection. Currently uses iframe hostname, which may misclassify
    // cookies in cross-origin iframes. See Requirement_Analysis_and_Documentation.md.
    const origin = getCookieOrigin(cookie.domain || "", location.hostname);
    const fp = origin === "First-party";
    const persistence = widgetGetCookiePersistence(cookie);
    const p = !persistence.isSession;
    const days = p ? (persistence.daysRemaining ?? 0) : 0;
    const dom = (cookie.domain || "").toLowerCase().replace(/^\./,"");
    let w = 0;
    if      (cat === "Strict")        w = 0;
    else if (cat === "Performance")   w = 0;
    else if (cat === "Functionality") w = fp ? (p ? 3 : 1) : (p ? 4 : 2);
    else if (cat === "Advertising")   w = fp ? (p ? 5 : 2) : (p ? 6 : 3);
    else                              w = fp ? (p ? 3 : 0) : (p ? 4 : 1);
    let l = 1;
    if (p) l = !fp ? (days < 7 ? 1 : days <= 30 ? 1.5 : 2) : (days <= 60 ? 1 : 2);
    const b = (!fp && widgetIsHighRisk(dom)) ? 2 : 1;
    penalty += w * l * b;
  }
  const score = Math.max(0, 100 - penalty);
  const label = score===0?"Dangerous":score<25?"Critical":score<50?"Poor":score<70?"Fair":score<90?"Good":"Excellent";
  return { score, label, total: rawCookies.length };
}

/**
 * widgetScoreColor: Map a privacy score to a border/text color hex value.
 * WHY IT EXISTS: The widget uses color-coding to give users instant visual
 *   feedback on privacy quality (red = dangerous, green = excellent). This
 *   function provides the border color, creating a clear visual hierarchy.
 * INPUT: score (number) — 0–100 privacy score.
 * OUTPUT: Hex color string (e.g., "#ff4d6e" for score 0).
 */
function widgetScoreColor(score) {
  return score===0?"#ff4d6e":score<25?"#ff7a35":score<50?"#ffb700":score<70?"#00aeff":"#00e5a0";
}

/**
 * widgetScoreBg: Map a privacy score to a background color hex value.
 * WHY IT EXISTS: Provides the widget's background tint, complementing the
 *   border color for a cohesive color scheme that communicates severity at a
 *   glance. Lighter tints ensure the text remains readable.
 * INPUT: score (number) — 0–100 privacy score.
 * OUTPUT: Hex color string (e.g., "#ffe0e6" for score 0).
 */
function widgetScoreBg(score) {
  return score===0?"#ffe0e6":score<25?"#ffe8d9":score<50?"#fff4cc":score<70?"#d9f0ff":"#d9fff0";
}

/**
 * widgetScoreText: Map a privacy score to a text color hex value.
 * WHY IT EXISTS: Provides the score number's text color, ensuring WCAG
 *   contrast compliance against the background color from `widgetScoreBg()`.
 * INPUT: score (number) — 0–100 privacy score.
 * OUTPUT: Hex color string (e.g., "#b3001a" for score 0).
 */
function widgetScoreText(score) {
  return score===0?"#b3001a":score<25?"#b34000":score<50?"#806600":score<70?"#005c8a":"#00805a";
}

/**
 * applyWidgetPosition: Apply the saved or default position to the widget
 *   element using CSS `!important` overrides.
 * WHY IT EXISTS: The widget is a fixed-position floating element that the user
 *   can drag. Its position must be restored from `chrome.storage.local` on
 *   load (for persistence across page loads) or defaulted to top-right. This
 *   function ensures the widget appears in the correct location regardless of
 *   how the page's own styles might try to position it. Without `!important`
 *   overrides, page stylesheets could relocate the widget to unexpected
 *   positions.
 * HOW IT WORKS:
 *   1. If `widgetPos` exists (user has dragged the widget), sets `top` and
 *      `left` to the saved coordinates, and `right: auto`.
 *   2. Otherwise, applies defaults: `top: 88px`, `right: 18px`, `left: auto`.
 * INPUT: None (reads globals `widgetEl`, `widgetPos`).
 * OUTPUT: Modifies `widgetEl`'s inline styles.
 */
function applyWidgetPosition() {
  if (!widgetEl) return;
  if (widgetPos) {
    widgetEl.style.setProperty("top", widgetPos.y + "px", "important");
    widgetEl.style.setProperty("right", "auto", "important");
    widgetEl.style.setProperty("left", widgetPos.x + "px", "important");
  } else {
    widgetEl.style.setProperty("top", "88px", "important");
    widgetEl.style.setProperty("right", "18px", "important");
    widgetEl.style.setProperty("left", "auto", "important");
  }
}

/**
 * ensureWidget: Create the floating score widget DOM element if it doesn't
 *   exist, set up drag behavior, and attach it to the page.
 * WHY IT EXISTS: The widget is the primary user-facing element of the
 *   extension — a draggable floating circle showing the privacy score. It
 *   must be created once, positioned correctly, and made interactive (draggable,
 *   clickable to open side panel). This function encapsulates the entire widget
 *   lifecycle: DOM creation, style injection, position restoration from storage,
 *   drag-and-drop event handling, hover animations, and click-to-toggle-panel.
 *   Without this function, the widget would not exist and users would have no
 *   visual indicator of privacy quality.
 * HOW IT WORKS:
 *   1. Guards: returns null if widget is disabled, not top frame, or already exists.
 *   2. Creates a `<button>` element with fixed positioning, circular shape (64x64px),
 *      z-index of 2147483645 (near max), and three child spans (title, score value, badge).
 *   3. Restores position from `chrome.storage.local` and applies it.
 *   4. Sets up mousedown/mousemove/mouseup for drag behavior with a 3px threshold
 *      to distinguish clicks from drags.
 *   5. Persists new position to storage on drag end.
 *   6. Adds hover animations (subtle translateY + scale).
 *   7. On click (not drag), sends `TOGGLE_SIDEPANEL` to open the side panel.
 *   8. Appends to `document.body` or `document.documentElement`.
 * INPUT: None (reads globals `widgetEnabled`, `IS_TOP_FRAME`, `widgetEl`).
 * OUTPUT: Returns the created `widgetEl` Element, or null if not created.
 */
function ensureWidget() {
  if (!widgetEnabled || !IS_TOP_FRAME) return null;
  if (widgetEl) return widgetEl;
  if (!document.body && !document.documentElement) return null;

  widgetEl = document.createElement("button");
  widgetEl.id = "cc-score-widget";
  widgetEl.type = "button";
  widgetEl.setAttribute("style", `
    position:fixed!important;right:18px!important;top:88px!important;z-index:2147483645!important;
    width:64px!important;height:64px!important;border-radius:999px!important;
    border:3px solid #ffffff!important;background:#ffffff!important;color:#333333!important;
    box-shadow:none!important;outline:none!important;cursor:grab!important;
    display:flex!important;align-items:center!important;justify-content:center!important;
    flex-direction:column!important;padding:0!important;font-family:'JetBrains Mono',monospace!important;
    transition:transform .16s ease, border-color .16s ease!important;
    line-height:1!important;text-rendering:optimizeLegibility!important;
    opacity:1!important;visibility:visible!important;overflow:visible!important;
    pointer-events:auto!important;appearance:none!important;-webkit-appearance:none!important;
  `);
  widgetEl.innerHTML = `
    <span id="cc-score-widget-title" style="font-size:7px!important;letter-spacing:.06em!important;line-height:1!important">Web Score:</span>
    <span id="cc-score-widget-value" style="font-size:18px!important;font-weight:700!important;line-height:1!important">--</span>
    <span id="cc-score-widget-badge" style="display:none!important;position:absolute!important;top:-6px!important;right:-6px!important;background:#ff4d6e!important;color:#fff!important;border-radius:999px!important;padding:2px 6px!important;font-size:9px!important;font-weight:700!important;border:2px solid #ffffff!important">+0</span>
  `;

  chrome.storage.local.get({ widgetPos: null }, res => {
    widgetPos = res.widgetPos || null;
    applyWidgetPosition();
  });

  let dragOffsetX = 0, dragOffsetY = 0, dragStartX = 0, dragStartY = 0;

  widgetEl.addEventListener("mousedown", (e) => {
    e.stopPropagation();
    widgetDragging = true;
    widgetDragMoved = false;
    const rect = widgetEl.getBoundingClientRect();
    dragOffsetX = e.clientX - rect.left;
    dragOffsetY = e.clientY - rect.top;
    dragStartX = e.clientX;
    dragStartY = e.clientY;
    widgetEl.style.cursor = "grabbing";
  });

  _onWidgetMouseMove = (e) => {
    if (!widgetDragging) return;
    const dx = Math.abs(e.clientX - dragStartX);
    const dy = Math.abs(e.clientY - dragStartY);
    if (dx > 3 || dy > 3) widgetDragMoved = true;
    if (!widgetDragMoved) return;

    let newX = e.clientX - dragOffsetX;
    let newY = e.clientY - dragOffsetY;

    const w = widgetEl.offsetWidth || 64;
    const h = widgetEl.offsetHeight || 64;
    newX = Math.max(0, Math.min(newX, window.innerWidth - w));
    newY = Math.max(0, Math.min(newY, window.innerHeight - h));

    widgetEl.style.setProperty("left", newX + "px", "important");
    widgetEl.style.setProperty("top", newY + "px", "important");
    widgetEl.style.setProperty("right", "auto", "important");
  };
  document.addEventListener("mousemove", _onWidgetMouseMove);

  _onWidgetMouseUp = () => {
    if (!widgetDragging) return;
    widgetDragging = false;
    widgetEl.style.cursor = "grab";
    if (!widgetDragMoved) return;

    const rect = widgetEl.getBoundingClientRect();
    widgetPos = { x: rect.left, y: rect.top };
    chrome.storage.local.set({ widgetPos });
  };
  document.addEventListener("mouseup", _onWidgetMouseUp);

  widgetEl.addEventListener("mouseenter", () => { if (!widgetDragging) widgetEl.style.transform = "translateY(-1px) scale(1.03)"; });
  widgetEl.addEventListener("mouseleave", () => { if (!widgetDragging) widgetEl.style.transform = "none"; });
  widgetEl.addEventListener("click", (e) => {
    if (widgetDragMoved) { widgetDragMoved = false; e.stopPropagation(); return; }
    try {
      chrome.runtime.sendMessage({ type: "TOGGLE_SIDEPANEL" });
    } catch(err) { console.warn("[CC]", err.message); }
  });
  (document.body || document.documentElement).appendChild(widgetEl);
  return widgetEl;
}

/**
 * updateWidgetPanelState: Reposition the widget when the side panel opens or
 *   closes to prevent overlap.
 * WHY IT EXISTS: The extension's side panel occupies 400px on the right side
 *   of the viewport. If the widget is positioned in that area, it would be
 *   obscured by the panel. This function moves the widget to the left when the
 *   panel opens, and restores its original position when the panel closes.
 *   Without this, the widget would be hidden behind the panel, making the
 *   score invisible while the user is interacting with the panel.
 * HOW IT WORKS:
 *   1. If opening: checks if the widget overlaps the panel area. If so, saves
 *      the current position in `prePanelWidgetPos` and moves the widget left
 *      by at least 64px + 18px gap from the panel edge.
 *   2. If closing: restores the saved position from `prePanelWidgetPos` and
 *      clears it.
 * INPUT: isOpen (boolean) — true if the side panel is opening.
 * OUTPUT: Modifies widget position and updates `prePanelWidgetPos`.
 */
function updateWidgetPanelState(isOpen) {
  if (!widgetEnabled || !IS_TOP_FRAME) return;
  const el = ensureWidget();
  if (!el) return;

  widgetPanelOpen = !!isOpen;

  if (isOpen) {
    const rect = el.getBoundingClientRect();
    const sidepanelLeft = window.innerWidth - 400;
    const widgetRight = rect.left + (el.offsetWidth || 64);

    if (widgetRight > sidepanelLeft) {
      if (!prePanelWidgetPos) {
        prePanelWidgetPos = widgetPos
          ? { x: widgetPos.x, y: widgetPos.y }
          : { x: rect.left, y: rect.top };
      }
      const gap = 18;
      const newLeft = Math.max(0, sidepanelLeft - 64 - gap);
      el.style.setProperty("left", newLeft + "px", "important");
      el.style.setProperty("top", rect.top + "px", "important");
      el.style.setProperty("right", "auto", "important");
    }
  } else {
    if (prePanelWidgetPos) {
      widgetPos = { x: prePanelWidgetPos.x, y: prePanelWidgetPos.y };
      prePanelWidgetPos = null;
      applyWidgetPosition();
    }
  }
}

/**
 * updateWidgetBadge: Show a temporary "+N" badge on the widget indicating new
 *   cookies were detected since the last refresh.
 * WHY IT EXISTS: When the cookie count increases between widget refreshes (e.g.,
 *   a CMP sets new tracking cookies after the page loads), the user should be
 *   alerted. A "+N" badge provides a visual nudge that something changed without
 *   disrupting the score display. The badge auto-hides after 2.6 seconds to
 *   avoid clutter. Without this, users would miss late-arriving cookies and
 *   assume the score is static.
 * HOW IT WORKS:
 *   1. Guards: returns if disabled, not top frame, no delta > 0, or no widget.
 *   2. Sets badge text to `+${delta}` and makes it visible.
 *   3. Clears any previous auto-hide timer.
 *   4. Sets a new 2600ms timer to hide the badge.
 * INPUT: delta (number) — how many new cookies were detected.
 * OUTPUT: Shows/hides the badge element. Sets/clears `widgetNewBadgeTimer`.
 */
function updateWidgetBadge(delta) {
  if (!widgetEnabled || !IS_TOP_FRAME) return;
  const hostEl = ensureWidget();
  const badge = hostEl?.querySelector("#cc-score-widget-badge");
  if (!badge || delta <= 0) return;
  badge.textContent = `+${delta}`;
  badge.style.display = "inline-flex";
  clearTimeout(widgetNewBadgeTimer);
  widgetNewBadgeTimer = setTimeout(() => {
    badge.style.display = "none";
  }, 2600);
}

/**
 * applyWidgetScore: Apply a computed score result to the widget's visual
 *   appearance (colors, score text, badge).
 * WHY IT EXISTS: The widget's visual state must match the computed privacy
 *   score. This function translates the abstract score number into concrete
 *   visual properties: border color, background color, text color, and the
 *   displayed score number. It also triggers the "+N" badge if new cookies
 *   were detected. Without this, the widget would display stale or default
 *   values regardless of the actual score.
 * HOW IT WORKS:
 *   1. Guards: returns if disabled, not top frame, or no widget.
 *   2. Calls `widgetScoreColor()`, `widgetScoreBg()`, `widgetScoreText()` to
 *      get the color scheme.
 *   3. Applies colors to the widget element's style.
 *   4. Updates the score value text.
 *   5. If delta > 0, calls `updateWidgetBadge(delta)`.
 * INPUT: result (Object) — `{ score: number, label: string, total: number }`.
 *        delta (number) — number of new cookies since last refresh.
 * OUTPUT: Modifies widget DOM styles and text content.
 */
function applyWidgetScore(result, delta) {
  if (!widgetEnabled || !IS_TOP_FRAME) return;
  const el = ensureWidget();
  if (!el) return;
  const color = widgetScoreColor(result.score);
  el.style.borderColor = color;
  el.style.color = widgetScoreText(result.score);
  el.style.background = widgetScoreBg(result.score);
  el.querySelector("#cc-score-widget-value").textContent = String(result.score);
  if (delta > 0) updateWidgetBadge(delta);
}

/**
 * refreshWidget: Fetch the latest cookie state and score for the current tab,
 *   then update the widget display.
 * WHY IT EXISTS: The widget must reflect the current privacy state, which
 *   changes as scripts set new cookies. This function either uses a provided
 *   cookie snapshot (for instant updates after local changes) or requests the
 *   latest state from the background script via `GET_TAB_WIDGET_STATE`. It
 *   also computes the delta (new cookies since last refresh) for the badge.
 *   Without this, the widget score would be stale and not reflect
 *   dynamically-set cookies.
 * HOW IT WORKS:
 *   1. Guards: returns if disabled, not top frame, or no widget.
 *   2. If `cookiesSnapshot` is provided (an array), computes score locally via
 *      `widgetComputeScore()` and updates the widget directly.
 *   3. Otherwise, sends `GET_TAB_WIDGET_STATE` to the background, which returns
 *      the pre-computed score, label, and cookie list for the tab.
 *   4. Computes delta = new cookies - last known count (for badge display).
 *   5. Calls `applyWidgetScore()` with the result and delta.
 * INPUT: cookiesSnapshot (Array|null) — optional pre-fetched cookie array.
 * OUTPUT: Updates widget display via `applyWidgetScore()`.
 */
function refreshWidget(cookiesSnapshot = null) {
  if (!widgetEnabled || !IS_TOP_FRAME) return;
  if (!ensureWidget()) return;
  if (Array.isArray(cookiesSnapshot)) {
    const cookies = cookiesSnapshot;
    const delta = lastWidgetCookieCount > 0 && cookies.length > lastWidgetCookieCount
      ? cookies.length - lastWidgetCookieCount
      : 0;
    lastWidgetCookieCount = cookies.length;
    applyWidgetScore(widgetComputeScore(cookies), delta);
    return;
  }
  chrome.runtime.sendMessage({ type: "GET_TAB_WIDGET_STATE" }, resp => {
    if (chrome.runtime.lastError || !resp) return;
    if (Number.isInteger(resp.tabId)) currentTabId = resp.tabId;
    const cookies = Array.isArray(resp.cookies) ? resp.cookies : [];
    const delta = lastWidgetCookieCount > 0 && cookies.length > lastWidgetCookieCount
      ? cookies.length - lastWidgetCookieCount
      : 0;
    lastWidgetCookieCount = cookies.length;
    applyWidgetScore({ score: resp.score ?? 100, label: resp.scoreLabel ?? "Excellent", total: cookies.length }, delta);
  });
}

let overlayEl = null;
let overlayHostEl = null;
let lastConsentAction = null;
let consentBypassUntil = 0;
let lastConsentTrigger = "manual";
let pendingBlockedConsentTarget = null;
let pendingBlockedConsentUntil = 0;
const remoteConsentActions = new Map();

/**
 * escapeHtml: Escape special HTML characters to prevent XSS when injecting
 *   user-controlled text into the consent overlay.
 * WHY IT EXISTS: The consent overlay is built via `innerHTML` assignment with
 *   string interpolation. If any cookie names, domain names, or tracker
 *   identifiers contain HTML metacharacters (<, >, &, ", '), they could break
 *   the layout or execute injected scripts. This is a standard XSS mitigation
 *   required whenever untrusted content is inserted into HTML via string
 *   concatenation. Without it, a malicious cookie name like `<img src=x onerror=alert(1)>`
 *   could execute arbitrary code in the overlay.
 * HOW IT WORKS: Replaces the five HTML-significant characters with their entity
 *   equivalents: & → &amp;, < → &lt;, > → &gt;, " → &quot;, ' → &#39;.
 * INPUT: text (string) — the raw text to escape.
 * OUTPUT: Escaped string safe for HTML interpolation.
 * Source: OWASP XSS Prevention Cheat Sheet — "HTML Entity Encoding" section.
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
 * simpleRegistrableDomain: Extract the registrable domain (eTLD+1) from a
 *   hostname using a simplified two-part heuristic.
 * WHY IT EXISTS: Cookie domains often include subdomains (e.g.,
 *   `ads.example.com`), but tracker identification requires matching at the
 *   registrable domain level (`example.com`). A full public suffix list lookup
 *   would be ideal but adds complexity and data size. This simplified approach
 *   assumes the last two parts of the domain form the registrable domain, which
 *   works for the vast majority of domains (excluding compound TLDs like
 *   `co.uk`, which are rare enough to not significantly affect detection).
 *   Without domain normalization, `ads.example.com` and `tracker.example.com`
 *   would be treated as separate entities, fragmenting the tracker database.
 * HOW IT WORKS: Strips `www.` prefix and leading dots, splits on `.`, and
 *   returns the last two segments joined by `.`. For domains with ≤2 parts,
 *   returns the full domain.
 * INPUT: host (string) — a hostname (e.g., "ads.example.com").
 * OUTPUT: Registrable domain string (e.g., "example.com").
 */
function simpleRegistrableDomain(host) {
  const clean = String(host || "").toLowerCase().replace(/^www\./, "").replace(/^\./, "");
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  return parts.slice(-2).join(".");
}

/**
 * trackerHitForHost: Look up a hostname in the tracker domain database and
 *   return the matching tracker entry (vendor name, category).
 * WHY IT EXISTS: The consent overlay needs to identify which scripts on the
 *   page are known trackers, and categorize them (Advertising, Performance,
 *   etc.). This function performs the lookup by checking both the exact hostname
 *   and its registrable domain against `TRACKER_DOMAINS`. Without it, the
 *   overlay could not show accurate vendor information or category breakdowns.
 * HOW IT WORKS:
 *   1. Normalizes the hostname (strips `www.`, leading dots, lowercases).
 *   2. Computes the registrable domain via `simpleRegistrableDomain()`.
 *   3. Looks up both the exact hostname and the registrable domain in
 *      `TRACKER_DOMAINS`.
 *   4. Returns `{ hit: trackerEntry|null, fallbackName: registrableDomain,
 *      domain: matchedKey }` — `domain` is the exact database key that
 *      matched (exact hostname first, else registrable domain), so the
 *      overlay can display the actual domain row each verdict rests on.
 * INPUT: host (string) — a hostname to look up.
 * OUTPUT: `{ hit: Object|null, fallbackName: string, domain: string }`
 *   where `hit` contains `vendor`, `vendor_norm`, and `cat` fields if
 *   found, and `domain` is the matched database key ("" when no match).
 */
function trackerHitForHost(host) {
  const clean = String(host || "").toLowerCase().replace(/^www\./, "").replace(/^\./, "");
  const reg = simpleRegistrableDomain(clean);
  const matched = TRACKER_DOMAINS[clean] ? clean : (TRACKER_DOMAINS[reg] ? reg : null);
  return {
    hit: matched ? TRACKER_DOMAINS[matched] : null,
    fallbackName: reg,
    domain: matched || "",
  };
}

/**
 * extractDomainsFromInlineScript: Extract hostnames referenced in inline
 *   JavaScript code, from both URLs and bare domain patterns.
 * WHY IT EXISTS: Many tracking scripts are loaded via inline JavaScript that
 *   references third-party domains (e.g., `fetch("https://tracker.example.com/collect")`,
 *   or `"https://cdn.analytics.com/script.js"`). These domains indicate
 *   potential trackers even when loaded indirectly. Without extracting domains
 *   from inline scripts, the overlay would only identify trackers loaded via
 *   `<script src>` tags, missing a significant class of tracking that happens
 *   through dynamically-created network requests.
 * HOW IT WORKS:
 *   1. Extracts full URLs via regex (`https?://...`) and parses them with
 *      `new URL()` to get hostnames.
 *   2. Extracts bare domain patterns via regex (`word.word.tld`) and filters
 *      out file extensions (.js, .css, .png, etc.) to avoid false positives.
 *   3. Deduplicates and returns the sorted list.
 * INPUT: text (string) — the text content of an inline `<script>` element.
 * OUTPUT: Array of unique hostname strings.
 */
function extractDomainsFromInlineScript(text) {
  const domains = new Set();
  const raw = String(text || "");
  const urlRe = /https?:\/\/[^\s"'<>`\\)]+/gi;
  const domainRe = /\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi;

  for (const match of raw.matchAll(urlRe)) {
    try {
      domains.add(new URL(match[0]).hostname.toLowerCase().replace(/^www\./, ""));
    } catch(e) { console.warn("[CC]", e.message); }
  }

  for (const match of raw.matchAll(domainRe)) {
    const host = match[0].toLowerCase().replace(/^www\./, "");
    if (!/\.(js|css|png|jpg|jpeg|gif|svg|webp|ico|json|xml|woff|woff2|ttf|eot|map|min|ts|tsx|vue|svelte)$/i.test(host)) {
      domains.add(host);
    }
  }

  return [...domains];
}

/**
 * addVendorEstimate: Add a detected tracker record to the vendors list,
 *   deduplicated by record identity.
 * WHY IT EXISTS: The same database record is looked up many times per page
 *   (every script src, every inline-script domain, subdomains resolving to
 *   the same registrable key). Without deduplication the overlay would
 *   double-count rows and inflate the apparent number of trackers. Each
 *   entry this function creates is ONE cookie_db.json record, copied
 *   verbatim — fields are never borrowed or combined across records, so the
 *   overlay can only ever display rows that exist in the database.
 * HOW IT WORKS:
 *   1. If no `hit` (tracker lookup result), returns immediately.
 *   2. If this exact record object was already seen this scan, returns
 *      (identity dedupe: TRACKER_DOMAINS is the live cookie_db.json object,
 *      so every lookup of the same row returns the same reference).
 *   3. Otherwise marks the record seen and pushes `{ name, domain, cat,
 *      high_risk, wtm_cat, disconnect_cat }` copied straight from that one
 *      record — plus `domain`, the exact database key matched (for display
 *      disambiguation: `Meta (facebook.net)` vs `Meta (facebook.com)`).
 *      No merge, no field synthesis, no ranking against other records.
 *      These fields are required by `evaluatePage()`.
 * INPUT: vendors (Array) — accumulator for detected vendor objects.
 *        found (Set) — seen DB record references (identity dedupe).
 *        hit (Object|null) — one tracker database record with `vendor`,
 *          `cat`, and optionally `high_risk`, `wtm_cat`, `disconnect_cat`.
 *        fallbackName (string) — fallback vendor name from domain lookup.
 *        domain (string) — matched database key (`trackerHitForHost`).
 * OUTPUT: Mutates `vendors` and `found`.
 */
function addVendorEstimate(vendors, found, hit, fallbackName, domain) {
  if (!hit || found.has(hit)) return;
  found.add(hit);
  vendors.push({
    name: hit.vendor || fallbackName,
    domain: domain || "",
    cat: hit.cat || "Unknown",
    high_risk: !!hit.high_risk,
    wtm_cat: hit.wtm_cat || "",
    disconnect_cat: hit.disconnect_cat || "",
  });
}

/**
 * removeOverlay: Remove the consent overlay from the DOM and reset all
 *   overlay-related state.
 * WHY IT EXISTS: The overlay must be cleanly removed when the user clicks
 *   "Go back", "Accept anyway", or the close button. This function ensures
 *   complete cleanup: DOM removal, state reset (last consent action, trigger
 *   type, banner visibility), and background notification. Without complete
 *   cleanup, stale state could prevent the overlay from showing again on the
 *   next consent event, or leave orphaned DOM elements.
 * HOW IT WORKS:
 *   1. Removes `overlayHostEl` (which contains `overlayEl`) from the DOM.
 *   2. Falls back to removing `overlayEl` directly if no host element.
 *   3. Nulls both element references.
 *   4. Resets `lastConsentAction`, `lastConsentTrigger`, and `lastState`.
 *   5. Notifies the background script that the banner is no longer visible.
 * INPUT: None (operates on global overlay state).
 * OUTPUT: Removes overlay DOM elements and resets state variables.
 */
function removeOverlay() {
  if (overlayHostEl) overlayHostEl.remove();
  else if (overlayEl) overlayEl.remove();
  overlayHostEl = null;
  overlayEl = null;
  lastConsentAction = null;
  lastConsentTrigger = "manual";
  lastState = false;
  notifyBannerState(false);
}

/**
 * notifyBannerState: Notify the background script whether the consent overlay
 *   is currently visible.
 * WHY IT EXISTS: The background script needs to track overlay visibility state
 *   across tabs for features like badge updates, popup menu state, and
 *   analytics. Without this notification, the background would have no way to
 *   know when the overlay is shown or dismissed, breaking tab-specific state
 *   management.
 * HOW IT WORKS: Sends a `BANNER_STATE_CHANGED` message with `{ bannerVisible }`
 *   to the background script. Uses `chrome.runtime.lastError` suppression to
 *   avoid console noise when the context is invalid.
 * INPUT: visible (boolean) — true if the overlay is now visible.
 * OUTPUT: Sends a Chrome runtime message.
 */
function notifyBannerState(visible) {
  try {
    chrome.runtime.sendMessage(
      { type: "BANNER_STATE_CHANGED", bannerVisible: !!visible },
      () => void chrome.runtime.lastError
    );
  } catch(e) { console.warn("[CC]", e.message); }
}


/**
 * getActionLabel: Extract a normalized text label from a clickable element by
 *   reading all possible text sources.
 * WHY IT EXISTS: Buttons can have their label in different places depending on
 *   how they are built: inner text, `value` attribute (for inputs), `aria-label`,
 *   `title`, or `alt` attribute. The consent interception system needs a single
 *   normalized label to match against accept/reject patterns. Without this
 *   unified extraction, some buttons would be missed because their label is only
 *   in an attribute (e.g., `<input value="Accept All">`) or ARIA label.
 * HOW IT WORKS: Collects `innerText`, `textContent`, `value`, `aria-label`,
 *   `title`, and `alt` from the element, filters out nulls, joins with spaces,
 *   collapses whitespace, and lowercases.
 * INPUT: el (Element) — a clickable element (button, link, input).
 * OUTPUT: Lowercase trimmed string of the element's text label.
 */
function getActionLabel(el) {
  return [
    el?.innerText,
    el?.textContent,
    el?.value,
    el?.getAttribute?.("aria-label"),
    el?.getAttribute?.("title"),
    el?.getAttribute?.("alt")
  ].filter(Boolean).join(" ").replace(/\s+/g, " ").trim().toLowerCase();
}

/**
 * findActionableTarget: Walk up the DOM tree from a start element to find the
 *   nearest clickable ancestor (button, link, input, or role="button").
 * WHY IT EXISTS: Click events often target child elements (spans, icons, text
 *   nodes) within a button rather than the button itself. The consent
 *   interception system needs to identify the actual interactive element to
 *   read its label and replay the click. Without this traversal, a click on a
 *   `<span>` inside a button would not be recognized as a button click, causing
 *   consent events to slip through unintercepted.
 * HOW IT WORKS: Starting from the event target (or its parent if it's not an
 *   element), walks up to 6 ancestors. Returns the first element matching
 *   `button, a, input[type='button'], input[type='submit'], input[type='reset'],
 *   [role='button']`. Returns null if no actionable target is found.
 * INPUT: start (Node|EventTarget) — the initial element (usually `e.target`).
 * OUTPUT: Element|null — the actionable clickable ancestor.
 */
function findActionableTarget(start) {
  let el = start?.nodeType === 1 ? start : start?.parentElement;
  for (let depth = 0; el && depth < 6; depth += 1, el = el.parentElement) {
    if (el.matches?.("button, a, input[type='button'], input[type='submit'], input[type='reset'], [role='button']")) {
      return el;
    }
  }
  return null;
}

/**
 * findConsentContainer: Walk up the DOM tree to find the best candidate
 *   consent container element, scoring each ancestor by consent-banner
 *   indicators.
 * WHY IT EXISTS: A button click alone is not sufficient evidence that the user
 *   is interacting with a consent banner — the button could be in any dialog
 *   on the page. This function identifies the containing element (typically the
 *   CMP banner wrapper) and scores it based on multiple signals: banner-like
 *   text, cookie keywords, known CMP attribute names, banner geometry, dialog
 *   role, and the presence of both accept and reject buttons. Without this
 *   container detection, the extension could not distinguish a consent banner's
 *   "Accept" button from a form's "Submit" button.
 * HOW IT WORKS:
 *   1. Walks up to 7 ancestors from the start element.
 *   2. For each ancestor, computes a score based on:
 *      - `textMatchesBanner()` (+3)
 *      - Cookie/consent keywords in text (+2)
 *      - Cookie/consent keywords in attributes (+2)
 *      - Banner-like geometry (+1)
 *      - Dialog role/modal (+1)
 *      - Both accept and reject buttons present (+2), or one of them (+1)
 *   3. Returns the highest-scoring ancestor with its metadata.
 * INPUT: start (Node) — the starting element (usually a button).
 * OUTPUT: `{ el, score, hasReject, hasAccept, modalLike, bannerText,
 *   hasCookieWords, hasCookieAttrs }` or null if no container found with score ≥ 3.
 */
function findConsentContainer(start) {
  let el = start?.nodeType === 1 ? start : start?.parentElement;
  let best = null;
  for (let depth = 0; el && depth < 7; depth += 1, el = el.parentElement) {
    try {
      const text = (el.innerText || el.textContent || "").toLowerCase();
      const attrs = `${el.id || ""} ${el.className || ""} ${el.getAttribute?.("aria-label") || ""} ${el.getAttribute?.("title") || ""}`.toLowerCase();
      const rect = el.getBoundingClientRect?.() || { width:0, height:0, top:0, bottom:0 };
      const modalLike = !!el.matches?.("dialog, [role='dialog'], [aria-modal='true']");
      const bannerText = textMatchesBanner(text);
      const hasCookieWords = /\bcookie\b|\bconsent\b|\bprivacy\b|\bpreferences?\b|\btracking\b/.test(text);
      const hasCookieAttrs = /cookie|consent|privacy|preferences|onetrust|didomi|usercentrics|cookiebot|trustarc|sourcepoint|quantcast|osano|termly/.test(attrs);
      const bannerLike = isBannerLikeGeometry(rect);
      const btns = [...el.querySelectorAll("button, a[role=button], input[type=button], input[type=submit], [role=button]")];
      const btnText = btns.map(b => (b.innerText || b.textContent || b.value || "").toLowerCase()).join(" ");
      const hasReject = REJECT_PATTERNS.test(btnText);
      const hasAccept = ACCEPT_PATTERNS.test(btnText);

      let score = 0;
      if (bannerText) score += 3;
      if (hasCookieWords) score += 2;
      if (hasCookieAttrs) score += 2;
      if (bannerLike) score += 1;
      if (modalLike) score += 1;
      if (hasAccept && hasReject) score += 2;
      else if (hasAccept || hasReject) score += 1;

      if (!best || score > best.score) {
        best = { el, score, hasReject, hasAccept, modalLike, bannerText, hasCookieWords, hasCookieAttrs };
      }
    } catch(e) { console.warn("[CC]", e.message); }
  }
  return best;
}

/**
 * consentContextScore: Score the surrounding DOM context of a button to
 *   determine if it is within a consent-related UI.
 * WHY IT EXISTS: Even if `findConsentContainer()` identifies a container, the
 *   button's broader context provides additional confidence. This function
 *   walks up to 5 ancestors and accumulates points for banner-matching text,
 *   cookie keywords, consent-related attributes, dialog roles, and banner
 *   geometry. The resulting score helps `inspectConsentAcceptAction()` decide
 *   whether a button click warrants interception. Without context scoring,
 *   the system would only know about the immediate container, missing important
 *   signals from grandparent elements.
 * HOW IT WORKS: Walks up to 5 ancestors, accumulating points for:
 *   - `textMatchesBanner()` (+2)
 *   - Cookie/consent keywords in text (+1)
 *   - Consent-related attributes (+1)
 *   - Dialog role (+1)
 *   - Banner-like geometry (+1)
 * INPUT: el (Element) — the button element to contextualize.
 * OUTPUT: `number` — cumulative context score (0–7).
 */
function consentContextScore(el) {
  let score = 0;
  let current = el;
  for (let depth = 0; current && depth < 5; depth += 1, current = current.parentElement) {
    try {
      const text = (current.innerText || current.textContent || "").toLowerCase();
      const attrs = `${current.id || ""} ${current.className || ""} ${current.getAttribute?.("aria-label") || ""} ${current.getAttribute?.("title") || ""}`.toLowerCase();
      if (textMatchesBanner(text)) score += 2;
      if (/\bcookie\b|\bconsent\b|\bprivacy\b|\bpreferences?\b/.test(text)) score += 1;
      if (/cookie|consent|privacy|preferences|policy|settings/.test(attrs)) score += 1;
      if (current.matches?.("dialog, [role='dialog'], [aria-modal='true']")) score += 1;
      if (isBannerLikeGeometry(current.getBoundingClientRect?.() || { width:0, height:0, top:0, bottom:0 })) score += 1;
    } catch(e) { console.warn("[CC]", e.message); }
  }
  return score;
}

/**
 * inspectConsentAcceptAction: Determine if a click target is a consent
 *   "Accept" button that should be intercepted by the overlay.
 * WHY IT EXISTS: This is the core decision function of the consent interception
 *   system. It combines multiple detection signals — button label matching,
 *   context scoring, container detection, and accept/reject pattern strength —
 *   to decide whether a click warrants showing the consent overlay. The
 *   function must be conservative: false positives (intercepting non-consent
 *   clicks) degrade user trust, while false negatives (missing consent clicks)
 *   defeat the extension's purpose. The multi-layered approach (label →
 *   context → container → pattern strength) ensures robustness.
 * HOW IT WORKS:
 *   1. Finds the actionable target via `findActionableTarget()`.
 *   2. Gets its label via `getActionLabel()`. If it doesn't match
 *      `ACCEPT_PATTERNS`, returns null.
 *   3. Computes `consentContextScore()`.
 *   4. Finds the consent container via `findConsentContainer()`. If container
 *      score < 3, returns null.
 *   5. Classifies the accept pattern as strong or weak.
 *   6. Applies acceptance criteria:
 *      - "Strong enough": strong pattern + explicit cookie context + container
 *        score ≥ 3 or modal.
 *      - "Weaker enough": weak pattern + explicit cookie context + both
 *        accept/reject buttons + container score ≥ 5.
 *   7. Returns the inspection result or null if criteria not met.
 * INPUT: start (Node) — the event target element.
 * OUTPUT: `{ target, label, context, strong, containerScore }` or null.
 */
function inspectConsentAcceptAction(start) {
  const target = findActionableTarget(start);
  if (!target) return null;
  const label = getActionLabel(target);
  if (!label || !ACCEPT_PATTERNS.test(label)) return null;

  const context = consentContextScore(target);
  const container = findConsentContainer(target);
  if (!container || container.score < 3) return null;

  const strong = STRONG_ACCEPT_PATTERNS.test(label);
  const weak = WEAK_ACCEPT_PATTERNS.test(label);
  const modalLike = !!target.closest?.("dialog, [role='dialog'], [aria-modal='true']") || container.modalLike;
  const explicitCookieContext = container.bannerText || container.hasCookieWords || container.hasCookieAttrs;

  const strongEnough = strong && explicitCookieContext && (container.score >= 3 || modalLike);
  const weakerEnough = weak && explicitCookieContext && container.hasReject && container.score >= 5;

  if (!strongEnough && !weakerEnough) return null;
  return { target, label, context, strong: strongEnough, containerScore: container.score };
}

/**
 * replayConsentAction: Replay the blocked consent click after the user
 *   explicitly confirms via the overlay.
 * WHY IT EXISTS: When the consent overlay intercepts a click on an "Accept
 *   All" button, it pauses the event and shows the overlay. If the user clicks
 *   "Accept anyway", this function dispatches the original click event to
 *   complete the consent action. Without it, the user's consent choice would be
 *   lost — the overlay would dismiss but the CMP would never receive the click,
 *   potentially leaving the user in a broken state with no cookies set.
 * HOW IT WORKS:
 *   1. If the last action was a remote (iframe) action, sends a
 *      `CC_REPLAY_CONSENT_ACTION` postMessage to the iframe's window.
 *   2. Otherwise, sets a 2500ms bypass window (`consentBypassUntil`) to prevent
 *      the overlay from re-intercepting the replayed click.
 *   3. Clears the blocked consent target state.
 *   4. Removes the overlay.
 *   5. In a `setTimeout(0)`, dispatches the full mouse event sequence
 *      (pointerdown → mousedown → mouseup → click) on the original target
 *      to simulate a real user interaction.
 * INPUT: None (reads `lastConsentAction` global).
 * OUTPUT: Dispatches mouse events on the original consent button.
 */
function replayConsentAction() {
  if (lastConsentAction?.remoteActionId) {
    const remote = remoteConsentActions.get(lastConsentAction.remoteActionId);
    if (remote?.sourceWindow) {
      try {
        remote.sourceWindow.postMessage({
          source: "CookieCrumbs",
          type: "CC_REPLAY_CONSENT_ACTION",
          actionId: lastConsentAction.remoteActionId,
        }, "*");
      } catch(e) { console.warn("[CC]", e.message); }
    }
    consentBypassUntil = Date.now() + 2500;
    pendingBlockedConsentTarget = null;
    pendingBlockedConsentUntil = 0;
    removeOverlay();
    return;
  }

  const target = lastConsentAction?.target;
  if (!target) return;
  consentBypassUntil = Date.now() + 2500;
  pendingBlockedConsentTarget = null;
  pendingBlockedConsentUntil = 0;
  removeOverlay();
  setTimeout(() => {
    try {
      target.dispatchEvent(new MouseEvent("pointerdown", { bubbles:true, cancelable:true, view:window, buttons:1 }));
      target.dispatchEvent(new MouseEvent("mousedown", { bubbles:true, cancelable:true, view:window, buttons:1 }));
      target.dispatchEvent(new MouseEvent("mouseup", { bubbles:true, cancelable:true, view:window, buttons:0 }));
      target.dispatchEvent(new MouseEvent("click", { bubbles:true, cancelable:true, view:window }));
    } catch(e) { console.warn("[CC]", e.message); }
  }, 0);
}

/**
 * showConsentOverlay: Display the consent overlay for a detected consent
 *   action, handling both top-frame and iframe scenarios.
 * WHY IT EXISTS: This is the entry point for showing the consent interception
 *   overlay. It handles the complexity of cross-frame communication: if the
 *   consent button is in an iframe, it sends the overlay request to the top
 *   frame via postMessage. If in the top frame, it directly shows the overlay.
 *   It also optionally pauses the original click event (via `preventDefault()`
 *   and `stopPropagation()`) to prevent the CMP from receiving the click
 *   before the user sees the overlay. Without this function, the overlay
 *   could not be shown for iframe-based CMPs, and the click would go through
 *   before the user had a chance to review.
 * HOW IT WORKS:
 *   1. If `pauseAction` and an event is provided, prevents the event's default,
 *      stops propagation, and stops immediate propagation.
 *   2. If not the top frame, generates a unique `actionId`, stores the remote
 *      action, and sends a `CC_SHOW_CONSENT_OVERLAY` postMessage to `window.top`.
 *   3. If in the top frame, stores the consent action and trigger type, sets a
 *      bypass window if pausing, notifies the background of banner visibility,
 *      and calls `buildOverlay()`.
 * INPUT: info (Object) — `{ target, label, context, strong, remoteActionId }`.
 *        trigger (string) — "manual", "hover", "focus", or "remote".
 *        pauseAction (boolean) — whether to pause the original click event.
 *        event (Event) — the original DOM event to pause.
 * OUTPUT: Shows overlay DOM or sends cross-frame message.
 */
function showConsentOverlay(info, trigger = "manual", pauseAction = false, event = null) {
  if (!info) return;

  if (pauseAction && event) {
    try {
      if (event.cancelable) event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
    } catch(e) { console.warn("[CC]", e.message); }
  }

  if (!IS_TOP_FRAME) {
    const actionId = info.remoteActionId || `cc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    remoteConsentActions.set(actionId, { target: info.target });
    try {
      window.top?.postMessage({
        source: "CookieCrumbs",
        type: "CC_SHOW_CONSENT_OVERLAY",
        info: {
          label: info.label,
          context: info.context,
          strong: info.strong,
          remoteActionId: actionId,
        },
        trigger,
      }, "*");
    } catch(e) { console.warn("[CC]", e.message); }
    return;
  }

  lastConsentAction = info;
  lastConsentTrigger = trigger;
  lastState = true;
  if (pauseAction) {
    consentBypassUntil = Date.now() + 700;
    pendingBlockedConsentTarget = info.target || null;
    pendingBlockedConsentUntil = Date.now() + 1400;
  }
  notifyBannerState(true);
  buildOverlay();
}

/**
 * isBlockedConsentFollowUpEvent: Check if a DOM event is a follow-up event
 *   (mouseup, click) that should be suppressed because the original pointerdown
 *   was already intercepted.
 * WHY IT EXISTS: When the consent overlay intercepts a pointerdown event on an
 *   "Accept" button, it pauses the action. However, the browser still fires
 *   subsequent mouseup and click events as part of the normal click sequence.
 *   If these follow-through events are not also blocked, they could trigger the
 *   CMP's click handler through event bubbling, bypassing the interception.
 *   This function identifies these orphaned follow-up events so they can be
 *   swallowed. Without it, the interception would be incomplete — the overlay
 *   would show, but the CMP would still receive the click event.
 * HOW IT WORKS:
 *   1. If the bypass timer has expired, clears the pending state and returns false.
 *   2. If no pending target, returns false.
 *   3. Gets the actionable target from the event's composed path.
 *   4. Returns true only if the actionable target matches the pending blocked target.
 * INPUT: e (Event) — a mouseup or click event.
 * OUTPUT: `boolean` — true if this event should be suppressed.
 */
function isBlockedConsentFollowUpEvent(e) {
  if (Date.now() >= pendingBlockedConsentUntil) {
    pendingBlockedConsentTarget = null;
    pendingBlockedConsentUntil = 0;
    return false;
  }

  if (!pendingBlockedConsentTarget) return false;
  const start = e.composedPath?.()[0] || e.target;
  const actionable = findActionableTarget(start);
  if (!actionable) return false;
  return actionable === pendingBlockedConsentTarget;
}

/**
 * swallowBlockedConsentEvent: Suppress follow-up mouse events that would
 *   complete a consent click that was already intercepted.
 * WHY IT EXISTS: Companion to `isBlockedConsentFollowUpEvent()`. After the
 *   consent overlay intercepts a pointerdown, the browser still dispatches
 *   mouseup and click events. This function stops those events from reaching
 *   the CMP's event handlers by calling `preventDefault()`, `stopPropagation()`,
 *   and `stopImmediatePropagation()`. Without this, the CMP would receive a
 *   complete click event despite the overlay being shown, potentially accepting
 *   cookies before the user has a chance to review.
 * HOW IT WORKS:
 *   1. Guards: returns if consent analysis is disabled.
 *   2. Calls `isBlockedConsentFollowUpEvent()` to check if this event should
 *      be blocked.
 *   3. If yes, prevents default, stops propagation, and stops immediate
 *      propagation on the event.
 * INPUT: e (Event) — a mouseup or click event.
 * OUTPUT: Suppresses the event if it matches a blocked follow-up.
 */
function swallowBlockedConsentEvent(e) {
  if (!consentAnalysisEnabled) return;
  if (!isBlockedConsentFollowUpEvent(e)) return;
  try {
    if (e.cancelable) e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();
  } catch(err) { console.warn("[CC]", err.message); }
}

/**
 * window.message listener (cross-frame consent): Handle inter-frame messages
 *   for consent overlay coordination between iframes and the top frame.
 * WHY IT EXISTS: CMP consent banners are often rendered in cross-origin iframes
 *   that cannot be directly manipulated from the top frame's content script.
 *   When the content script in an iframe detects a consent action, it sends a
 *   `CC_SHOW_CONSENT_OVERLAY` postMessage to the top frame, which then shows
 *   the overlay. Conversely, when the user clicks "Accept anyway" in the top
 *   frame's overlay, a `CC_REPLAY_CONSENT_ACTION` message is sent back to the
 *   iframe to replay the click. Without this bidirectional messaging, the
 *   overlay could not intercept or replay consent actions in iframes.
 * HOW IT WORKS:
 *   1. Filters messages by `source: "CookieCrumbs"` to avoid processing messages
 *      from other extensions or the page itself.
 *   2. `CC_SHOW_CONSENT_OVERLAY` (top frame only): Stores the remote action
 *      source window and calls `showConsentOverlay()` with the remote info.
 *   3. `CC_REPLAY_CONSENT_ACTION` (iframe only): Looks up the stored remote
 *      action, constructs a `lastConsentAction`, and calls
 *      `replayConsentAction()` to dispatch the click in the iframe.
 * INPUT: MessageEvent from `window.postMessage`.
 * OUTPUT: Shows overlay (top frame) or replays click (iframe).
 */
window.addEventListener("message", e => {
  const msg = e.data;
  if (!msg || msg.source !== "CookieCrumbs") return;

  if (msg.type === "CC_SHOW_CONSENT_OVERLAY" && IS_TOP_FRAME) {
    if (msg.info?.remoteActionId) {
      remoteConsentActions.set(msg.info.remoteActionId, { sourceWindow: e.source });
    }
    showConsentOverlay(msg.info, msg.trigger || "remote");
    return;
  }

  if (msg.type === "CC_REPLAY_CONSENT_ACTION" && !IS_TOP_FRAME) {
    const action = remoteConsentActions.get(msg.actionId);
    if (!action?.target) return;
    lastConsentAction = {
      target: action.target,
      label: getActionLabel(action.target) || "accept",
      context: 0,
      strong: true,
    };
    replayConsentAction();
    remoteConsentActions.delete(msg.actionId);
  }
});

/**
 * CAT_CONSENT_EXPLAIN: Human-readable explanations of what each cookie
 *   category does, used in the consent summary paragraph.
 * WHY IT EXISTS: The consent summary paragraph (e.g., "This includes ad
 *   trackers that target you across other sites") needs plain-English
 *   descriptions of each category's purpose. These explanations help users
 *   understand the practical impact of accepting cookies. Without them, the
 *   summary would only show category names, which are meaningless to most users.
 * Source: Based on IAB Europe TCF purpose descriptions and GDPR transparency
 *   guidelines from the UK ICO.
 */
const CAT_CONSENT_EXPLAIN = {
  Advertising:   "target you across other sites",
  Performance:   "measure how you use the site",
  Functionality: "remember your preferences and login state",
  Strict:        "are essential for the site to work",
  Unknown:       "have an unidentified purpose",
};

/**
 * CAT_CONSENT_PLURAL: Pluralized labels for each cookie category, used in
 *   the consent summary paragraph.
 * WHY IT EXISTS: The consent summary needs category names in plural form
 *   (e.g., "ad trackers" vs "Advertising"). This mapping provides natural
 *   language labels for each category. Without it, the summary would display
 *   raw category identifiers, which are not user-friendly.
 */
const CAT_CONSENT_PLURAL = {
  Advertising:   "ad trackers",
  Performance:   "analytics scripts",
  Functionality: "functional scripts",
  Strict:        "essential scripts",
  Unknown:       "unclassified scripts",
};

/**
 * SEVERITY_DISC_CATS: Disconnect.me category labels treated as severity
 *   escalations in the consent overlay.
 * WHY IT EXISTS: Disconnect labels a small set of domains with behaviors that
 *   are materially worse than ordinary advertising (device fingerprinting,
 *   cryptomining, aggressive email harvesting). Surfacing these in the overlay
 *   warning is rule-based: a fixed label list from the vendor database's
 *   `disconnect_cat` field (4,425 Disconnect-sourced domain records). Source:
 *   Disconnect.me, merged into cookie_db.json (see `_meta.sources.domains`).
 */
const SEVERITY_DISC_CATS = ["Cryptomining", "FingerprintingInvasive", "FingerprintingGeneral", "EmailAggressive"];

/**
 * SAFE_WTM_CATS: WhoTracksMe category labels considered benign for the calm
 *   overlay variant.
 * WHY IT EXISTS: The calm ("safe to accept") variant must only fire when every
 *   detected vendor is a known-benign class. WhoTracksMe's `wtm_cat` field
 *   covers 9,916 domain records; only hosting/utility/audio-video-player
 *   labels qualify. `extensions` was removed because WhoTracksMe defines it
 *   as software that "intercepts and analyzes browser requests by redirecting
 *   traffic to itself", which includes browser hijacking extensions. Anything
 *   missing or outside this set blocks calm (fail-safe direction).
 *   Source: WhoTracksMe, merged into cookie_db.json (see `_meta.sources.domains`).
 */
const SAFE_WTM_CATS = ["hosting", "utilities", "audio_video_player"];

/**
 * DISC_CAUTION / WTM_CAUTION: Category values that file a vendor under the
 *   CAUTION box in `classifyVendor()`. Named `disconnect_cat` values that
 *   are neither severity nor absorbed by an earlier rule, and the remaining
 *   (non-safe) WhoTracksMe `wtm_cat` values. `Anti-fraud` is deliberately
 *   absent: it is treated as SAFE (bot/fraud protection, no browser blocks
 *   it, all 30 domains carry cat Strict with no high_risk flag).
 */
const DISC_CAUTION = ["Analytics", "Content", "Email", "Social", "ConsentManagers"];
const WTM_CAUTION = ["site_analytics", "customer_interaction", "social_media", "pornvertising", "consent", "extensions"];

/**
 * DISC_CAT_EXPLAIN: One-sentence plain-English consequence text for each
 *   severity `disconnect_cat` label, appended inside the overlay's single
 *   bottom paragraph when `evaluatePage()` escalates to red.
 * WHY IT EXISTS: A bare "fingerprinting detected" is meaningless to most
 *   users; each clause states what the behavior does to them in simple terms.
 *   Appended-only: these sentences can never remove or soften the base
 *   warning (false-negative guard).
 */
const DISC_CAT_EXPLAIN = {
  Cryptomining:           "This page also includes cryptomining scripts that use your device's processing power.",
  FingerprintingInvasive: "This page also includes fingerprinting scripts that identify your device across visits.",
  FingerprintingGeneral:  "This page also includes fingerprinting scripts that help identify your device across visits.",
  EmailAggressive:        "This page also includes aggressive scripts that collect email addresses.",
};

/**
 * TIER_STYLES: Per-tier visual tokens for the consent overlay (background,
 *   border, header, accent, title size, accept-button fill). Two palettes
 *   with identical shade structure: red covers both warning tiers (amber
 *   phrase and confirmed-high-risk phrase render on the same red chrome);
 *   green covers the calm variant. Each palette uses pale background (50),
 *   border/accent (600), and dark header/accept fill (900).
 * WHY IT EXISTS: The overlay switches between three verified risk tiers
 *   (red / amber / calm). Keeping every color decision in one map makes the
 *   tier swap a single lookup in `buildOverlay()` and keeps the variants
 *   visually consistent. `titleSize` is the header headline font size:
 *   warning tiers render maximally large on a single line, calm stays sized
 *   for its longer phrase with the same one-line + side-margin treatment.
 *   `acceptBg` is the solid fill for the "Accept anyway" button (900 shade
 *   of the tier color) with white text.
 */
const TIER_STYLES = {
  red:  { bg: "#fef2f2", border: "#dc2626", headerBg: "#7f1d1d", headerText: "#ffffff", accent: "#dc2626", titleSize: "min(48px,calc((100vw - 140px)/13))", acceptBg: "#7f1d1d" },
  calm: { bg: "#f0fdf4", border: "#16a34a", headerBg: "#14532d", headerText: "#ffffff", accent: "#16a34a", titleSize: "min(48px,calc((100vw - 140px)/14))", acceptBg: "#14532d" },
};
/**
 * relQtyConsent: Convert an absolute count into a relative quantity word
 *   ("No", "A few", "Some", "Many", "Most") for human-readable consent summaries.
 * WHY IT EXISTS: Raw numbers (e.g., "12 of 40 scripts") are less intuitive
 *   than relative quantifiers (e.g., "Many ad trackers"). This function maps
 *   the ratio n/total to natural language, making the consent summary more
 *   readable and actionable. Without it, the summary would contain awkward
 *   number phrasing.
 * HOW IT WORKS: If total is 0, returns "No". Otherwise computes the ratio
 *   n/total and maps: >50% → "Most", >20% → "Many", >5% → "Some", else → "A few".
 * INPUT: n (number) — count of items in a category.
 *        total (number) — total count across all categories.
 * OUTPUT: string — relative quantity word.
 */
function relQtyConsent(n, total) {
  if (total === 0) return "No";
  const pct = n / total;
  if (pct > 0.5) return "Most";
  if (pct > 0.2) return "Many";
  if (pct > 0.05) return "Some";
  return "A few";
}
/**
 * classifyVendor: The single vendor classification used by the whole
 *   overlay. Maps one detected vendor to its tier box and dataset category
 *   label, worst tier first.
 * WHY IT EXISTS: The header verdict, the why-sentence, and the tier-list
 *   boxes must all describe the SAME classification. This is the only place
 *   a vendor is interpreted; `evaluatePage()` derives everything else from
 *   its output. Every label is a literal category value from cookie_db.json
 *   (disconnect_cat / wtm_cat / cat); `high_risk` is a flag, not a category,
 *   so it is never a trigger or label here (it only blocks calm inside
 *   `evaluatePage()`).
 * HOW IT WORKS (precedence):
 *   1. severity disconnect_cat (SEVERITY_DISC_CATS) -> HIGH
 *   2. wtm_cat ∈ SAFE_WTM_CATS -> SAFE; disconnect_cat "Anti-fraud" -> SAFE
 *   3. named disconnect_cat (DISC_CAUTION) -> CAUTION
 *   4. remaining wtm_cat (WTM_CAUTION) -> CAUTION
 *   5. cat Advertising / wtm_cat advertising -> CAUTION ("advertising")
 *   6. otherwise -> null (unclassified; blocks calm, never displayed)
 * INPUT: v (Object) — vendor from addVendorEstimate().
 * OUTPUT: `{ box: "high"|"safe"|"caution", cat: string }` or null.
 */
function classifyVendor(v) {
  const disc = String(v.disconnect_cat || "");
  const wtm = String(v.wtm_cat || "");
  if (SEVERITY_DISC_CATS.includes(disc)) return { box: "high", cat: disc };
  if (SAFE_WTM_CATS.includes(wtm)) return { box: "safe", cat: wtm };
  if (disc === "Anti-fraud") return { box: "safe", cat: "Anti-fraud" };
  if (DISC_CAUTION.includes(disc)) return { box: "caution", cat: disc };
  if (WTM_CAUTION.includes(wtm)) return { box: "caution", cat: wtm };
  if (v.cat === "Advertising" || wtm === "advertising") return { box: "caution", cat: "advertising" };
  return null;
}

/**
 * evaluatePage: THE single decision path for the consent overlay. One
 *   function turns the detected vendors into the verdict tier, the
 *   why-sentence, the grouped tier-list boxes, and the severity clauses.
 * WHY IT EXISTS: The header ("DO NOT ACCEPT" / "SAFE TO ACCEPT"), the
 *   sentence strip, and the three boxes are three views of one result. They
 *   were previously computed by separate functions that could disagree;
 *   now nothing is computed twice. The vendor database (Disconnect.me +
 *   WhoTracksMe merge, cookie_db.json `_meta.sources`) contradicts itself
 *   across sources, so CALM fails closed and cues may only ADD severity.
 * HOW IT WORKS:
 *   1. Classify every vendor once via `classifyVendor()`. Group classified
 *      vendors (name ≥ 4 chars; junk 1-char DB keys are display-skipped)
 *      into `{ high, caution, safe }` groups of `{ cat, names }`; the exact
 *      same name inside one group is listed once (distinct records that
 *      share a vendor string would otherwise render identical bullets).
 *   2. RED: any usable vendor with box "high" (severity disconnect_cat,
 *      single source). Severity clauses = DISC_CAT_EXPLAIN for each HIGH
 *      group present (deduped by group).
 *   3. CALM: at least one vendor, EVERY vendor (junk included) classifies
 *      to a SAFE box, no vendor carries the high_risk flag, and internally
 *      derived counts have zero Advertising and zero Unknown. Null
 *      classifications block calm (fail closed).
 *   4. AMBER: everything else.
 *   5. The why-sentence is selected from the same boxes/counts: calm ->
 *      reassurance sentence; red -> strongest HIGH category in severity
 *      order (Cryptomining, FingerprintingInvasive, FingerprintingGeneral,
 *      EmailAggressive); amber -> advertising/unclassified counts.
  * INPUT: vendors (Array) — detected vendor objects from addVendorEstimate()
  *          (fields: name, domain, cat, high_risk, wtm_cat, disconnect_cat).
  * OUTPUT: `{ tier: "red"|"amber"|"calm", why: string,
  *            boxes: { high: [], caution: [], safe: [] },
  *            severityClauses: string[] }` — boxes hold grouped
  *          `{ cat, names }` ready for rendering, where each name is
  *          `Vendor (domain)` when the two differ (e.g. `Meta
  *          (facebook.net)` vs `Meta (facebook.com)`).
 */
function evaluatePage(vendors) {
  const list = vendors || [];
  const counts = { Advertising: 0, Performance: 0, Functionality: 0, Strict: 0, Unknown: 0 };
  list.forEach(v => { if (counts[v.cat] !== undefined) counts[v.cat]++; });

  const boxes = { high: [], caution: [], safe: [] };
  const byBox = { high: new Map(), caution: new Map(), safe: new Map() };
  let red = false;
  let calmOk = list.length > 0;
  let hasHighRisk = false;

  for (const v of list) {
    const c = classifyVendor(v);
    const usable = String(v.name || "").length >= 4;
    if (v.high_risk) hasHighRisk = true;
    if (usable && c) {
      const m = byBox[c.box];
      if (!m.has(c.cat)) { const g = { cat: c.cat, names: [] }; m.set(c.cat, g); boxes[c.box].push(g); }
      const label = v.domain && v.domain !== v.name ? `${v.name} (${v.domain})` : v.name;
      const names = m.get(c.cat).names;
      if (!names.includes(label)) names.push(label);
      if (c.box === "high") red = true;
    }
    if (!c || c.box !== "safe") calmOk = false;
  }

  const adBlocked = counts.Advertising > 0 || counts.Unknown > 0;
  const calm = calmOk && !hasHighRisk && !adBlocked;
  const tier = red ? "red" : calm ? "calm" : "amber";

  const severityClauses = boxes.high
    .filter(g => DISC_CAT_EXPLAIN[g.cat])
    .map(g => DISC_CAT_EXPLAIN[g.cat]);

  let why;
  if (tier === "calm") {
    why = "Every script on this page is a hosting, utility, or media player service with no advertising or unclassified trackers detected.";
  } else if (tier === "red") {
    const RED_WHY = {
      Cryptomining: "This page loads a script flagged as cryptomining that would use your device's computing power to mine currency for someone else.",
      FingerprintingInvasive: "This page loads scripts flagged for invasive fingerprinting that can single out your device across the web.",
      FingerprintingGeneral: "This page loads scripts flagged for fingerprinting that can help identify your device across visits.",
      EmailAggressive: "This page loads scripts flagged for harvesting email addresses."
    };
    const order = ["Cryptomining", "FingerprintingInvasive", "FingerprintingGeneral", "EmailAggressive"];
    const found = order.find(cat => boxes.high.some(g => g.cat === cat));
    why = RED_WHY[found] || "This page loads scripts the dataset flags with a high-risk category.";
  } else {
    const ad = counts.Advertising > 0;
    const unk = counts.Unknown > 0;
    if (ad && unk) why = "This page loads advertising and unclassified scripts that would begin tracking you if you accept.";
    else if (ad) why = "This page loads advertising scripts that would track you across sites if you accept.";
    else if (unk) why = "This page loads scripts we could not classify that could track you if you accept.";
    else why = "Some scripts here lack category data so we cannot confirm accepting is safe.";
  }

  return { tier, why, boxes, severityClauses };
}

/**
 * buildTierListHtml: Render the overlay's tier list (high risk / caution /
 *   safe) as three columns side by side from a precomputed `evaluatePage()`
 *   result.
 * WHY IT EXISTS: Pure presentation. The verdict, the why-sentence, and these
 *   boxes must show one consistent classification, so this function does no
 *   classification of its own: it renders `page.boxes` exactly as
 *   `evaluatePage()` produced them. Every group label is a literal category
 *   value from cookie_db.json (disconnect_cat / wtm_cat / cat), reformatted
 *   for readability via LABEL_TEXT only. Identical categories are collapsed
 *   into one group (category + count header, description line, divider,
 *   bullet list of names); the three tiers sit side by side so the verdicts
 *   are comparable at a glance. Empty boxes render a literal "none" so the
 *   overlay is auditable at a glance.
 * HOW IT WORKS:
 *   1. Takes `page.boxes` = { high, caution, safe }, each a list of
 *      `{ cat, names }` groups already ordered worst-category-first by
 *      `evaluatePage()`. Junk names (< 4 chars) were already skipped there.
 *   2. Each group renders as a tinted mini-card: bold "Label (N)" header,
 *      italic description (REASON_DESC), divider, then bullet names.
 *   3. The three boxes render in a 3-column grid; each column has a large
 *      tier-colored label above a white rounded box (3px tier-colored
 *      border) with a fixed-height scrollable rows area, so all three
 *      columns stay aligned.
 * INPUT: page (Object) — result of evaluatePage(): { tier, why, boxes,
 *          severityClauses }.
 * OUTPUT: HTML string (three columns; names are escaped).
 */
function buildTierListHtml(page) {
  const DOT = { high: "#dc2626", caution: "#d97706", safe: "#16a34a" };

  // LABEL_TEXT: display-only reformatting of dataset category values
  //   (camelCase/snake_case → words, sentence case). No invented wording;
  //   unmapped values fall through verbatim.
  const LABEL_TEXT = {
    FingerprintingInvasive: "Fingerprinting invasive",
    FingerprintingGeneral: "Fingerprinting general",
    EmailAggressive: "Email aggressive",
    ConsentManagers: "Consent managers",
    site_analytics: "Site analytics",
    customer_interaction: "Customer interaction",
    audio_video_player: "Audio video player",
    social_media: "Social media",
    advertising: "Advertising",
    hosting: "Hosting",
    utilities: "Utilities",
    extensions: "Extensions",
    consent: "Consent"
  };

  // REASON_DESC: one-sentence explanation per dataset category, keyed by the
  //   raw dataset value (same keys as LABEL_TEXT). Text grounded in the
  //   upstream definitions: WhoTracksMe category descriptions (ghostery.com/
  //   whotracksme) and Disconnect category definitions (disconnect.me/
  //   trackerprotection). Rendered after "Label (N)" on the same line.
  const REASON_DESC = {
    Cryptomining: "uses your device to mine cryptocurrency without permission",
    FingerprintingInvasive: "reads device details through APIs not meant to expose them",
    FingerprintingGeneral: "uses device properties in unintended ways to identify you",
    EmailAggressive: "aggressively collects email addresses for tracking",
    hosting: "serves site files, no tracking found",
    utilities: "needed for the site to work",
    audio_video_player: "plays audio or video on the page",
    advertising: "tracks you across sites for ads",
    Analytics: "measures how the site is used",
    Content: "delivers page content such as images and video",
    Email: "handles email features such as newsletters",
    Social: "embeds social media buttons or feeds",
    "Anti-fraud": "detects bots and fraudulent requests",
    ConsentManagers: "runs a cookie consent banner",
    site_analytics: "collects site usage statistics",
    customer_interaction: "runs chat, support, or messaging tools",
    social_media: "embeds social media content in the page",
    pornvertising: "advertising on adult content sites",
    consent: "runs a cookie consent tool",
    extensions: "intercepts and analyzes browser requests"
  };

  const TINT = {
    high:   { bg: "#fef2f2", border: "#fecaca" },
    caution:{ bg: "#fffbeb", border: "#fde68a" },
    safe:   { bg: "#f0fdf4", border: "#bbf7d0" }
  };

  const box = (tier, label, color, groups) => {
    const tint = TINT[tier];
    const body = groups.length
      ? groups.map(g => {
          const names = g.names.map(n =>
            `<div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#475569;line-height:1.5;margin:1px 0 1px 10px;overflow-wrap:anywhere">&bull; ${escapeHtml(n)}</div>`
          ).join("");
          const display = LABEL_TEXT[g.cat] || g.cat;
          const desc = REASON_DESC[g.cat];
          const descRow = desc
            ? `<div style="font-family:'JetBrains Mono',monospace;font-size:10px;font-style:italic;color:#64748b;line-height:1.4;margin:1px 0 4px;overflow-wrap:anywhere">${escapeHtml(desc)}</div>`
            : "";
          return `<div style="background:${tint.bg};border:1px solid ${tint.border};border-radius:8px;padding:6px 8px;margin-bottom:8px">
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:700;color:#1d2b3d;line-height:1.4">${escapeHtml(display)} (${g.names.length})</div>
            ${descRow}
            <div style="height:1px;background:${tint.border};margin-bottom:3px"></div>
            ${names}
          </div>`;
        }).join("")
      : `<div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:#64748b;font-style:italic;margin:2px 0">none</div>`;
    return `<div style="display:flex;flex-direction:column;min-width:0">
      <div style="font-family:'JetBrains Mono',monospace;font-size:15px;font-weight:700;letter-spacing:.08em;color:${color};text-transform:uppercase;margin:0 0 6px 2px">${label}</div>
      <div style="background:#ffffff;border:3px solid ${color};border-radius:10px;padding:8px 10px;display:flex;flex-direction:column;min-width:0">
        <div style="height:140px;overflow:auto;padding-right:4px">${body}</div>
      </div>
    </div>`;
  };

  return `<div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px;margin-bottom:10px">`
    + box("high", "high risk", DOT.high, page.boxes.high)
    + box("caution", "caution", DOT.caution, page.boxes.caution)
    + box("safe", "safe", DOT.safe, page.boxes.safe)
    + `</div>`;
}

/**
 * generateConsentSummaryParagraph: Generate a full consequence paragraph
 *   (count sentence + fused categories/destinations + severity clauses).
 * WHY IT EXISTS: Kept for the fixture test suite and as the detailed text
 *   reference; the live overlay now renders the single `evaluatePage().why`
 *   strip under the header instead of this paragraph.
 * HOW IT WORKS:
 *   1. If no vendors, returns a reassuring "no tracking" one-liner.
 *   2. Builds the category clause from `CAT_CONSENT_PLURAL` +
 *      `CAT_CONSENT_EXPLAIN`, joined naturally ("X, Y, and Z").
 *   3. Builds the destination clause (up to 4 names + "and others").
 *   4. Fuses them: "If you accept, N… activate. <lead><categories> — and
 *      your data may be shared with …". Calm tier prefixes "No advertising
 *      or unclassified scripts detected."
 *   5. Appends any severityClauses (red tier) in the same paragraph string.
 * INPUT: vendors (Array) — detected vendor objects.
 *        counts (Object) — category counts `{ Advertising: N, ... }`.
 *        collected (Set) — data types collected (unused; kept for signature
 *          compatibility with the previous implementation).
 *        dests (Array) — destination vendor names.
 *        tier (string) — "red" | "amber" | "calm" from `evaluatePage()`.
 *        severityClauses (Array) — consequence sentences to append (red tier).
 * OUTPUT: Formatted paragraph string with HTML escaping via `escapeHtml()`.
 */
function generateConsentSummaryParagraph(vendors, counts, collected, dests, tier = "amber", severityClauses = []) {
  const total = vendors.length;
  if (total === 0) {
    return "No tracking scripts were detected on this page. If you accept, no third-party tracking is expected.";
  }

  const catParts = [];
  const ordered = ["Advertising","Performance","Functionality","Strict","Unknown"];
  for (const cat of ordered) {
    if (!counts[cat]) continue;
    const plural = CAT_CONSENT_PLURAL[cat] || "scripts";
    const explain = CAT_CONSENT_EXPLAIN[cat] || "";
    catParts.push(`${plural} that ${explain}`);
  }
  let catClause = "";
  if (catParts.length === 1) {
    catClause = catParts[0];
  } else if (catParts.length === 2) {
    catClause = `${catParts[0]} and ${catParts[1]}`;
  } else if (catParts.length > 2) {
    catClause = `${catParts.slice(0, -1).join(", ")}, and ${catParts[catParts.length - 1]}`;
  }

  const destArr = dests.slice(0, 4);
  let destClause = "";
  if (destArr.length > 0) {
    const more = dests.length > 4 ? ", and others" : "";
    destClause = `your data may be shared with ${destArr.map(d => escapeHtml(d)).join(", ")}${more}`;
  }

  const lead = tier === "calm"
    ? "No advertising or unclassified scripts detected. This includes "
    : "This includes ";
  const countSentence = `If you accept, ${total} tracking script${total !== 1 ? "s" : ""} will activate.`;

  let paragraph = "";
  if (catClause && destClause) {
    paragraph = `${countSentence} ${lead}${catClause} — and ${destClause}.`;
  } else if (catClause) {
    paragraph = `${countSentence} ${lead}${catClause}.`;
  } else if (destClause) {
    paragraph = `${countSentence} ${destClause.replace(/^your data may be shared with /, "Your data may be shared with ")}.`;
  }

  if (severityClauses.length) {
    paragraph = `${paragraph} ${severityClauses.join(" ")}`;
  }
  return paragraph.trim();
}

/**
 * buildOverlay: Construct and display the full consent overlay UI, including
 *   script detection, vendor categorization, and interactive buttons.
 * WHY IT EXISTS: This is the main UI function of the consent interception
 *   system. It performs the complete overlay pipeline:
 *   1. Scans all `<script>` tags and inline scripts for tracker domains.
 *   2. Categorizes detected vendors by privacy impact (Advertising, etc.).
 *   3. Computes verdict, sentence, and boxes via `evaluatePage()` (one call).
 *   4. Renders exactly TWO text blocks: one big warning phrase at the top
 *      ("Do not accept" — the script count lives in the bottom paragraph)
 *      and ONE consequence paragraph at the bottom (count sentence + the
 *      former category + destination sentences fused with an em-dash, plus
 *      any severity clauses) — per the design directive to keep the overlay
 *      to a single top phrase and a single bottom paragraph.
 *   5. Renders the category presence table and destination list (unchanged).
 *   6. Renders "Go back" as the solid primary action and "Accept anyway" as
 *      a demoted outline button (visual demotion only — IDs and handlers
 *      unchanged; one click still accepts).
 * HOW IT WORKS:
 *   1. Guards: only runs in top frame, only if no overlay already exists.
 *   2. Collects all `<script src>` URLs and inline script contents.
 *   3. For each script source, looks up the host in `TRACKER_DOMAINS` via
 *      `trackerHitForHost()` and adds to vendor list via `addVendorEstimate()`
 *      (one verbatim database record per entry — no field merging).
 *   4. For inline scripts, extracts domains via `extractDomainsFromInlineScript()`
 *      and looks them up similarly.
 *   5. Special-cases Google Tag Manager to add "Ad vendors via GTM" if no
 *      advertising vendors are already detected.
 *   6. Selects palette/stripe/phrase from TIER_STYLES/PHRASES using the
 *      evaluated tier.
 *   7. Builds the overlay DOM with inline styles (max-width 1024px, tier theme).
 *   8. Attaches click handlers: close → `removeOverlay()`, go back →
 *      `removeOverlay()` + `notifyBannerState(false)`, accept anyway →
 *      `replayConsentAction()` + `notifyBannerState(false)`.
 * INPUT: None (reads globals `overlayEl`, `TRACKER_DOMAINS`, `lastConsentAction`).
 * OUTPUT: Creates and appends overlay DOM elements.
 */
function buildOverlay() {
  if (!IS_TOP_FRAME) return;
  if (overlayEl) return;
  const srcs    = [...document.querySelectorAll("script[src]")].map(s => s.src);
  const inlines = [...document.querySelectorAll("script:not([src])")].map(s => s.textContent || "");
  const found   = new Set(), vendors = [];

  for (const src of srcs) {
    try {
      const host = new URL(src).hostname;
      const { hit, fallbackName, domain } = trackerHitForHost(host);
      addVendorEstimate(vendors, found, hit, fallbackName, domain);
    } catch(e) { console.warn("[CC]", e.message); }
  }

  for (const inline of inlines) {
    for (const domain of extractDomainsFromInlineScript(inline)) {
      const { hit, fallbackName, domain: domainKey } = trackerHitForHost(domain);
      addVendorEstimate(vendors, found, hit, fallbackName, domainKey);
    }
  }

  if (vendors.some(v => v.name.includes("googletagmanager") || v.name === "Google Tag Manager")
      && !vendors.some(v => v.cat === "Advertising"))
    vendors.push({ name:"Ad vendors via GTM", cat:"Advertising" });

  const page = evaluatePage(vendors);
  const TSTYLE = TIER_STYLES[page.tier === "calm" ? "calm" : "red"] || TIER_STYLES.red;
  const PHRASES = {
    red:    { title: "DO NOT ACCEPT" },
    amber:  { title: "DO NOT ACCEPT" },
    calm:   { title: "SAFE TO ACCEPT" },
  };
  const phrase = PHRASES[page.tier] || PHRASES.amber;

  const whySentence = page.why;
  const tierListHtml = buildTierListHtml(page);

  overlayHostEl = document.createElement("div");
  overlayHostEl.id = "cc-preconsent-host";
  overlayHostEl.setAttribute("style",`
    position:fixed!important;inset:0!important;
    z-index:2147483647!important;
    width:100vw!important;height:100vh!important;
    display:flex!important;align-items:center!important;justify-content:center!important;
    padding:16px!important;background:rgba(15,23,42,.18)!important;
    isolation:isolate!important;pointer-events:auto!important;
    box-sizing:border-box!important;
  `);

  overlayEl = document.createElement("div");
  overlayEl.id = "cc-preconsent-overlay";
  overlayEl.setAttribute("style",`
    position:relative!important;
    z-index:2147483647!important;width:min(1024px,calc(100vw - 32px))!important;
    background:${TSTYLE.bg}!important;border-radius:16px!important;
    box-shadow:0 20px 60px rgba(15,23,42,.2)!important;
    border:3px solid ${TSTYLE.border}!important;
    font-family:-apple-system,sans-serif!important;
    overflow:auto!important;max-height:82vh!important;
    display:flex!important;flex-direction:column!important;
  `);
  overlayEl.innerHTML = `
    <style>
      #cc-preconsent-overlay *,
      #cc-preconsent-overlay *::before,
      #cc-preconsent-overlay *::after{box-sizing:border-box!important}
      #cc-preconsent-overlay,
      #cc-preconsent-overlay *{
        scrollbar-width:thin!important;
        scrollbar-color:${TSTYLE.border} ${TSTYLE.bg}!important;
      }
      #cc-preconsent-overlay::-webkit-scrollbar,
      #cc-preconsent-overlay *::-webkit-scrollbar{
        width:10px!important;
        height:10px!important;
      }
      #cc-preconsent-overlay::-webkit-scrollbar-track,
      #cc-preconsent-overlay *::-webkit-scrollbar-track{
        background:${TSTYLE.bg}!important;
        border-radius:999px!important;
      }
      #cc-preconsent-overlay::-webkit-scrollbar-thumb,
      #cc-preconsent-overlay *::-webkit-scrollbar-thumb{
        background:${TSTYLE.border}!important;
        border-radius:999px!important;
        border:2px solid ${TSTYLE.bg}!important;
      }
      #cc-preconsent-overlay::-webkit-scrollbar-thumb:hover,
      #cc-preconsent-overlay *::-webkit-scrollbar-thumb:hover{
        background:${TSTYLE.headerText}!important;
      }
    </style>
    <div style="background:${TSTYLE.headerBg};padding:16px 18px;border-bottom:3px solid ${TSTYLE.border};display:flex;align-items:center;gap:12px;flex-shrink:0">
      <div style="flex:1;text-align:center">
        <div style="font-family:'Syne',sans-serif;font-size:${TSTYLE.titleSize};font-weight:800;color:${TSTYLE.headerText};line-height:1;letter-spacing:.02em;white-space:nowrap">${phrase.title}</div>
      </div>
      <button id="cc-close-btn" style="background:${TSTYLE.border}!important;border:3px solid ${TSTYLE.headerText}!important;border-radius:7px!important;cursor:pointer!important;color:#fff!important;font-size:12px!important;width:26px!important;height:26px!important;display:flex!important;align-items:center!important;justify-content:center!important;flex-shrink:0!important;padding:0!important;font-weight:700!important">✕</button>
    </div>
    <div style="background:${TSTYLE.bg};padding:10px 16px;font-family:'JetBrains Mono',monospace;font-size:16px;font-weight:600;color:#1d2b3d;line-height:1.45;flex-shrink:0">${escapeHtml(whySentence)}</div>
    <div style="padding:8px 18px 4px 18px;display:flex;flex-direction:column;min-height:0;flex:1">
      <div style="font-family:'JetBrains Mono',monospace;font-size:9px;color:#1d2b3d;text-transform:uppercase;letter-spacing:.1em;font-weight:600;margin-bottom:6px">tier list</div>
      <div style="overflow:auto;flex:1;min-height:0">${tierListHtml}</div>
    </div>
    <div style="min-height:44px;border-top:1px dashed ${TSTYLE.border};opacity:.95;padding:8px 18px 10px;display:flex;align-items:center;justify-content:flex-end;gap:12px;flex-shrink:0">
      <div style="display:flex;gap:12px;flex-shrink:0">
        <button id="cc-go-back-btn" style="background:#2563eb!important;border:3px solid #1d4ed8!important;border-radius:10px!important;cursor:pointer!important;color:#fff!important;font-size:12px!important;padding:9px 16px!important;font-weight:800!important;min-width:100px!important;box-shadow:0 10px 24px rgba(37,99,235,.25)!important">Go back</button>
        <button id="cc-accept-anyway-btn" ${lastConsentAction ? "" : "disabled"} style="background:${TSTYLE.acceptBg}!important;border:3px solid ${TSTYLE.acceptBg}!important;border-radius:10px!important;cursor:pointer!important;color:#fff!important;font-size:11px!important;padding:8px 14px!important;font-weight:800!important;min-width:120px!important;opacity:${lastConsentAction ? "1" : ".45"}!important">Accept anyway</button>
      </div>
    </div>
  `;

  overlayHostEl.appendChild(overlayEl);
  (document.documentElement || document.body).appendChild(overlayHostEl);
  overlayEl.querySelector("#cc-close-btn").addEventListener("click", removeOverlay);
  overlayEl.querySelector("#cc-go-back-btn")?.addEventListener("click", () => {
    removeOverlay();
    notifyBannerState(false);
  });
  overlayEl.querySelector("#cc-accept-anyway-btn")?.addEventListener("click", () => {
    if (!lastConsentAction?.target) {
      removeOverlay();
      notifyBannerState(false);
      return;
    }
    replayConsentAction();
    notifyBannerState(false);
  });
}

let lastState = null;


/**
 * maybeInterceptConsentEvent: Main event interceptor that evaluates whether a
 *   DOM event targets a consent "Accept" button and should be intercepted.
 * WHY IT EXISTS: This is the heart of the consent interception system. Every
 *   pointer/mouse/focus event on the page passes through this function. It must
 *   efficiently determine whether the event targets a consent accept button
 *   (using `inspectConsentAcceptAction()`) and, if so, either show the overlay
 *   immediately (for pointerdown) or pre-emptively flag the element (for hover/
 *   focus). The function must be fast (it runs on every event) and conservative
 *   (avoid false positives). Without this, the consent overlay would never be
 *   triggered by user interactions.
 * HOW IT WORKS:
 *   1. Guards: returns if consent analysis disabled, event is untrusted, within
 *      bypass window, or targets the overlay itself.
 *   2. Filters: only left-button pointer events (button 0 or undefined).
 *   3. Gets the actionable target from the event's composed path.
 *   4. Runs `inspectConsentAcceptAction()` on the target.
 *   5. If no match, returns.
 *   6. For `pointerover`: shows overlay if the accept pattern is strong AND
 *      container score ≥ 5 (hover preview).
 *   7. For `focusin`: same as hover — shows overlay for strong accepts in
 *      high-confidence containers.
 *   8. For `pointerdown`: shows overlay with `pauseAction=true` to block the
 *      click until the user decides.
 * INPUT: e (Event) — a pointer, mouse, or focus event.
 * OUTPUT: May show the consent overlay and suppress the event.
 */
function maybeInterceptConsentEvent(e) {
  if (!consentAnalysisEnabled) return;
  if (!e?.isTrusted) return;
  if (Date.now() < consentBypassUntil) return;
  if (overlayEl && overlayEl.contains(e.target)) return;
  if (e.type === "pointerdown" && e.button !== 0 && e.button !== undefined) return;

  const start = e.composedPath?.()[0] || e.target;
  const info = inspectConsentAcceptAction(start);
  if (!info) return;

  if (e.type === "pointerover") {
    if (!info.strong || (info.containerScore || 0) < 5) return;
    showConsentOverlay(info, "hover");
    return;
  }

  if (e.type === "focusin") {
    if (!info.strong || (info.containerScore || 0) < 5) return;
    showConsentOverlay(info, "focus");
    return;
  }

  showConsentOverlay(info, "pointerdown", true, e);
}

/**
 * registerConsentGuard: Attach consent interception and event swallowing
 *   listeners to a target document.
 * WHY IT EXISTS: The consent guard must be installed on every document where
 *   consent events should be intercepted — initially the main document, and
 *   potentially sub-documents. This function registers both the interception
 *   listeners (pointerover, mouseover, focusin, pointerdown) via
 *   `maybeInterceptConsentEvent` and the event swallowing listeners (pointerup,
 *   mouseup, click) via `swallowBlockedConsentEvent`. Both sets use capture
 *   phase (`true` as the third argument) to intercept events before the page's
 *   own handlers. Without capture-phase registration, the CMP's event handlers
 *   would fire first, making interception impossible.
 * HOW IT WORKS: Adds 7 event listeners to the target document:
 *   - pointerover, mouseover, focusin, pointerdown → `maybeInterceptConsentEvent`
 *   - pointerup, mouseup, click → `swallowBlockedConsentEvent`
 *   All use capture phase (3rd arg = true).
 * INPUT: target (Document) — the document to protect.
 * OUTPUT: Attaches event listeners to the target.
 */
function registerConsentGuard(target) {
  target.addEventListener("pointerover", maybeInterceptConsentEvent, true);
  target.addEventListener("mouseover", maybeInterceptConsentEvent, true);
  target.addEventListener("focusin", maybeInterceptConsentEvent, true);
  target.addEventListener("pointerdown", maybeInterceptConsentEvent, true);
  target.addEventListener("pointerup", swallowBlockedConsentEvent, true);
  target.addEventListener("mouseup", swallowBlockedConsentEvent, true);
  target.addEventListener("click", swallowBlockedConsentEvent, true);
}

/**
 * chrome.runtime.onMessage listener: Handle messages from the background script
 *   and popup to update the content script's UI state.
 * WHY IT EXISTS: The background script and popup need to communicate with the
 *   content script to trigger overlay display, query banner state, request
 *   cookie reads, deliver updated cookie data, and inform about panel state
 *   changes. This listener routes incoming messages to the appropriate handler.
 *   Without it, the content script would be isolated from the rest of the
 *   extension and could not respond to user actions in the popup or background.
 * HOW IT WORKS: Routes messages by `msg.type`:
 *   - `SHOW_OVERLAY`: Calls `buildOverlay()` to show the consent overlay.
 *   - `GET_BANNER_STATE`: Responds with `{ visible }` indicating overlay state.
 *   - `READ_DOC_COOKIES`: Triggers `readAndSendDocCookies()`.
 *   - `COOKIES_UPDATED`: Receives updated cookie arrays from the background,
 *     computes delta for the badge, and updates the widget score. Filters by
 *     tabId to avoid updating the wrong tab.
 *   - `PANEL_STATE_CHANGED`: Calls `updateWidgetPanelState()` to reposition
 *     the widget when the side panel opens/closes.
 * INPUT: Message from background/popup with `{ type, ...payload }`.
 * OUTPUT: Calls appropriate handler functions. Some messages return a response.
 */
chrome.runtime.onMessage.addListener((msg, _, sendResponse) => {
  if (msg.type === "SHOW_OVERLAY")     { buildOverlay(); return false; }
  if (msg.type === "GET_BANNER_STATE") { sendResponse({ visible: lastState === true }); return true; }
  if (msg.type === "READ_DOC_COOKIES") { readAndSendDocCookies(); return false; }
  if (msg.type === "COOKIES_UPDATED")  {
    if (Number.isInteger(msg.tabId) && Number.isInteger(currentTabId) && msg.tabId !== currentTabId) return false;
    if (Array.isArray(msg.cookies)) {
      if (Number.isInteger(msg.score)) {
        const cookies = msg.cookies;
        const delta = lastWidgetCookieCount > 0 && cookies.length > lastWidgetCookieCount
          ? cookies.length - lastWidgetCookieCount : 0;
        lastWidgetCookieCount = cookies.length;
        applyWidgetScore({ score: msg.score, label: msg.scoreLabel || "Good", total: cookies.length }, delta);
      } else {
        refreshWidget(msg.cookies);
      }
    } else {
      refreshWidget();
    }
    return false;
  }
  if (msg.type === "PANEL_STATE_CHANGED") {
    if (Number.isInteger(msg.tabId) && Number.isInteger(currentTabId) && msg.tabId !== currentTabId) return false;
    updateWidgetPanelState(!!msg.isOpen);
    return false;
  }
});

/**
 * window.message listener (DOC_COOKIE_CHANGED): Receive notifications from the
 *   injected `doc_cookie_hook.js` that the page has written a cookie.
 * WHY IT EXISTS: The `doc_cookie_hook.js` script (injected by
 *   `installDocCookieHook()`) monkey-patches the page's `document.cookie` setter
 *   to post a `CC_DOC_COOKIE_CHANGED` message whenever the page writes a cookie.
 *   This listener receives those messages and triggers a debounced re-read of
 *   `document.cookie` via `scheduleDocCookieRefresh()`. Without this bridge, the
 *   content script would never know when the page sets new cookies after initial
 *   load, causing the widget score to be stale.
 * HOW IT WORKS:
 *   1. Filters: only accepts messages from `window` (same window, not iframes).
 *   2. Filters by `source: "CookieCrumbs"` and `type: "CC_DOC_COOKIE_CHANGED"`.
 *   3. Calls `scheduleDocCookieRefresh()` to debounce and re-read cookies.
 * INPUT: MessageEvent from the injected hook script.
 * OUTPUT: Triggers `scheduleDocCookieRefresh()`.
 */
window.addEventListener("message", event => {
  if (event.source !== window) return;
  const msg = event.data;
  if (!msg || msg.source !== "CookieCrumbs" || msg.type !== "CC_DOC_COOKIE_CHANGED") return;
  scheduleDocCookieRefresh();
});

/**
 * chrome.storage.onChanged listener: React to real-time settings changes from
 *   the extension's options page or background script.
 * WHY IT EXISTS: Users can toggle widget visibility, consent analysis, or the
 *   master switch from the extension's popup or options page. These changes are
 *   saved to `chrome.storage.local` and must be immediately reflected in the
 *   content script without requiring a page reload. This listener updates the
 *   in-memory settings and calls `applySettings()` to synchronize the UI. Without
 *   it, setting changes would only take effect after the next page load, creating
 *   a confusing user experience.
 * HOW IT WORKS:
 *   1. Filters: only responds to changes in `"local"` storage area.
 *   2. Updates `widgetEnabled` if `changes.widgetEnabled` exists.
 *   3. Updates `ccEnabled` if `changes.ccEnabled` exists. If master is off,
 *      forces both sub-features off.
 *   4. Updates `consentAnalysisEnabled` if `changes.consentAnalysisEnabled` exists.
 *   5. Calls `applySettings()` to apply all changes.
 * INPUT: changes (Object) — Chrome storage change descriptors with `oldValue`/`newValue`.
 *        area (string) — "local", "sync", or "managed".
 * OUTPUT: Updates global settings and calls `applySettings()`.
 */
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== "local") return;
  if (changes.widgetEnabled) {
    widgetEnabled = changes.widgetEnabled.newValue !== false;
  }
  if (changes.ccEnabled) {
    ccEnabled = changes.ccEnabled.newValue !== false;
    if (!ccEnabled) {
      widgetEnabled = false;
      consentAnalysisEnabled = false;
    }
  }
  if (changes.consentAnalysisEnabled) {
    consentAnalysisEnabled = changes.consentAnalysisEnabled.newValue !== false;
  }
  applySettings();
});

(async () => {
  await loadSettings();
  if (ccEnabled && consentAnalysisEnabled) registerConsentGuard(document);
  const data = await requestLocalData();
  await Promise.all([loadDB(data), loadModel(data)]);
  refreshWidget();
})();


