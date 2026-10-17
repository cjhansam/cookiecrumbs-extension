// ============================================================
// Cookie Crumbs v5.16 — domain_utils.js
// Shared domain, origin, and classification helpers.
// This file is the foundation of the entire classification system.
// Every function here is called by background.js, sidepanel.js,
// content.js, or ml_inference.js.
// ============================================================

// 23 country-code second-level domains (e.g. co.uk, com.au).
// Needed because "www.bbc.co.uk" — the registrable domain is
// "bbc.co.uk", NOT "co.uk". Without this list, getRegistrableDomain
// would return "co.uk" for every .co.uk site, breaking first-party
// detection for UK sites.
const CC_TLDS = ["co.uk", "co.jp", "co.kr", "co.nz", "com.au", "com.ph", "com.sg", "com.hk", "com.br", "co.za", "co.in", "com.mx", "co.id", "com.ar", "com.co", "org.uk", "co.th", "com.cn", "co.ke", "net.au", "or.jp", "com.tr", "com.vn"];

/**
 * normalizeHost: Standardizes a hostname for consistent map lookups.
 *
 * WHY IT EXISTS: Cookies arrive with inconsistent domain formats:
 * ".www.mlb.com", "www.mlb.com", "MLB.COM", "mlb.com". Without
 * normalization, the same domain produces different map keys, causing
 * cookie counts to jump (the "cookie count jumping" bug we fixed).
 *
 * HOW IT WORKS: Lowercase, trim whitespace, strip leading dot (set by
 * sites like ".nba.com" to match all subdomains), strip leading "www."
 * so "www.nba.com" and "nba.com" produce the same key.
 *
 * INPUT: Any hostname string (e.g. ".WWW.mlb.com")
 * OUTPUT: Normalized string (e.g. "mlb.com")
 */
function normalizeHost(host) {
  return String(host || "")
    .trim()
    .toLowerCase()
    .replace(/^\./, "")
    .replace(/^www\./, "");
}

/**
 * getRegistrableDomain: Extracts the eTLD+1 (top domain the user owns).
 *
 * WHY IT EXISTS: "ads.google.com" and "mail.google.com" are different
 * subdomains but the SAME registrable domain ("google.com"). We need
 * this to determine first-party vs third-party: a cookie on
 * "ads.google.com" is first-party to "mail.google.com" because they
 * share the registrable domain "google.com".
 *
 * HOW IT WORKS: Splits the hostname by dots. If the last two parts
 * form a ccTLD (e.g. "co.uk"), takes the last three parts. Otherwise
 * takes the last two parts. IP addresses are returned as-is.
 *
 * INPUT: Normalized hostname (e.g. "ads.google.com")
 * OUTPUT: Registrable domain (e.g. "google.com")
 */
function getRegistrableDomain(host) {
  const clean = normalizeHost(host);
  if (!clean) return "";
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  if (/^\d+$/.test(parts[0])) return parts.join(".");
  const suffix = parts.slice(-2).join(".");
  if (CC_TLDS.includes(suffix) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return parts.slice(-2).join(".");
}

/**
 * getCookieOrigin: Determines if a cookie is first-party or third-party.
 *
 * WHY IT EXISTS: First-party and third-party cookies are treated
 * completely differently by every rule in the system. Third-party
 * advertising cookies are always blocked; first-party advertising
 * cookies need corroboration. The score formula also weighs them
 * differently (3P gets higher penalty).
 *
 * HOW IT WORKS: Compares the registrable domain of the cookie's
 * domain with the registrable domain of the current site. If they
 * match → first-party. If not → third-party.
 *
 * INPUT: Cookie domain (e.g. "ads.google.com"), site hostname (e.g. "mail.google.com")
 * OUTPUT: "First-party" or "Third-party"
 */
function getCookieOrigin(cookieDomain, siteHostname) {
  const cookieReg = getRegistrableDomain(cookieDomain);
  const siteReg = getRegistrableDomain(siteHostname);
  return cookieReg && siteReg && cookieReg === siteReg ? "First-party" : "Third-party";
}

/**
 * getCookiePersistence: Determines if a cookie is session or persistent.
 *
 * WHY IT EXISTS: Persistent cookies survive browser restarts and are
 * the primary tracking mechanism. Session cookies are less risky but
 * can still be stolen if they lack security flags. The scoring formula
 * multiplies penalties by longevity — persistent third-party cookies
 * with long lifetimes get the highest penalty.
 *
 * HOW IT WORKS: Checks the browser's `session` flag first (most
 * reliable). For document.cookie-set cookies (no session flag), uses
 * absence of expiry as the session indicator. For cookies with an
 * expiry, marks as persistent. If only HttpOnly is present without
 * expiry info, assumes session. Also calculates days remaining for
 * persistent cookies.
 *
 * INPUT: Cookie object with session, expirationDate, httpOnly, fromDocCookie
 * OUTPUT: { isSession, hasExpiry, daysRemaining }
 */
function getCookiePersistence(cookie) {
  const hasSessionFlag = typeof cookie?.session === "boolean";
  const hasExpiry = Number.isFinite(cookie?.expirationDate);
  const fromDocCookie = !!cookie?.fromDocCookie;
  let isSession;
  if (hasSessionFlag) {
    isSession = cookie.session;
  } else if (fromDocCookie) {
    isSession = !hasExpiry;
  } else if (hasExpiry) {
    isSession = false;
  } else if (cookie?.httpOnly) {
    isSession = true;
  } else {
    isSession = false;
  }
  const daysRemaining = !isSession && hasExpiry
    ? (cookie.expirationDate - Date.now()/1000)/86400
    : null;
  return { isSession, hasExpiry, daysRemaining };
}

/**
 * getDbVendorRecord: Looks up a domain's vendor record from the database.
 *
 * WHY IT EXISTS: The database (cookie_db.json) contains 14,353 domain
 * entries from Disconnect.me and WhoTracksMe. Each entry tells us
 * who operates the domain and what category they fall into. This
 * function is used by the tracker-blocking system to identify
 * tracking vendors, and by the vendor-scope check to validate
 * DB exact-name matches.
 *
 * HOW IT WORKS: First tries an exact match on the normalized hostname.
 * If that fails, tries the registrable domain (so "ads.google.com"
 * falls back to "google.com"). This handles subdomains that aren't
 * individually listed in the database.
 *
 * INPUT: Domain string, database object
 * OUTPUT: Database entry object or null
 */
function getDbVendorRecord(domain, db) {
  const d = normalizeHost(domain);
  if (!d || !db?.domains) return null;
  const reg = getRegistrableDomain(d);
  return db.domains?.[d] || (reg && db.domains?.[reg]) || null;
}

/**
 * getDbTrackerRecord: Same lookup as getDbVendorRecord.
 *
 * WHY IT EXISTS: Kept as a separate function for code clarity —
 * "vendor record" is used for site identification (what company
 * owns this domain), while "tracker record" is used for blocking
 * decisions (is this domain a tracker?). In practice the database
 * stores both in the same `domains` object, so the logic is
 * identical. Named differently so callers express their intent.
 *
 * INPUT: Domain string, database object
 * OUTPUT: Database entry object or null
 */
function getDbTrackerRecord(domain, db) {
  const d = normalizeHost(domain);
  if (!d || !db?.domains) return null;
  const reg = getRegistrableDomain(d);
  return db.domains?.[d] || (reg && db.domains?.[reg]) || null;
}

/**
 * getCookieDbMatch: Matches a cookie name against the database.
 *
 * WHY IT EXISTS: The database contains 1,979 exact cookie-name entries
 * and 264 wildcard prefixes. This is the first and fastest tier of
 * the classification cascade — if the name is in the database, we
 * know its category without needing the ML model.
 *
 * HOW IT WORKS: First tries exact match (lowercase, then original
 * case). If no exact match, tries wildcard prefixes — e.g. "__ga"
 * matches cookies starting with "__ga". Wildcards use the prefix
 * field from the database's `wildcards` array.
 *
 * INPUT: Cookie object (needs .name), database object
 * OUTPUT: Database entry object or null
 */
function getCookieDbMatch(cookie, db) {
  if (!db) return null;
  const name = String(cookie?.name || "");
  const lower = name.toLowerCase();
  const exact = db.lookup?.[lower] || db.lookup?.[name];
  if (exact) return exact;
  const wildcard = Array.isArray(db.wildcards)
    ? db.wildcards.find(w => lower.startsWith(w.prefix))
    : null;
  return wildcard || null;
}

/**
 * vendorNormsMatch: Compares two vendor names for same-family match.
 *
 * WHY IT EXISTS: The database may record "google analytics" as a
 * vendor while a domain record says "google". These are the same
 * vendor family. Simple string equality would miss this, causing
 * the vendor-scope check to wrongly reject valid DB matches.
 *
 * HOW IT WORKS: Returns true if either string contains the other.
 * So "google analytics".includes("google") = true, and
 * "google".includes("google analytics") = false but the reverse
 * catches it. Also handles exact equality.
 *
 * INPUT: Two vendor name strings
 * OUTPUT: Boolean
 */
function vendorNormsMatch(a, b) {
  if (!a || !b) return false;
  return a === b || a.includes(b) || b.includes(a);
}

/**
 * isExactMatchVendorScoped: Validates a DB exact-name match via vendor check.
 *
 * WHY IT EXISTS: The database says cookie "CID" belongs to Adform
 * (an ad vendor). But on Canva, "CID" is Canva's own internal ID —
 * not a tracker. Without this check, the system would wrongly
 * classify Canva's CID as Advertising, triggering false-positive
 * blocking and potentially breaking the site.
 *
 * This function prevents 309 known name collisions measured across
 * the database.
 *
 * HOW IT WORKS:
 * 1. If the DB entry has no vendor info → accept the hit (name is good enough)
 * 2. If the cookie is third-party → accept (cross-site = DB vendor likely applies)
 * 3. Look up the site's vendor and the cookie domain's vendor from the database
 * 4. If either known vendor matches the entry vendor → accept
 * 5. If both are known and neither matches → REJECT (positive contradiction)
 * 6. If vendors are unknown → accept (name is good enough)
 *
 * The key insight: we only reject when we can PROVE the DB entry is
 * wrong for this specific site. When we don't know, we trust the DB.
 *
 * INPUT: Cookie name, cookie domain, site hostname, database, DB entry, quiet flag
 * OUTPUT: Boolean (true = accept the DB match, false = reject it)
 */
function isExactMatchVendorScoped(cookieName, cookieDomain, site, db, exact, quiet) {
  const entryVendor = getVendorNormFromRecord(exact);
  if (!entryVendor) return true;
  const d = normalizeHost(cookieDomain);
  const s = normalizeHost(site);
  if (!d || !s) return true;
  if (getRegistrableDomain(d) !== getRegistrableDomain(s)) return true;
  const siteVendor = getVendorNormFromRecord(getDbVendorRecord(s, db));
  const cookieVendor = getVendorNormFromRecord(getDbVendorRecord(d, db));
  const knownSides = [siteVendor, cookieVendor].filter(Boolean);
  if (!knownSides.length) return true;
  if (knownSides.some(v => vendorNormsMatch(v, entryVendor))) return true;
  if (!quiet) {
    try {
      console.debug("[CC][db-skip]", {
        name: cookieName || "",
        domain: d,
        site: s,
        entryVendor,
        siteVendor: siteVendor || "",
        cookieVendor: cookieVendor || "",
      });
    } catch (e) {}
  }
  return false;
}

/**
 * getVendorLabelFromRecord: Extracts a human-readable vendor name.
 *
 * WHY IT EXISTS: Database records have vendor info in different fields
 * depending on the source — some use "vendor", some "vendor_name",
 * some "platform". This function normalizes the field access so
 * callers don't need to know the source schema.
 *
 * INPUT: Database record (object or string)
 * OUTPUT: Vendor name string (e.g. "Google Analytics")
 */
function getVendorLabelFromRecord(raw) {
  if (!raw) return "";
  if (typeof raw === "string") return raw.trim();
  const vendor = raw?.vendor || raw?.vendor_name || raw?.platform || raw?.vendor_norm;
  return typeof vendor === "string" ? vendor.trim() : "";
}

/**
 * getVendorNormFromRecord: Extracts and normalizes a vendor name.
 *
 * WHY IT EXISTS: Same as getVendorLabelFromRecord, but normalizes
 * the result through normalizeHost for consistent comparison.
 * Used by vendorNormsMatch and isExactMatchVendorScoped where
 * string comparison needs normalized forms.
 *
 * INPUT: Database record (object or string)
 * OUTPUT: Normalized vendor name string (e.g. "google")
 */
function getVendorNormFromRecord(raw) {
  if (!raw) return "";
  if (typeof raw === "string") return normalizeHost(raw);
  const vendor = raw?.vendor_norm || raw?.vendor || raw?.vendor_name || raw?.platform;
  return typeof vendor === "string" ? normalizeHost(vendor) : "";
}

/**
 * getResolvedVendorInfo: Full vendor resolution cascade for a cookie.
 *
 * WHY IT EXISTS: Different parts of the system need to know "who
 * owns this cookie?" The answer comes from multiple sources with
 * different reliability levels. This function tries them in order
 * and returns the best available info.
 *
 * HOW IT WORKS: Cascade of 4 sources, each tried only if the previous
 * failed:
 * 1. Attached vendorResolved object (from background.js enrichment)
 * 2. Cookie-name DB match (1,979 entries — most specific)
 * 3. Domain vendor record (14,353 entries — broader)
 * 4. Domain tracker record (same data, different label)
 *
 * Each result includes: label (display name), norm (normalized for
 * comparison), source (which tier found it), record (raw DB entry),
 * highRisk (whether the domain is on the blocklist).
 *
 * INPUT: Cookie object or domain string, database object
 * OUTPUT: { label, norm, source, record, highRisk } or null
 */
function getResolvedVendorInfo(cookieOrDomain, db) {
  const cookie = typeof cookieOrDomain === "object" && cookieOrDomain ? cookieOrDomain : null;
  const domain = cookie ? cookie.domain : cookieOrDomain;

  if (cookie?.vendorResolved && typeof cookie.vendorResolved === "object") {
    const attached = cookie.vendorResolved;
    const attachedLabel = typeof attached.label === "string" ? attached.label : "";
    const attachedNorm = typeof attached.norm === "string" ? attached.norm : "";
    if (attachedLabel || attachedNorm) {
      return {
        label: attachedLabel,
        norm: attachedNorm,
        source: attached.source || "attached",
        record: attached.record || null,
        highRisk: !!attached.highRisk,
      };
    }
  }

  if (cookie) {
    const match = getCookieDbMatch(cookie, db);
    if (match) {
    return {
      label: getVendorLabelFromRecord(match),
      norm: getVendorNormFromRecord(match),
      source: "cookie",
      record: match,
      highRisk: !!match?.high_risk,
    };
  }
  }

  const vendorRecord = getDbVendorRecord(domain, db);
  if (vendorRecord) {
    return {
      label: getVendorLabelFromRecord(vendorRecord),
      norm: getVendorNormFromRecord(vendorRecord),
      source: "domain",
      record: vendorRecord,
      highRisk: !!vendorRecord?.high_risk,
    };
  }

  const trackerRecord = getDbTrackerRecord(domain, db);
  if (trackerRecord) {
    return {
      label: getVendorLabelFromRecord(trackerRecord),
      norm: getVendorNormFromRecord(trackerRecord),
      source: "tracker",
      record: trackerRecord,
      highRisk: !!trackerRecord?.high_risk,
    };
  }

  return null;
}

// Cache for isDomainInList performance (blocklist has 14,000+ entries)
let _blSet = null;
let _blRef = null;
let _blParents = null;

/**
 * isDomainInList: Checks if a domain is on a given blocklist.
 *
 * WHY IT EXISTS: The Disconnect blocklist and tracker domain list
 * have 14,000+ entries. Checking membership on every cookie event
 * would be slow without caching. This function builds a Set once
 * and reuses it for all subsequent checks on the same list.
 *
 * HOW IT WORKS: On first call (or when the list changes), normalizes
 * all entries into a Set and also builds a "parents" set containing
 * all parent domains (so "ads.google.com" matches if "google.com"
 * is on the list). Then checks the input domain against both sets.
 *
 * The parent-domain expansion is critical: a tracker blocklist may
 * list "google.com" but a cookie comes from "ads.doubleclick.net".
 * Without parent expansion, subdomains would slip through.
 *
 * INPUT: Domain string, list array
 * OUTPUT: Boolean
 */
function isDomainInList(domain, list) {
  const d = normalizeHost(domain);
  if (!d || !Array.isArray(list) || !list.length) return false;
  if (list !== _blRef) {
    const normalized = [];
    const parents = new Set();
    for (const h of list) {
      const n = normalizeHost(h);
      if (!n) continue;
      normalized.push(n);
      parents.add(n);
      const parts = n.split(".");
      for (let i = 1; i < parts.length; i++) {
        if (parts.length - i >= 2) parents.add(parts.slice(i).join("."));
      }
    }
    _blRef = list;
    _blSet = new Set(normalized);
    _blParents = parents;
  }
  if (_blSet.has(d)) return true;
  const parts = d.split(".");
  for (let i = 1; i < parts.length; i++) {
    if (_blParents.has(parts.slice(i).join("."))) return true;
  }
  return false;
}

/**
 * classifyCookie: The 4-tier classification cascade — the core of the system.
 *
 * WHY IT EXISTS: Every cookie must be categorized into one of 5 labels:
 * Strict, Performance, Functionality, Advertising, or Unknown. This
 * drives everything: the privacy score, what gets blocked, what gets
 * kept, what appears in the UI. This single function is the gateway.
 *
 * HOW IT WORKS: Four tiers in strict order. Each tier is tried only
 * if the previous one failed. The first confident result wins:
 *
 * TIER 1 — DB EXACT MATCH (fastest, most reliable):
 *   Cookie name found in 1,979-entry lookup table → use its category.
 *   The vendor-scope check (isExactMatchVendorScoped) prevents false
 *   positives from 309 known name collisions.
 *
 * TIER 2 — DOMAIN TRACKER MATCH:
 *   Third-party cookie on a known tracker domain (14,353 entries from
 *   Disconnect.me + WhoTracksMe + OCD) → use the entry's own category
 *   (Advertising only as fallback when the entry has none).
 *   First-party cookies skip this tier entirely — a first-party cookie
 *   on a tracker domain is the site's own cookie, not a tracker.
 *
 * TIER 3 — ML MODEL:
 *   Random Forest classifier with 360 features, trained on 22,118
 *   records. Only trusted if confidence ≥ 0.30 (the threshold).
 *   Below threshold → falls to Unknown.
 *
 * TIER 4 — UNKNOWN:
 *   No method produced a confident result. The safe default.
 *   Unknown cookies are kept unless corroborated evidence exists.
 *
 * INPUT: Cookie object, site hostname, database object, ML classifier
 * OUTPUT: { cat, method, desc, platform, confidence }
 */
function classifyCookie(cookie, site, db, ml) {
  const name   = (cookie.name || "").toLowerCase();
  const domain = normalizeHost(cookie?.domain || "");
  const BASE = { cat: "Unknown", method: "Unknown", desc: "", platform: "", confidence: null };

  if (db) {
    const exact = getCookieDbMatch(cookie, db);
    if (exact && isExactMatchVendorScoped(cookie?.name || "", domain, site, db, exact)) return { ...BASE, cat: exact.cat || "Unknown", method: "DB", desc: exact.desc || "", platform: exact.platform || "" };

    const isFirstParty = getRegistrableDomain(domain) === getRegistrableDomain(site);
    if (!isFirstParty) {
      const domainMatch = getDbTrackerRecord(domain, db);
      if (domainMatch) return { ...BASE, cat: domainMatch.cat || "Advertising", method: "Domain", desc: domainMatch.vendor || "" };
    }
  }

  if (ml) {
    try {
      const r = ml.predict(cookie, site);
      if (typeof mlDiag === "function") {
        mlDiag({ name: cookie.name, domain: cookie.domain, cat: r.category, conf: r.confidence, trusted: r.trusted, method: r.trusted ? "ML" : "Unknown" });
      }
      if (r?.trusted) return { ...BASE, cat: r.category || "Unknown", method: "ML", confidence: r.confidence };
    } catch(e) { console.warn("[CC] ML error:", e.message); }
  }

  return BASE;
}

/**
 * normalizeSiteWhitelistEntry: Canonicalizes a user-entered whitelist entry (or a
 *   site key) to the extension's site identity — the registrable domain (eTLD+1).
 *
 * WHY IT EXISTS: Users should not have to list every subdomain. Entering
 *   "google.com", "www.google.com", or "mail.google.com" must all resolve to the
 *   same entry, and the site keys the guards compare against are already
 *   registrable domains (tab state assigns getRegistrableDomain(hostname)).
 *   Normalizing both sides through this one function makes membership an exact
 *   comparison, with a dot-boundary suffix check as belt-and-braces.
 *
 * HOW IT WORKS: Lowercases, strips a scheme ("https://"), anything from the first
 *   "/" (path), and a ":port" suffix, then runs getRegistrableDomain() (which
 *   itself normalizes: trim, leading dot, leading "www."). IP addresses and
 *   single-label hosts (localhost) pass through unchanged because
 *   getRegistrableDomain returns them as-is. Returns "" for empty input.
 *
 * INPUT: raw (string — user entry like "https://www.google.com/login" or a siteKey).
 * OUTPUT: string — registrable domain (e.g. "google.com"), or "" if unparseable.
 * Source: Domain-to-registrable-domain mapping — Public Suffix List style eTLD+1
 *   scoping (Mozilla); subdomain-agnostic site identity as used by
 *   getRegistrableDomain() in this file.
 */
function normalizeSiteWhitelistEntry(raw) {
  const cleaned = String(raw || "")
    .trim()
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .split("/")[0]
    .replace(/:\d+$/, "")
    .replace(/^\./, "");
  if (!cleaned) return "";
  return getRegistrableDomain(cleaned) || cleaned;
}

/**
 * siteMatchesWhitelist: Reports whether a site is exempt for one whitelist
 *   (Tracker Blocking's list or Session Guard's list — passed in by the caller,
 *   so the two lists stay fully independent).
 *
 * WHY IT EXISTS: Both enforcement engines need the same membership test: exact
 *   match after registrable normalization covers every subdomain of an entry
 *   (site keys are eTLD+1, so "google.com" already represents mail.google.com),
 *   and the suffix check covers any siteKey that still carries subdomain labels.
 *
 * HOW IT WORKS: Returns false immediately for an empty/non-array list. Normalizes
 *   the site key the same way entries are normalized, then checks list membership
 *   and finally dot-boundary suffix ("sub.example.com" matches entry "example.com"
 *   but "notexample.com" does not).
 *
 * INPUT: siteKey (string — site being judged), list (string[] — one whitelist).
 * OUTPUT: boolean — true if the site is on that whitelist.
 * Source: HTTP state management — cookie domain match semantics, RFC 6265
 *   Section 5.1.3 (domain match: label-boundary suffix, never bare substring).
 */
function siteMatchesWhitelist(siteKey, list) {
  if (!Array.isArray(list) || !list.length) return false;
  const site = normalizeSiteWhitelistEntry(siteKey);
  if (!site) return false;
  for (const raw of list) {
    const entry = normalizeSiteWhitelistEntry(raw);
    if (!entry) continue;
    if (site === entry || site.endsWith("." + entry)) return true;
  }
  return false;
}
