// ============================================================
// Cookie Crumbs v5.3 - cookie_intel.js
// Per-cookie data descriptions
// Source: Open Cookie Database - Kwakman, J. (2023)
// ============================================================

function lookupIntelDomain(rawDomain, dbOverride) {
  return getResolvedVendorInfo(rawDomain, dbOverride || DB);
}

function getCookieIntel(name, category, rawDomain, dbOverride) {
  const db = dbOverride || DB;
  const n = (name || "").toLowerCase();

  // Category fallbacks
  const FB = {
    Strict:        {data:["Session identifier","Security token","CSRF protection","Load-balancer routing"],dest:"First party server only",risk:"None - essential for site function"},
    Performance:   {data:["Page views & session duration","Device type & browser","Click paths & referrer","A/B test assignment"],dest:"Analytics provider (typically US-based)",risk:"Low - anonymised analytics"},
    Functionality: {data:["Language & region preference","Login state","Shopping cart","Consent choices"],dest:"First party or CMP provider",risk:"Low - user preference storage"},
    Advertising:   {data:["Browsing history across sites","Unique advertising identifier","Interests & demographics","Ad impressions & clicks","Conversion events"],dest:"Ad network & data brokers (typically US-based)",risk:"High - cross-site tracking & profiling"},
    Unknown:       {data:["Purpose not identified"],dest:"Unknown",risk:"Review manually"},
  };

  if (typeof db === "object" && db) {
    const exact = db.lookup?.[n] || db.lookup?.[name];
    const wildcard = Array.isArray(db.wildcards)
      ? db.wildcards.find(w => n.startsWith(w.prefix))
      : null;
    const ocd = exact || wildcard;

    if (ocd) {
      const fb = FB[ocd.cat] || FB[category] || FB.Unknown;
      return {
        isSpecific: true,
        vendor: ocd.platform || null,
        dataGathered: ocd.desc ? [ocd.desc] : fb.data,
        destination: fb.dest,
        risk: fb.risk,
        docs: null,
      };
    }
  }

  const domainIntel = lookupIntelDomain(rawDomain, db);
  const fb = FB[category] || FB.Unknown;
  return {
    isSpecific:false,
    vendor:domainIntel?.label || null,
    dataGathered:fb.data,
    destination:domainIntel?.label ? `Third-party service: ${domainIntel.label}` : fb.dest,
    risk:domainIntel?.highRisk ? "Known high-risk tracker infrastructure" : fb.risk,
    docs:null
  };
}
