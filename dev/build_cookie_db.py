#!/usr/bin/env python3
"""
Cookie Crumbs v5.2 — build_cookie_db.py
Builds cookie_db.json from four dataset files.

Sources:
  open-cookie-database.csv  — Kwakman, J. (2023) — github.com/jkwakman/Open-Cookie-Database
  services.json             — Disconnect.me — github.com/disconnectme/disconnect-tracking-protection
  Rules.json                — Consent-O-Matic — Møller & Schoenlau, ACM CHI 2021
  trackers-preview.json     — WhoTracksMe — Cliqz/Ghostery — whotracks.me

Usage:
  python3 build_cookie_db.py \
      --ocd      open-cookie-database.csv \
      --disc     services.json \
      --rules    Rules.json \
      --wtm      trackers-preview.json \
      --out      cookie_db.json
"""
import sys
sys.dont_write_bytecode = True

import argparse, csv, json, re
from collections import Counter

CAT_MAP_OCD = {
    "Functional":      "Functionality",
    "Personalization": "Functionality",
    "Necessary":       "Strict",
    "Security":        "Strict",
    "Analytics":       "Performance",
    "Marketing":       "Advertising",
}

# WhoTracksMe category → our 5 categories
CAT_MAP_WTM = {
    "advertising":          "Advertising",
    "pornvertising":        "Advertising",
    "social_media":         "Advertising",
    "site_analytics":       "Performance",
    "audio_video_player":   "Performance",
    "consent":              "Functionality",
    "customer_interaction": "Functionality",
    "extensions":           "Functionality",
    "hosting":              "Strict",
    "utilities":            "Strict",
    "misc":                 None,   # skip — too ambiguous
}

DISC_CAT_TO_OUR = {
    "Advertising": "Advertising",
    "Analytics": "Performance",
    "Content": "Functionality",
    "ConsentManagers": "Functionality",
    "Anti-fraud": "Strict",
    "FingerprintingGeneral": "Advertising",
    "FingerprintingInvasive": "Advertising",
    "Social": "Advertising",
    "Email": "Advertising",
    "EmailAggressive": "Advertising",
    "Cryptomining": "Advertising",
}
HIGH_RISK = {"Advertising", "FingerprintingInvasive", "Social", "Email", "EmailAggressive", "Cryptomining"}
CC_TLDS = {
    "co.uk", "co.jp", "co.kr", "co.nz", "com.au", "com.ph", "com.sg", "com.hk", "com.br", "co.za",
    "co.in", "com.mx", "co.id", "com.ar", "com.co", "org.uk", "co.th", "com.cn", "co.ke",
    "net.au", "or.jp", "com.tr", "com.vn"
}
CONSENT_KW = [
    "cookie", "consent", "gdpr", "privacy", "cmp", "notice", "banner",
    "popup", "modal", "eprivacy", "onetrust", "cookiebot", "didomi",
    "usercentrics", "quantcast", "trustarc", "borlabs", "iubenda",
    "cookieyes", "cookiefirst", "complianz", "axeptio", "tarteaucitron",
    "consentmanager", "ensighten", "sourcepoint", "snigel", "truste",
    "cc_", "qc-cmp", "cookiebanner", "cookieconsent", "sp_message",
]
GENERIC_SELECTORS = {
    "[class*='consent']",
    "[id*='consent']",
    "[aria-label*='consent']",
    "[aria-label*='cookie consent']",
}
VENDOR_ALIASES = {
    "doubleclick": "google",
    "doubleclick google marketing": "google",
    "google ads": "google",
    "google analytics": "google",
    "google tag manager": "google",
    "google optimize": "google",
    "google maps": "google",
    "google recaptcha": "google",
    "google surveys": "google",
    "facebook": "meta",
    "facebook connect": "meta",
    "meta pixel": "meta",
    "instagram": "meta",
    "cookielawinfo": "cookieyes",
}
SOURCE_PRIORITY = {"OCD": 3, "Disconnect": 2}

def normalize_vendor_name(name):
    if not name:
        return None
    normalized = name.strip().lower().replace("&", " and ")
    normalized = re.sub(r"[^a-z0-9]+", " ", normalized)
    normalized = re.sub(
        r"\b(inc|llc|ltd|limited|corp|corporation|company|gmbh|ag|sa|sas|bv|plc|group|holdings|technology|technologies|tech|solutions|systems|media|software|services)\b",
        " ",
        normalized,
    )
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return VENDOR_ALIASES.get(normalized, normalized or None)

def clean_domain(domain):
    domain = (domain or "").strip().lower()
    if not domain:
        return ""
    domain = re.sub(r"^[a-z]+://", "", domain)
    domain = domain.split("/", 1)[0]
    domain = domain.lstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]
    return domain

def registrable_domain(domain):
    domain = clean_domain(domain)
    parts = [part for part in domain.split(".") if part]
    if len(parts) <= 2:
        return ".".join(parts)
    suffix = ".".join(parts[-2:])
    if suffix in CC_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def build_domain_entry(vendor, vendor_norm, source, cat=None, high_risk=False, extra=None):
    entry = {"vendor": vendor or None, "vendor_norm": vendor_norm or None, "source": source}
    if cat:
        entry["cat"] = cat
    if high_risk:
        entry["high_risk"] = True
    if extra:
        entry.update(extra)
    return entry

def remember_domain(domain_vendors, domain, entry):
    domain = clean_domain(domain)
    if not domain:
        return
    existing = domain_vendors.get(domain)
    incoming_rank = SOURCE_PRIORITY.get(entry["source"], 0)
    existing_rank = SOURCE_PRIORITY.get(existing["source"], 0) if existing else -1
    if not existing or incoming_rank > existing_rank:
        domain_vendors[domain] = entry
        return
    if existing_rank == incoming_rank:
        if existing.get("high_risk") is not True and entry.get("high_risk") is True:
            domain_vendors[domain] = entry
            return
        if not existing.get("cat") and entry.get("cat"):
            domain_vendors[domain] = entry

def selector_score(selector, vendor_count, hit_count):
    lower = selector.lower()
    score = 1
    if selector.startswith("#") or "[data-" in lower or "[id" in lower:
        score += 1
    if any(keyword in lower for keyword in CONSENT_KW if len(keyword) > 3):
        score += 1
    if vendor_count >= 2 or hit_count >= 2:
        score += 1
    if selector in GENERIC_SELECTORS or "*=" in selector or ":not(" in selector:
        score -= 1
    return max(1, min(score, 4))

def build(ocd_path, disc_path, rules_path, wtm_path, out_path):

    # ── 1. Open Cookie Database ───────────────────────────────
    lookup, wildcards, domain_vendors = {}, [], {}
    with open(ocd_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name       = (row.get("Cookie / Data Key name") or "").strip()
            cat_raw    = (row.get("Category") or "").strip()
            desc       = (row.get("Description") or "").strip()[:180]
            platform   = (row.get("Platform") or "").strip()
            controller = (row.get("Data Controller") or "").strip()
            domain     = clean_domain(row.get("Domain"))
            wildcard   = (row.get("Wildcard match") or "0").strip()
            cat        = CAT_MAP_OCD.get(cat_raw)
            if not name or not cat: continue
            vendor_norm = normalize_vendor_name(controller or platform)
            entry = {"cat": cat, "desc": desc, "platform": platform, "vendor_norm": vendor_norm}
            if wildcard == "1" or "*" in name:
                wildcards.append({"prefix": name.replace("*","").lower(), **entry})
            else:
                lookup[name.lower()] = entry
            if domain:
                domain_entry = build_domain_entry(
                    vendor=platform or controller or None,
                    vendor_norm=vendor_norm,
                    source="OCD",
                    cat=cat,
                    extra={"controller": controller or None},
                )
                remember_domain(domain_vendors, domain, domain_entry)
                remember_domain(domain_vendors, registrable_domain(domain), domain_entry)
    print(f"OCD: {len(lookup)} exact, {len(wildcards)} wildcards")

    # ── 2. Disconnect.me ─────────────────────────────────────
    svcs = json.load(open(disc_path, encoding="utf-8"))
    cats_disc = svcs["categories"]
    disconnect_count = 0
    for cat_name, vendors in cats_disc.items():
        mapped_cat = DISC_CAT_TO_OUR.get(cat_name)
        high_risk = cat_name in HIGH_RISK
        for vendor in vendors:
            for vname, vdata in vendor.items():
                vendor_norm = normalize_vendor_name(vname)
                for _url, domains in vdata.items():
                    for d in domains:
                        clean = clean_domain(d)
                        if not clean:
                            continue
                        disconnect_count += 1
                        domain_entry = build_domain_entry(
                            vendor=vname,
                            vendor_norm=vendor_norm,
                            source="Disconnect",
                            cat=mapped_cat,
                            high_risk=high_risk,
                            extra={"disconnect_cat": cat_name},
                        )
                        remember_domain(domain_vendors, clean, domain_entry)
                        remember_domain(domain_vendors, registrable_domain(clean), domain_entry)
    print(f"Disconnect: {disconnect_count} domains")

    # ── 3. Consent-O-Matic Rules.json ─────────────────────────
    rules = json.load(open(rules_path, encoding="utf-8"))
    selector_hits = {}
    def extract(obj, vendor_name):
        if isinstance(obj, dict):
            if "selector" in obj and isinstance(obj["selector"], str):
                hit = selector_hits.setdefault(obj["selector"], {"count": 0, "vendors": set()})
                hit["count"] += 1
                hit["vendors"].add(vendor_name)
            for v in obj.values():
                extract(v, vendor_name)
        elif isinstance(obj, list):
            for v in obj:
                extract(v, vendor_name)
    for vendor_name, rule in rules.items():
        extract(rule, vendor_name)
    cmp_selector_entries = []
    for selector, hit in selector_hits.items():
        lower = selector.lower()
        if not selector or len(selector) <= 2:
            continue
        if not any(keyword in lower for keyword in CONSENT_KW):
            continue
        cmp_selector_entries.append({
            "selector": selector,
            "score": selector_score(selector, len(hit["vendors"]), hit["count"]),
            "count": hit["count"],
            "vendor_count": len(hit["vendors"]),
        })
    cmp_selector_entries.sort(key=lambda item: (-item["score"], -item["count"], -len(item["selector"]), item["selector"]))
    banner_sels = [item["selector"] for item in cmp_selector_entries]
    print(f"Consent-O-Matic: {len(selector_hits)} total, {len(banner_sels)} banner selectors")

    # ── 4. WhoTracksMe trackers-preview.json ─────────────────
    # Source: whotracks.me — Cliqz GmbH / Ghostery
    # Maps tracker domains to their primary category from
    # real-world crawl data across millions of pages.
    # Merges into domain_vendors to create a single unified domains dict.
    wtm      = json.load(open(wtm_path, encoding="utf-8"))
    wtm_cats = wtm["categories"]    # list: index → category name
    wtm_data = wtm["trackers"]      # domain → [count per category]
    wtm_count = 0
    wtm_new = 0
    for domain, counts in wtm_data.items():
        best_cat_raw, best_count = None, 0
        for i, count in enumerate(counts):
            if count > best_count and i < len(wtm_cats):
                best_count   = count
                best_cat_raw = wtm_cats[i]
        if best_cat_raw and best_count >= 1:
            our_cat = CAT_MAP_WTM.get(best_cat_raw)
            if our_cat:
                clean = clean_domain(domain)
                if not clean:
                    continue
                wtm_count += 1
                existing = domain_vendors.get(clean) or domain_vendors.get(registrable_domain(clean))
                if existing:
                    existing["cat"] = our_cat
                    existing["wtm_cat"] = best_cat_raw
                    existing["count"] = best_count
                else:
                    wtm_new += 1
                    domain_vendors[clean] = {
                        "cat": our_cat,
                        "vendor": None,
                        "vendor_norm": None,
                        "source": "WhoTracksMe",
                        "wtm_cat": best_cat_raw,
                        "count": best_count,
                    }
    print(f"WhoTracksMe: {wtm_count} domains merged ({wtm_new} new)")
    dist = Counter(v.get("cat") for v in domain_vendors.values())
    print(f"  Domain distribution: {dict(dist.most_common())}")

    # ── 5. Assemble ───────────────────────────────────────────
    db = {
        "_meta": {
            "sources": {
                "lookup":    "Open Cookie Database — Kwakman, J. (2023) — github.com/jkwakman/Open-Cookie-Database",
                "domains":   "Merged: Disconnect.me + WhoTracksMe + OCD",
                "selectors": "Consent-O-Matic — Møller & Schoenlau, ACM CHI 2021 — github.com/cavi-au/Consent-O-Matic",
                "model":     "CookieBlock Dataset — Bollinger et al. USENIX Security 2022 — github.com/dibollinger/CookieBlock-Consent-Classifier",
            },
            "counts": {
                "ocd_exact":     len(lookup),
                "ocd_wildcard":  len(wildcards),
                "domains":       len(domain_vendors),
                "cmp_selectors": len(banner_sels),
                "cmp_scored_selectors": len(cmp_selector_entries),
            }
        },
        "lookup":          lookup,
        "wildcards":       wildcards,
        "domains":         domain_vendors,
        "cmp_selectors":   banner_sels,
        "cmp_selector_entries": cmp_selector_entries,
    }
    out = json.dumps(db, separators=(",",":"))
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out)
    print(f"\ncookie_db.json: {len(out)/1024:.1f} KB")
    print("Counts:", db["_meta"]["counts"])

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--ocd",   default="open-cookie-database.csv")
    ap.add_argument("--disc",  default="services.json")
    ap.add_argument("--rules", default="Rules.json")
    ap.add_argument("--wtm",   default="trackers-preview.json")
    ap.add_argument("--out",   default="cookie_db.json")
    args = ap.parse_args()
    build(args.ocd, args.disc, args.rules, args.wtm, args.out)
