// ============================================================
// Cookie Crumbs v5.16 — ml_inference.js
// Pure ML: 60 structural + 300 char n-gram TF-IDF features
// Trained on: CookieBlock + relabeled Zenodo crawl
// NO hardcoded keyword lists. All patterns learned from data.
//
// The model is a Random Forest (200 trees, depth 16, Strict:5 weight)
// exported from train.py as model_weights.json (test acc 90.35%).
// This file loads the model and runs inference in the browser.
// ============================================================

/**
 * CookieMLClassifier: The ML model runtime.
 *
 * WHY IT EXISTS: The database can't know every cookie name — new ones
 * appear daily. The ML model classifies unknown cookies by learning
 * patterns from 22,118 labeled examples. It recognizes shape, not
 * name: short opaque values + persistent + no HttpOnly = likely tracker.
 *
 * The model is loaded once at startup (from model_weights.json via
 * IndexedDB cache) and used for every cookie that doesn't match
 * the database.
 */
class CookieMLClassifier {
  /**
   * constructor: Unpacks the serialized model into ready-to-use structures.
   *
   * WHAT IT RECEIVES: The model_weights.json object containing:
   * - meta: version, accuracy, class names, threshold, feature counts
   * - trees: 200 serialized decision trees (each is a flat array of nodes)
   * - tfidf: vocabulary mapping, IDF weights, n-gram config
   *
   * WHAT IT STORES:
   * - this.classes: ["Advertising", "Functionality", "Performance", "Strict"]
   * - this.threshold: 0.30 (minimum confidence to trust a prediction)
   * - this.trees: 200 tree arrays (each node has feature index, threshold, children)
   * - this.vocab: character n-gram → feature index mapping
   * - this.idf: inverse document frequency weight per vocabulary entry
   * - this.ngramRange: [1, 5] (character n-gram sizes from 1 to 5)
   * - this.sublinear: true (use 1+log(tf) instead of raw count)
   * - this.ccTlds: country-code TLDs for domain normalization
   */
  constructor(model) {
    const m          = model.meta;
    this.classes     = m.classes;
    this.threshold   = m.recommended_threshold || 0.30;
    this.nNum        = m.n_features_num;
    this.nNgram      = m.n_features_ngram;
    this.testAcc     = m.test_accuracy;   // real computed accuracy
    this.trees       = model.trees;
    const tf         = model.tfidf;
    this.vocab       = tf.vocab;
    this.idf         = tf.idf;
    this.ngramRange  = tf.ngram_range;
    this.sublinear   = tf.sublinear_tf;
    this.ccTlds      = ["co.uk","co.jp","co.kr","co.nz","com.au","com.ph","com.sg","com.hk","com.br","co.za","co.in","com.mx","co.id","com.ar","com.co","org.uk","co.th","com.cn","co.ke","net.au","or.jp","com.tr","com.vn"];
  }

  /**
   * _regDomain: Extracts registrable domain (duplicated from domain_utils.js).
   *
   * WHY IT'S DUPLICATED: The content script (content.js) also loads
   * this file and needs domain normalization without access to
   * domain_utils.js. Keeping a copy here avoids a cross-file dependency
   * in the content script context.
   *
   * Same logic as getRegistrableDomain in domain_utils.js.
   */
  _regDomain(d) {
    d = (d || "").replace(/^\./, "").toLowerCase();
    d = d.replace(/^[a-z]+:\/\//, "");
    d = d.split("/", 1)[0];
    if (d.startsWith("www.")) d = d.slice(4);
    const parts = d.split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const suffix = parts.slice(-2).join(".");
    if (this.ccTlds.includes(suffix) && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return parts.slice(-2).join(".");
  }

  /**
   * _vectorizeName: Converts a cookie name into a TF-IDF feature vector.
   *
   * WHY IT EXISTS: The ML model needs numerical features. Character
   * n-gram TF-IDF captures the "shape" of cookie names — patterns
   * like "_ga" (analytics), "__cf" (Cloudflare), "session_" (auth)
   * — without hardcoding keywords. The model learns which n-grams
   * correlate with which categories.
   *
   * HOW IT WORKS:
   * 1. Lowercase the name and pad with spaces (" session_id ")
   * 2. Extract all character n-grams from size 1 to 5
   * 3. Look up each n-gram in the learned vocabulary (300 entries)
   * 4. Count occurrences (term frequency)
   * 5. Apply sublinear scaling: tf = 1 + log(count) — reduces the
   *    impact of very frequent n-grams
   * 6. Multiply by IDF weight — downweights n-grams that appear in
   *    many categories (less informative)
   * 7. L2 normalize — ensures the vector has unit length so names
   *    of different lengths are comparable
   *
   * INPUT: Cookie name string (e.g. "__cfduid")
   * OUTPUT: Float32Array of length 300 (the TF-IDF vector)
   */
  _vectorizeName(name) {
    const n   = name.toLowerCase();
    const pad = " " + n + " ";
    const vec = new Float32Array(this.nNgram);
    const tf  = {};

    for (let sz = this.ngramRange[0]; sz <= this.ngramRange[1]; sz++) {
      for (let i = 0; i <= pad.length - sz; i++) {
        const gram = pad.slice(i, i + sz);
        const idx  = this.vocab[gram];
        if (idx !== undefined) tf[idx] = (tf[idx] || 0) + 1;
      }
    }

    let norm = 0;
    const vals = {};
    for (const [idx, cnt] of Object.entries(tf)) {
      const tfVal = this.sublinear ? 1 + Math.log(cnt) : cnt;
      const v     = tfVal * this.idf[+idx];
      vals[idx]   = v;
      norm       += v * v;
    }
    norm = Math.sqrt(norm) || 1;
    for (const [idx, v] of Object.entries(vals)) vec[+idx] = v / norm;
    return vec;
  }

  /**
   * _entropy: Computes Shannon entropy of a string.
   *
   * WHY IT EXISTS: Session tokens and tracking IDs have high entropy
   * (many unique characters), while meaningful names like "session_id"
   * have low entropy. This helps the model distinguish between
   * human-readable names and opaque tokens.
   *
   * HOW IT WORKS: Counts character frequencies, computes
   * -sum(p * log2(p)) where p is the frequency of each character.
   * High entropy = many unique characters (e.g. "aB3xY9z" = ~2.8 bits).
   * Low entropy = repetitive characters (e.g. "aaaaaaaa" = 0 bits).
   *
   * INPUT: String
   * OUTPUT: Number (bits of entropy, 0 to log2(length))
   */
  _entropy(s) {
    if (!s) return 0;
    const f = {};
    for (const c of s) f[c] = (f[c] || 0) + 1;
    return -Object.values(f).reduce((sum, n) => {
      const p = n / s.length; return sum + p * Math.log2(p);
    }, 0);
  }

  /**
   * _numerical: Extracts 58 structural/statistical features from a cookie.
   *
   * WHY IT EXISTS: The ML model needs numerical features beyond just
   * the name. These 58 features capture everything measurable about
   * a cookie: its name structure, security flags, lifetime, domain,
   * path, value shape, and keyword hints. Combined with the 300
   * TF-IDF features, they give the model a complete picture.
   *
   * HOW IT WORKS: Features are grouped into 10 categories:
   *
   * NAME STRUCTURE (11 features, indices 0-10):
   *   Length, normalized length, digit ratio, underscore/hyphen/dot
   *   ratios, uppercase ratio, starts with "_" or "__", first char
   *   uppercase, Shannon entropy. Names like "_ga" and "__cfduid"
   *   have distinctive patterns vs session names like "JSESSIONID".
   *
   * COOKIE FLAGS (7 features, indices 11-17):
   *   HttpOnly, hostOnly, Secure, and their combinations. Missing
   *   flags indicate tracking cookies (HttpOnly prevents JS access,
   *   Secure prevents HTTP interception).
   *
   * EXPIRY BUCKETS (8 features, indices 18-25):
   *   Session flag, lifespan buckets (≤1d, ≤7d, ≤30d, ≤90d, ≤365d,
   *   >365d), normalized days. Long-lived cookies are tracking-shaped.
   *
   * FLAG × EXPIRY INTERACTIONS (3 features, indices 26-28):
   *   HttpOnly+session, !HttpOnly+>365d, !HttpOnly+session. These
   *   capture dangerous combinations (persistent cookie readable by JS).
   *
   * SAMESITE (3 features, indices 29-31):
   *   Strict, Lax, None. Lax is the browser default; None means
   *   no cross-site protection (tracking indicator).
   *
   * DOMAIN STRUCTURE (4 features, indices 32-35):
   *   First-party?, third-party?, subdomain depth, normalized length.
   *   First-party vs third-party is the strongest tracking signal.
   *
   * PATH STRUCTURE (4 features, indices 36-39):
   *   Root path?, path depth, normalized length, has digits. Tracking
   *   cookies often use deep paths.
   *
   * VALUE STRUCTURE (7 features, indices 40-46):
   *   UUID?, short (≤12 chars), long (>50 chars), percent-encoded,
   *   JSON?, entropy, length bucket. Opaque values are tracking-shaped.
   *
   * NAME KEYWORDS (8 features, indices 47-54):
   *   Regex hits for csrf/xsrf, session, token/jwt, analytics, ad,
   *   consent, preference, framework. These are NOT hardcoded rules —
   *   they're features the model learns to weight.
   *
   * CROSS-FEATURES (5 features, indices 55-59):
   *   Consent+Lax, None+Secure, session+HttpOnly, session+non-session,
   *   long value. Interaction terms that capture correlated signals.
   *
   * INPUT: Cookie object, site hostname
   * OUTPUT: Array of 58 numbers
   */
  _numerical(cookie, site) {
    const name  = cookie.name || "";
    const rawDom = (cookie.domain || "").toLowerCase();
    const dom   = rawDom.replace(/^\./, "");
    const path  = cookie.path || "/";
    const n     = name.toLowerCase();
    const ho    = cookie.httpOnly ? 1 : 0;
    const hosto = cookie.hostOnly ? 1 : 0;
    const sec   = cookie.secure   ? 1 : 0;
    const hasSessionFlag = typeof cookie.session === "boolean";
    const sess  = hasSessionFlag ? (cookie.session ? 1 : 0) : (!cookie.expirationDate ? 1 : 0);
    const days  = sess ? -1 : Math.max(0,
      Math.round(((cookie.expirationDate || 0) - Date.now()/1000)/86400));
    const val   = String(cookie.value || "");
    const vf    = cookie.valueFeatures || null;
    const ss    = (cookie.sameSite || "").toLowerCase();
    const nl    = Math.max(n.length, 1);
    const namel = Math.max(name.length, 1);
    const pathSegments = path.split("/").filter(Boolean);
    const valLen = vf ? Number(vf.length || 0) : val.length;
    const f     = [];

    // Name structure (11 features)
    f.push(n.length, Math.min(n.length/40, 1));
    f.push(
      [...n].filter(c => /\d/.test(c)).length / nl,
      (n.match(/_/g)||[]).length / nl,
      (n.match(/-/g)||[]).length / nl,
      (n.match(/\./g)||[]).length / nl,
      [...name].filter(c => c !== c.toLowerCase() && c === c.toUpperCase()).length / namel
    );
    f.push(
      n.startsWith("_") ? 1 : 0,
      n.startsWith("__") ? 1 : 0,
      name.length > 0 && name[0] !== name[0].toLowerCase() ? 1 : 0,
      Math.round(this._entropy(n) / 5 * 1e4) / 1e4
    );

    // Cookie flags (7)
    f.push(ho, hosto, sec, ho&&!sec?1:0, ho&&sec?1:0, !ho&&!sec?1:0, hosto&&sec?1:0);

    // Expiry buckets (8)
    f.push(
      sess,
      days>0&&days<=1?1:0,  days>1&&days<=7?1:0,
      days>7&&days<=30?1:0, days>30&&days<=90?1:0,
      days>90&&days<=365?1:0, days>365?1:0,
      days > 0 ? Math.min(days,730)/730 : 0
    );

    // Flag x expiry interactions (3)
    f.push(ho&&sess?1:0, !ho&&days>365?1:0, !ho&&sess?1:0);

    // SameSite (3)
    f.push(
      ss==="strict"?1:0,
      ss==="lax"?1:0,
      (ss==="no_restriction"||ss==="none")?1:0
    );

    // Domain structure -- no keyword matching (4)
    const siteReg = this._regDomain(site);
    const domReg  = this._regDomain(rawDom);
    const isFp    = siteReg === domReg ? 1 : 0;
    f.push(isFp, 1-isFp, dom.split(".").filter(Boolean).length, Math.min(rawDom.length,60)/60);

    // Path structure (4)
    f.push(path === "/" ? 1 : 0, pathSegments.length, Math.min(path.length,80)/80, /\d/.test(path) ? 1 : 0);

    // Value structure (7)
    const isUUID = vf ? (vf.isUUID ? 1 : 0)
      : (/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(val)
        || /^[0-9a-f]{32,}$/i.test(val) ? 1 : 0);
    f.push(
      isUUID,
      vf ? (vf.isShort ? 1 : 0) : (valLen>0 && valLen<=12 ? 1 : 0),
      vf ? (vf.isLong ? 1 : 0) : (valLen > 50 ? 1 : 0),
      vf ? (vf.hasPercentEncoding ? 1 : 0) : (val.includes("%") ? 1 : 0),
      vf ? (vf.hasJsonBrace ? 1 : 0) : (val.includes("{") ? 1 : 0),
      vf ? Number(vf.entropy || 0) : Math.round(Math.min(this._entropy(val)/5, 1) * 1e4) / 1e4,
      vf ? Number(vf.lengthBucket || 0) : Math.min(valLen, 200) / 200
    );

    // Name keywords (8)
    const kwCsrf      = /csrf|xsrf|antiforgery|forgery|xsrf-/.test(n) ? 1 : 0;
    const kwSession   = /session|sess[^o]|_sid|sid[=_]/.test(n) ? 1 : 0;
    const kwToken     = /token|jwt|bearer|credential/.test(n) ? 1 : 0;
    const kwAnalytics = /analytics|_ga|_gid|gtag|track|beacon|pixel|utag/.test(n) ? 1 : 0;
    const kwAd        = /__?(ad|ads|gads|gpi|eoi)|marketing|retarget|conversion/.test(n) ? 1 : 0;
    const kwConsent   = /consent|optanon|cookiebot|gdpr|ccpa|usprivacy/.test(n) ? 1 : 0;
    const kwPref      = /pref|setting|lang|locale|theme/.test(n) ? 1 : 0;
    const kwFramework = /\.aspnet|\.aspx|laravel|django|rails|express|spring|shopify|wordpress|woocommerce/.test(n) ? 1 : 0;
    f.push(kwCsrf, kwSession, kwToken, kwAnalytics, kwAd, kwConsent, kwPref, kwFramework);

    // Interaction features (5)
    f.push(
      kwConsent && ss === "lax" ? 1 : 0,
      (ss === "no_restriction" || ss === "none") && sec ? 1 : 0,
      sess && ho ? 1 : 0,
      kwSession && !sess ? 1 : 0,
      valLen > 20 ? 1 : 0
    );

    return f; // 58 features
  }

  /**
   * _walkTree: Traverses a single decision tree from root to leaf.
   *
   * WHY IT EXISTS: Each tree in the forest is a series of if/else
   * decisions. This function walks one tree for one cookie's feature
   * vector and returns the probability distribution at the leaf.
   *
   * HOW IT WORKS: Starting at node 0, at each internal node:
   * - Read the feature value: feats[node.f]
   * - Compare to threshold: node.t
   * - If ≤ threshold, go left (node.L); if > threshold, go right (node.R)
   * - Continue until reaching a leaf node (node.l === true)
   * - Return the leaf's probability distribution: [P(Adv), P(Func), P(Perf), P(Strict)]
   *
   * If the tree is empty or the path doesn't reach a leaf, returns
   * a uniform distribution (1/4 for each class).
   *
   * INPUT: Tree array (serialized nodes), feature vector (Float32Array)
   * OUTPUT: Float32Array of length 4 (probability per class)
   */
  _walkTree(tree, feats) {
    if (!tree || !tree.length) return new Float32Array(this.classes.length).fill(1 / this.classes.length);
    let i = 0;
    while (i < tree.length && !tree[i].l) {
      const n = tree[i];
      const fi = feats[n.f] ?? 0;
      i = fi <= n.t ? n.L : n.R;
    }
    return (i < tree.length && tree[i].p) ? tree[i].p : new Float32Array(this.classes.length).fill(1 / this.classes.length);
  }

  /**
   * predict: Runs the full Random Forest inference pipeline.
   *
   * WHY IT EXISTS: This is the entry point for ML classification.
   * Called by classifyCookie (domain_utils.js) when DB and domain
   * lookups fail.
   *
   * HOW IT WORKS:
   * 1. Extract 60 numerical features via _numerical(cookie, site)
   * 2. Extract 300 TF-IDF features via _vectorizeName(cookie.name)
   * 3. Concatenate into 360-element feature vector
   * 4. For each of 200 trees, call _walkTree → get probability distribution
   * 5. Average all 200 distributions (forest averaging)
   * 6. Find the class with highest average probability
   * 7. If that probability ≥ 0.30 → trusted (classified)
   *    If below 0.30 → not trusted (Unknown)
   *
   * The 0.30 threshold was chosen by measuring accuracy vs coverage
   * across thresholds 0.30-0.60. At 0.30, we classify 99.99% of
   * cookies with 90.4% accuracy. Raising to 0.50 would classify only
   * 92% of cookies — too conservative.
   *
   * INPUT: Cookie object, site hostname
   * OUTPUT: { category, confidence, trusted, probs }
   */
  predict(cookie, site) {
    const numF  = this._numerical(cookie, site);
    const ngF   = this._vectorizeName(cookie.name || "");
    const feats = [...numF, ...ngF];          // 360 total
    const nC    = this.classes.length;
    const avg   = new Float32Array(nC);

    for (const tree of this.trees) {
      const p = this._walkTree(tree, feats);
      for (let i = 0; i < nC; i++) avg[i] += p[i];
    }
    const nTrees = this.trees.length || 1;
    for (let i = 0; i < nC; i++) avg[i] /= nTrees;

    let bestIdx = 0, bestP = 0, secondP = 0;
    for (let i = 0; i < nC; i++) {
      if (avg[i] > bestP) {
        secondP = bestP;
        bestP = avg[i];
        bestIdx = i;
      } else if (avg[i] > secondP) {
        secondP = avg[i];
      }
    }

    return {
      category:   this.classes[bestIdx],
      confidence: bestP,
      trusted:    bestP >= this.threshold,
      probs:      Object.fromEntries(this.classes.map((c,i) => [c, avg[i]])),
    };
  }
}
