// ============================================================
// Cookie Crumbs IndexedDB store
// Seeds cookie_db.json and model_weights.json once, then serves
// them from browser-local storage.
// ============================================================

const CC_DB_NAME = "cookiecrumbs-local-data";
const CC_DB_VERSION = 1;
const CC_META_KEY = "seed_version";

let ccDbPromise = null;
let ccSeedPromise = null;
let ccCache = {
  cookieDb: null,
  modelWeights: null,
};

function ccGetAppVersion() {
  try {
    return chrome?.runtime?.getManifest?.()?.version || "0";
  } catch (e) {
    return "0";
  }
}

function ccOpenDb() {
  if (ccDbPromise) return ccDbPromise;
  ccDbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(CC_DB_NAME, CC_DB_VERSION);

    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("datasets")) {
        db.createObjectStore("datasets");
      }
      if (!db.objectStoreNames.contains("meta")) {
        db.createObjectStore("meta");
      }
    };

    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return ccDbPromise;
}

function ccTx(db, storeName, mode = "readonly") {
  return db.transaction(storeName, mode).objectStore(storeName);
}

function ccGet(storeName, key) {
  return ccOpenDb().then(db => new Promise((resolve, reject) => {
    const req = ccTx(db, storeName).get(key);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  }));
}

function ccSet(storeName, key, value) {
  return ccOpenDb().then(db => new Promise((resolve, reject) => {
    const req = ccTx(db, storeName, "readwrite").put(value, key);
    req.onsuccess = () => resolve(value);
    req.onerror = () => reject(req.error);
  }));
}

async function ccFetchJson(path) {
  const url = chrome.runtime.getURL(path);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to load ${path}: ${resp.status}`);
  return resp.json();
}

async function ccSeedIfNeeded() {
  if (ccSeedPromise) return ccSeedPromise;
  ccSeedPromise = (async () => {
    const appVersion = ccGetAppVersion();
    const storedVersion = await ccGet("meta", CC_META_KEY);
    const cookieDb = await ccGet("datasets", "cookie_db");
    const modelWeights = await ccGet("datasets", "model_weights");

    if (storedVersion === appVersion && cookieDb && modelWeights) {
      ccCache.cookieDb = cookieDb;
      ccCache.modelWeights = modelWeights;
      return ccCache;
    }

    const [freshDb, freshModel] = await Promise.all([
      ccFetchJson("cookie_db.json"),
      ccFetchJson("model_weights.json"),
    ]);

    await new Promise((resolve, reject) => {
      ccOpenDb().then(db => {
        const tx = db.transaction(["datasets", "meta"], "readwrite");
        tx.objectStore("datasets").put(freshDb, "cookie_db");
        tx.objectStore("datasets").put(freshModel, "model_weights");
        tx.objectStore("meta").put(appVersion, CC_META_KEY);
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      }).catch(reject);
    });

    ccCache.cookieDb = freshDb;
    ccCache.modelWeights = freshModel;
    return ccCache;
  })().finally(() => {
    ccSeedPromise = null;
  });
  return ccSeedPromise;
}

const CookieCrumbsStore = {
  async init() {
    await ccOpenDb();
    return ccSeedIfNeeded();
  },
  async getCookieDb() {
    if (ccCache.cookieDb) return ccCache.cookieDb;
    await ccSeedIfNeeded();
    if (ccCache.cookieDb) return ccCache.cookieDb;
    const fromDb = await ccGet("datasets", "cookie_db");
    if (fromDb) ccCache.cookieDb = fromDb;
    return fromDb;
  },
  async getModelWeights() {
    if (ccCache.modelWeights) return ccCache.modelWeights;
    await ccSeedIfNeeded();
    if (ccCache.modelWeights) return ccCache.modelWeights;
    const fromDb = await ccGet("datasets", "model_weights");
    if (fromDb) ccCache.modelWeights = fromDb;
    return fromDb;
  },
  async getAll() {
    await ccSeedIfNeeded();
    return {
      cookieDb: ccCache.cookieDb,
      modelWeights: ccCache.modelWeights,
    };
  },
};

globalThis.CookieCrumbsStore = CookieCrumbsStore;
