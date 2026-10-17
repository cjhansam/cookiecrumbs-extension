// CookieCrumbs runtime crypto helpers.
// Keeps raw cookie values out of long-lived extension records.

globalThis.CC_CRYPTO = (() => {
  const enc = new TextEncoder();
  let aesKeyPromise = null;
  let hmacKeyPromise = null;

  function bytesToB64(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(String(b64 || ""));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function entropy(s) {
    if (!s) return 0;
    const f = {};
    for (const c of s) f[c] = (f[c] || 0) + 1;
    return -Object.values(f).reduce((sum, n) => {
      const p = n / s.length;
      return sum + p * Math.log2(p);
    }, 0);
  }

  function getValueFeatures(value) {
    const val = String(value || "");
    const valLen = val.length;
    const isUUID = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(val)
                || /^[0-9a-f]{32,}$/i.test(val);
    return {
      length: valLen,
      isUUID,
      isShort: valLen > 0 && valLen <= 12,
      isLong: valLen > 50,
      hasPercentEncoding: val.includes("%"),
      hasJsonBrace: val.includes("{"),
      entropy: Math.round(Math.min(entropy(val) / 5, 1) * 1e4) / 1e4,
      lengthBucket: Math.min(valLen, 200) / 200,
    };
  }

  async function getAesKey() {
    if (!aesKeyPromise) {
      aesKeyPromise = crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"]
      );
    }
    return aesKeyPromise;
  }

  async function getHmacKey() {
    if (!hmacKeyPromise) {
      hmacKeyPromise = crypto.subtle.generateKey(
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
    }
    return hmacKeyPromise;
  }

  async function encryptValue(value) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cipher = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      await getAesKey(),
      enc.encode(String(value || ""))
    );
    return {
      iv: bytesToB64(iv),
      ciphertext: bytesToB64(new Uint8Array(cipher)),
      alg: "AES-GCM",
    };
  }

  async function decryptValue(encryptedValue) {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64ToBytes(encryptedValue.iv) },
      await getAesKey(),
      b64ToBytes(encryptedValue.ciphertext)
    );
    return new TextDecoder().decode(plain);
  }

  async function hmacValue(value) {
    const sig = await crypto.subtle.sign(
      "HMAC",
      await getHmacKey(),
      enc.encode(String(value || ""))
    );
    return bytesToB64(new Uint8Array(sig));
  }

  async function protectCookie(cookie) {
    if (cookie?.valueProtected) return cookie;
    const rawValue = String(cookie?.value || "");
    try {
      const [encryptedValue, cookieID] = await Promise.all([
        encryptValue(rawValue),
        hmacValue(rawValue),
      ]);
      const { value, ...rest } = cookie || {};
      return {
        ...rest,
        encryptedValue,
        cookieID,
        valueFeatures: getValueFeatures(rawValue),
        valueProtected: true,
      };
    } catch (e) {
      console.warn("[CC] crypto.subtle unavailable, storing unencrypted", e?.message);
      const { value, ...rest } = cookie || {};
      return { ...rest, valueFeatures: getValueFeatures(rawValue), valueProtected: false };
    }
  }

  return {
    protectCookie,
    decryptValue,
    getValueFeatures,
  };
})();
