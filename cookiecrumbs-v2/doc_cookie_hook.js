(() => {
  try {
    if (window.__ccDocCookieHookInstalled) return;
    window.__ccDocCookieHookInstalled = true;

    const desc = Object.getOwnPropertyDescriptor(Document.prototype, "cookie");
    if (!desc || typeof desc.get !== "function" || typeof desc.set !== "function") return;

    const notify = () => {
      try {
        window.postMessage({
          source: "CookieCrumbs",
          type: "CC_DOC_COOKIE_CHANGED",
          href: location.href,
        }, "*");
      } catch (e) {}
    };

    Object.defineProperty(Document.prototype, "cookie", {
      configurable: true,
      enumerable: desc.enumerable,
      get() {
        return desc.get.call(this);
      },
      set(value) {
        const result = desc.set.call(this, value);
        queueMicrotask(notify);
        return result;
      },
    });

    notify();
  } catch (e) {}
})();
