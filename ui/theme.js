// Theme preference for the PE view: "light", "dark" or "system" (default).
// The app has no shared theme mechanism yet, so the dark tokens in studio.css
// only cover the PE view; data-theme is still set on <html> so other views can
// opt in later. The choice is kept in localStorage like other UI settings.
(function (root) {
  const KEY = "mcparser-theme";
  const CHOICES = ["light", "dark", "system"];
  const LABELS = { light: "Light", dark: "Dark", system: "Follow system" };

  function normalize(v) { return CHOICES.includes(v) ? v : "system"; }
  function resolve(choice, prefersDark) { const c = normalize(choice); return c === "system" ? (prefersDark ? "dark" : "light") : c; }
  function load(storage) { try { return normalize(storage && storage.getItem(KEY)); } catch (_) { return "system"; } }
  function save(storage, choice) { const c = normalize(choice); try { storage && storage.setItem(KEY, c); } catch (_) { /* ignore */ } return c; }
  // Arrow keys move through the radio group, wrapping like native radios.
  function step(choice, key) {
    const i = CHOICES.indexOf(normalize(choice));
    if (key === "ArrowRight" || key === "ArrowDown") return CHOICES[(i + 1) % CHOICES.length];
    if (key === "ArrowLeft" || key === "ArrowUp") return CHOICES[(i + CHOICES.length - 1) % CHOICES.length];
    if (key === "Home") return CHOICES[0];
    if (key === "End") return CHOICES[CHOICES.length - 1];
    return null;
  }

  // Browser wiring: builds a radiogroup inside `host` and keeps <html data-theme> in sync.
  function mount(host, opts) {
    const o = opts || {};
    const doc = host.ownerDocument;
    const win = doc.defaultView;
    const storage = o.storage || win.localStorage;
    const mq = win.matchMedia ? win.matchMedia("(prefers-color-scheme: dark)") : null;
    let choice = load(storage);
    const group = doc.createElement("div");
    group.className = "pe-theme";
    group.setAttribute("role", "radiogroup");
    group.setAttribute("aria-label", "Theme");
    const buttons = CHOICES.map((c) => {
      const b = doc.createElement("button");
      b.type = "button"; b.className = "pe-theme-opt"; b.dataset.choice = c;
      b.setAttribute("role", "radio"); b.textContent = LABELS[c];
      b.addEventListener("click", () => set(c));
      b.addEventListener("keydown", (e) => { const n = step(choice, e.key); if (n) { e.preventDefault(); set(n); buttons[CHOICES.indexOf(n)].focus(); } });
      group.appendChild(b);
      return b;
    });
    function apply() {
      doc.documentElement.dataset.theme = resolve(choice, !!(mq && mq.matches));
      doc.documentElement.dataset.themeChoice = choice;
      buttons.forEach((b) => { const on = b.dataset.choice === choice; b.setAttribute("aria-checked", String(on)); b.tabIndex = on ? 0 : -1; });
    }
    function set(c) { choice = save(storage, c); apply(); }
    if (mq) { const f = () => { if (choice === "system") apply(); }; mq.addEventListener ? mq.addEventListener("change", f) : mq.addListener(f); }
    host.appendChild(group);
    apply();
    return { set, get: () => choice };
  }

  const api = { KEY, CHOICES, LABELS, normalize, resolve, load, save, step, mount };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PeTheme = api;
})(typeof window !== "undefined" ? window : globalThis);
