// Light or dark mode for the whole app, chosen from View > Mode in the app
// menu. theme.js sets data-theme on <html>; studio.css keys every view's
// palette (app and PE view) off it. The choice is kept in localStorage under
// "mcparser-theme". A stored "system" (from an earlier build) or no value at
// all follows the OS until the user picks Light or Dark. Loaded in <head> so
// the first paint already has the right palette.
(function (root) {
  const KEY = "mcparser-theme";
  const MODES = ["light", "dark"];
  const CHOICES = ["light", "dark", "system"];

  function normalize(v) { return CHOICES.includes(v) ? v : "system"; }
  function resolve(choice, prefersDark) { const c = normalize(choice); return c === "system" ? (prefersDark ? "dark" : "light") : c; }
  function load(storage) { try { return normalize(storage && storage.getItem(KEY)); } catch (_) { return "system"; } }
  function save(storage, mode) {
    if (!MODES.includes(mode)) return null;
    try { storage && storage.setItem(KEY, mode); } catch (_) { /* ignore */ }
    return mode;
  }
  function prefersDark(win) { try { return !!(win.matchMedia && win.matchMedia("(prefers-color-scheme: dark)").matches); } catch (_) { return false; } }
  function storageOf(win, storage) { if (storage) return storage; try { return win.localStorage; } catch (_) { return null; } }

  function apply(doc, choice, dark) {
    const mode = resolve(choice, dark);
    doc.documentElement.dataset.theme = mode;
    doc.documentElement.dataset.themeChoice = normalize(choice);
    return mode;
  }

  // Set data-theme from the stored choice before any UI is mounted.
  function init(doc, storage) {
    const win = doc.defaultView;
    const choice = load(storageOf(win, storage));
    apply(doc, choice, prefersDark(win));
    return choice;
  }

  // Renderer wiring for the View > Mode menu. `bridge` is the preload API:
  // onSetThemeMode(handler) receives "light" or "dark" from the menu, and
  // themeModeChanged(mode) tells main the effective mode so it can check the
  // right radio. Returns { set, get, mode }.
  function connect(doc, bridge, storage) {
    const win = doc.defaultView;
    const st = storageOf(win, storage);
    let choice = load(st);
    let last = null;
    function refresh() {
      const mode = apply(doc, choice, prefersDark(win));
      if (mode !== last) { last = mode; if (bridge && bridge.themeModeChanged) bridge.themeModeChanged(mode); }
      return mode;
    }
    function set(mode) { if (save(st, mode)) choice = mode; return refresh(); }
    if (bridge && bridge.onSetThemeMode) bridge.onSetThemeMode(set);
    const mq = win.matchMedia ? win.matchMedia("(prefers-color-scheme: dark)") : null;
    if (mq) { const f = () => { if (choice === "system") refresh(); }; mq.addEventListener ? mq.addEventListener("change", f) : mq.addListener && mq.addListener(f); }
    refresh();
    return { set, get: () => choice, mode: () => last };
  }

  const api = { KEY, MODES, CHOICES, normalize, resolve, load, save, apply, init, connect };
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.PeTheme = api; if (root.document && root.document.documentElement) init(root.document); }
})(typeof window !== "undefined" ? window : globalThis);
