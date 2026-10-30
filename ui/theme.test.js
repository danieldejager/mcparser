const test = require("node:test");
const assert = require("node:assert");
const T = require("./theme.js");

const mem = (init) => { const m = new Map(init ? [[T.KEY, init]] : []); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), m }; };

test("default is follow system", () => {
  assert.strictEqual(T.load(mem()), "system");
  assert.strictEqual(T.load(mem("purple")), "system");
  assert.strictEqual(T.load(null), "system");
});

test("system resolves from prefers-color-scheme, explicit choices win", () => {
  assert.strictEqual(T.resolve("system", true), "dark");
  assert.strictEqual(T.resolve("system", false), "light");
  assert.strictEqual(T.resolve("light", true), "light");
  assert.strictEqual(T.resolve("dark", false), "dark");
  assert.strictEqual(T.resolve(undefined, true), "dark");
});

test("save persists normalized choice and round trips", () => {
  const s = mem();
  assert.strictEqual(T.save(s, "dark"), "dark");
  assert.strictEqual(T.load(s), "dark");
  T.save(s, "bogus");
  assert.strictEqual(s.m.get(T.KEY), "system");
});

test("storage errors fall back quietly", () => {
  const bad = { getItem() { throw new Error("x"); }, setItem() { throw new Error("x"); } };
  assert.strictEqual(T.load(bad), "system");
  assert.strictEqual(T.save(bad, "light"), "light");
});

test("arrow keys wrap through the radio group", () => {
  assert.strictEqual(T.step("light", "ArrowRight"), "dark");
  assert.strictEqual(T.step("system", "ArrowDown"), "light");
  assert.strictEqual(T.step("light", "ArrowLeft"), "system");
  assert.strictEqual(T.step("dark", "Home"), "light");
  assert.strictEqual(T.step("light", "End"), "system");
  assert.strictEqual(T.step("light", "a"), null);
});

test("init sets data-theme on <html> from storage before mounting", () => {
  const html = { dataset: {} };
  const doc = { documentElement: html, defaultView: { matchMedia: () => ({ matches: true }) } };
  assert.strictEqual(T.init(doc, mem()), "system");
  assert.strictEqual(html.dataset.theme, "dark");
  T.init(doc, mem("light"));
  assert.strictEqual(html.dataset.theme, "light");
  assert.strictEqual(html.dataset.themeChoice, "light");
});

test("app wiring: Appearance lives only in the Preferences dialog", () => {
  const fs = require("node:fs");
  const html = fs.readFileSync(__dirname + "/index.html", "utf8");
  const head = html.slice(0, html.indexOf("</head>"));
  assert.ok(head.includes('src="theme.js"'), "theme.js loads in <head> so the first paint is themed");
  const toolbar = html.slice(html.indexOf('id="toolbar"'), html.indexOf("</header>"));
  assert.ok(!toolbar.includes("app-theme") && !toolbar.includes("tb-appearance"), "toolbar switch is gone");
  assert.strictEqual(html.split('id="app-theme"').length, 2, "exactly one Appearance control");
  assert.ok(/id="prefs-sheet" class="sheet" hidden>[\s\S]*id="app-theme"/.test(html));
  assert.ok(!html.includes('id="pe-theme"'));
  const r = fs.readFileSync(__dirname + "/renderer.js", "utf8");
  assert.ok(r.includes('PeTheme.mount(document.getElementById("app-theme")'));
  assert.ok(r.includes("window.mcparser.onOpenPreferences(openPreferences)"));
});

test("menu: Preferences... with Cmd/Ctrl+, sends a fixed IPC channel", () => {
  const fs = require("node:fs");
  const m = fs.readFileSync(__dirname + "/main.js", "utf8");
  assert.ok(m.includes('const PREFS_CHANNEL = "open-preferences"'));
  assert.ok(/label: "Preferences\.\.\.", accelerator: "CmdOrCtrl\+,", click: \(\) => win && win\.webContents\.send\(PREFS_CHANNEL\)/.test(m));
  assert.ok(m.includes("...(isMac ? [{ type: \"separator\" }, prefsItem] : [])"), "macOS app menu");
  assert.ok(m.includes("...(isMac ? [] : [{ type: \"separator\" }, prefsItem])"), "File menu elsewhere");
  const p = fs.readFileSync(__dirname + "/preload.js", "utf8");
  assert.ok(p.includes('onOpenPreferences: (handler) => ipcRenderer.on("open-preferences", () => handler())'));
});

test("Preferences dialog: choosing a radio applies and persists the theme", () => {
  // Minimal DOM fake, enough for PeTheme.mount.
  const el = (tag) => { const e = { tag, children: [], dataset: {}, attrs: {}, listeners: {}, tabIndex: 0, textContent: "",
    setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return this.attrs[k]; }, appendChild(c) { this.children.push(c); return c; },
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }, focus() { doc.active = this; } }; e.ownerDocument = doc; return e; };
  const store = mem("system");
  const doc = { documentElement: { dataset: {} }, createElement: el, defaultView: { localStorage: store, matchMedia: () => ({ matches: false, addEventListener() {} }) } };
  const host = el("div");
  const ctl = T.mount(host, { label: "Appearance" });
  const group = host.children[0];
  assert.strictEqual(group.attrs.role, "radiogroup");
  const [light, dark, sys] = group.children;
  assert.strictEqual(sys.attrs["aria-checked"], "true");
  dark.listeners.click[0]();
  assert.strictEqual(doc.documentElement.dataset.theme, "dark");
  assert.strictEqual(store.m.get(T.KEY), "dark");
  assert.strictEqual(dark.attrs["aria-checked"], "true");
  assert.strictEqual(dark.tabIndex, 0);
  dark.listeners.keydown[0]({ key: "ArrowLeft", preventDefault() {} });
  assert.strictEqual(ctl.get(), "light");
  assert.strictEqual(store.m.get(T.KEY), "light");
  assert.strictEqual(doc.active, light);
  assert.strictEqual(T.load(store), "light", "same storage key carries over");
});

test("studio.css: every app token has a dark value and no light-only literals remain on core surfaces", () => {
  const css = require("node:fs").readFileSync(__dirname + "/studio.css", "utf8");
  const block = (sel) => { const i = css.indexOf(sel + " {"); return css.slice(i, css.indexOf("}", i)); };
  const names = (b) => [...b.matchAll(/(--app-[a-z0-9-]+):/g)].map((m) => m[1]).sort();
  const light = names(block(":root")), dark = names(block(':root[data-theme="dark"]'));
  assert.ok(light.length > 20);
  assert.deepStrictEqual(dark, light);
  for (const sel of ["aside {", ".editor, .results {", "textarea {", "th {", "#transcript {", ".sheet form {", ".row-menu {", ".tab.active {"]) {
    const rule = css.slice(css.indexOf(sel), css.indexOf("}", css.indexOf(sel)));
    assert.ok(!/background: #(fff|fafafa|f7f7f7)\b/.test(rule), sel + " still has a light-only background");
  }
});

// WCAG relative luminance contrast.
const lum = (hex) => { const n = parseInt(hex.slice(1), 16); return [n >> 16, (n >> 8) & 255, n & 255].map((c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; }).reduce((a, c, i) => a + c * [0.2126, 0.7152, 0.0722][i], 0); };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };

test("text tokens meet WCAG AA (4.5:1) on their surfaces in both themes", () => {
  const css = require("node:fs").readFileSync(__dirname + "/studio.css", "utf8");
  const vars = (sel) => { const i = css.indexOf(sel + " {"); const b = css.slice(i, css.indexOf("}", i)); return Object.fromEntries([...b.matchAll(/--app-([a-z0-9-]+): (#[0-9a-f]{6}|#[0-9a-f]{3})\b/gi)].map((m) => [m[1], m[2].length === 4 ? "#" + [...m[2].slice(1)].map((c) => c + c).join("") : m[2]])); };
  for (const sel of [":root", ':root[data-theme="dark"]']) {
    const v = vars(sel);
    for (const fg of ["fg", "strong", "fg2", "dim", "link", "red", "green", "purple"]) for (const bg of ["bg", "chrome", "surface", "sunken"]) {
      assert.ok(ratio(v[fg], v[bg]) >= 4.5, `${sel} ${fg} on ${bg}: ${ratio(v[fg], v[bg]).toFixed(2)}`);
    }
    assert.ok(ratio("#ffffff", v.run) >= 4.5, sel + " run button");
  }
});
