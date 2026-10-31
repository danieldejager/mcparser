const test = require("node:test");
const assert = require("node:assert");
const T = require("./theme.js");

const mem = (init) => { const m = new Map(init ? [[T.KEY, init]] : []); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), m }; };

test("no stored value or a stored system value follows the OS", () => {
  assert.strictEqual(T.load(mem()), "system");
  assert.strictEqual(T.load(mem("system")), "system");
  assert.strictEqual(T.load(mem("purple")), "system");
  assert.strictEqual(T.load(null), "system");
  assert.strictEqual(T.resolve("system", true), "dark");
  assert.strictEqual(T.resolve("system", false), "light");
  assert.strictEqual(T.resolve("light", true), "light");
  assert.strictEqual(T.resolve("dark", false), "dark");
});

test("save stores only light or dark under mcparser-theme", () => {
  assert.strictEqual(T.KEY, "mcparser-theme");
  const s = mem();
  assert.strictEqual(T.save(s, "dark"), "dark");
  assert.strictEqual(T.load(s), "dark");
  assert.strictEqual(T.save(s, "bogus"), null);
  assert.strictEqual(T.save(s, "system"), null);
  assert.strictEqual(s.m.get(T.KEY), "dark");
});

test("storage errors fall back quietly", () => {
  const bad = { getItem() { throw new Error("x"); }, setItem() { throw new Error("x"); } };
  assert.strictEqual(T.load(bad), "system");
  assert.strictEqual(T.save(bad, "light"), "light");
});

test("init sets data-theme on <html> from storage before any UI (no flash)", () => {
  const html = { dataset: {} };
  const doc = { documentElement: html, defaultView: { matchMedia: () => ({ matches: true }) } };
  assert.strictEqual(T.init(doc, mem()), "system");
  assert.strictEqual(html.dataset.theme, "dark");
  T.init(doc, mem("light"));
  assert.strictEqual(html.dataset.theme, "light");
  const fs = require("node:fs");
  const page = fs.readFileSync(__dirname + "/index.html", "utf8");
  assert.ok(page.slice(0, page.indexOf("</head>")).includes('src="theme.js"'), "theme.js loads in <head> so the first paint is themed");
});

function fakeRenderer(stored, osDark) {
  const store = mem(stored);
  const listeners = [];
  const doc = { documentElement: { dataset: {} }, defaultView: { localStorage: store, matchMedia: () => ({ matches: osDark, addEventListener(_t, f) { listeners.push(f); } }) } };
  const sent = [];
  let handler = null;
  const bridge = { themeModeChanged: (m) => sent.push(m), onSetThemeMode: (h) => { handler = h; } };
  const ctl = T.connect(doc, bridge);
  return { store, doc, sent, ctl, pick: (m) => handler(m), osChange: (dark) => { osDark = dark; doc.defaultView.matchMedia = () => ({ matches: dark }); listeners.forEach((f) => f()); } };
}

test("View > Mode: startup reports the effective mode so the menu can check it", () => {
  const r = fakeRenderer(null, true);
  assert.deepStrictEqual(r.sent, ["dark"], "follows the OS until the user picks");
  assert.strictEqual(r.doc.documentElement.dataset.theme, "dark");
  assert.deepStrictEqual(fakeRenderer("light", true).sent, ["light"]);
  assert.deepStrictEqual(fakeRenderer("system", false).sent, ["light"]);
});

test("View > Mode: picking Light or Dark applies at once, persists, and reports back", () => {
  const r = fakeRenderer(null, false);
  r.pick("dark");
  assert.strictEqual(r.doc.documentElement.dataset.theme, "dark");
  assert.strictEqual(r.store.m.get(T.KEY), "dark");
  assert.deepStrictEqual(r.sent, ["light", "dark"]);
  r.osChange(false);
  assert.strictEqual(r.doc.documentElement.dataset.theme, "dark", "an explicit pick ignores the OS");
  r.pick("light");
  assert.strictEqual(r.store.m.get(T.KEY), "light");
  assert.strictEqual(r.doc.documentElement.dataset.theme, "light");
  assert.deepStrictEqual(r.sent, ["light", "dark", "light"]);
  assert.strictEqual(T.load(r.store), "light", "same storage key carries over a restart");
});

test("View > Mode: with no pick yet, an OS change is followed and reported", () => {
  const r = fakeRenderer(null, false);
  r.osChange(true);
  assert.strictEqual(r.doc.documentElement.dataset.theme, "dark");
  assert.deepStrictEqual(r.sent, ["light", "dark"]);
  assert.strictEqual(r.store.m.has(T.KEY), false, "following the OS writes nothing");
});

test("menu: View follows Edit and holds Mode > Light / Dark radios on fixed IPC channels", () => {
  const fs = require("node:fs");
  const m = fs.readFileSync(__dirname + "/main.js", "utf8");
  const edit = m.indexOf('label: "Edit"'), view = m.indexOf("    viewMenu(),\n"), audit = m.indexOf('label: "Audit"');
  assert.ok(edit > 0 && view > edit && audit > view, "View sits right after Edit");
  assert.ok(/label: "View",\s*submenu: \[\s*\{\s*label: "Mode",\s*submenu: \[/.test(m));
  assert.ok(m.includes('{ label: "Light", type: "radio", checked: themeMode === "light", click: () => setThemeMode("light") }'));
  assert.ok(m.includes('{ label: "Dark", type: "radio", checked: themeMode === "dark", click: () => setThemeMode("dark") }'));
  assert.ok(m.includes('const THEME_SET_CHANNEL = "set-theme-mode"'));
  assert.ok(m.includes('const THEME_STATE_CHANNEL = "theme-mode"'));
  assert.ok(m.includes("win.webContents.send(THEME_SET_CHANNEL, mode)"));
  assert.ok(/ipcMain\.on\(THEME_STATE_CHANNEL,[\s\S]{0,200}event\.sender !== win\.webContents[\s\S]{0,120}buildMenu\(\)/.test(m), "menu checks follow the renderer");
  const p = fs.readFileSync(__dirname + "/preload.js", "utf8");
  assert.ok(p.includes('ipcRenderer.send("theme-mode"'));
  assert.ok(p.includes('ipcRenderer.on("set-theme-mode"'));
  const r = fs.readFileSync(__dirname + "/renderer.js", "utf8");
  assert.ok(r.includes("window.PeTheme.connect(document, window.mcparser)"));
});

test("no Preferences dialog is left anywhere", () => {
  const fs = require("node:fs");
  for (const f of ["main.js", "preload.js", "renderer.js", "index.html", "studio.css"]) {
    const t = fs.readFileSync(__dirname + "/" + f, "utf8").replace(/webPreferences/g, "");
    assert.ok(!/preferences|prefs-|CmdOrCtrl\+,|app-theme/i.test(t), f + " still mentions the Preferences dialog");
  }
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
