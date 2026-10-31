const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

const html = fs.readFileSync(path.join(__dirname, "index.html"), "utf8");
const main = fs.readFileSync(path.join(__dirname, "main.js"), "utf8");

function csp() {
  const m = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]+)"/i);
  return m ? m[1] : "";
}

test("index.html carries a strict CSP meta", () => {
  const policy = csp();
  assert.ok(policy, "CSP meta missing");
  assert.match(policy, /default-src 'self'/);
  assert.ok(!/unsafe-eval/.test(policy));
  assert.ok(!/unsafe-inline/.test(policy));
  assert.ok(!/https?:|wss?:|\*/.test(policy), "no remote origins");
});

test("index.html has no inline script, style or event handler", () => {
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/i.test(html), "inline script");
  assert.ok(!/<style\b/i.test(html), "inline style element");
  assert.ok(!/\sstyle="/i.test(html), "style attribute");
  assert.ok(!/\son[a-z]+="/i.test(html), "inline handler");
});

test("every BrowserWindow sets hardened webPreferences", () => {
  const wins = main.split("new BrowserWindow(").slice(1);
  assert.ok(wins.length > 0);
  for (const w of wins) {
    const prefs = w.slice(0, w.indexOf("});"));
    for (const want of ["contextIsolation: true", "nodeIntegration: false", "sandbox: true", "webSecurity: true", "allowRunningInsecureContent: false"]) {
      assert.ok(prefs.includes(want), want);
    }
  }
});
