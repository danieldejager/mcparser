const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const { windowOptions } = require("./window-options.js");

test("linux and win32 get a native frame, visible menu bar and no fullscreen", () => {
  for (const p of ["linux", "win32"]) {
    const o = windowOptions(p);
    assert.strictEqual(o.frame, true);
    assert.strictEqual(o.fullscreen, false);
    assert.strictEqual(o.autoHideMenuBar, false);
    assert.strictEqual(o.maximize, true);
  }
});

test("darwin keeps fullscreen", () => {
  assert.strictEqual(windowOptions("darwin").fullscreen, true);
  assert.strictEqual(windowOptions("darwin").maximize, false);
});

test("main.js applies the menu on every platform and uses windowOptions", () => {
  const src = fs.readFileSync(path.join(__dirname, "main.js"), "utf8");
  assert.match(src, /Menu\.setApplicationMenu\(Menu\.buildFromTemplate\(template\)\)/);
  assert.doesNotMatch(src, /setApplicationMenu\(null\)/);
  assert.doesNotMatch(src, /fullscreen:\s*true/);
  assert.match(src, /windowOptions\(process\.platform\)/);
});
