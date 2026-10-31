const test = require("node:test");
const assert = require("node:assert");
const { isTrustedSender, guard } = require("./ipc-guard.js");

const mainFrame = { processId: 4, routingId: 1 };
const wc = { mainFrame };
const win = { webContents: wc, isDestroyed: () => false };

test("isTrustedSender accepts only the main window's top frame", () => {
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: mainFrame }, win), true);
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: { processId: 4, routingId: 1 } }, win), true);
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: { processId: 4, routingId: 7 } }, win), false);
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: null }, win), false);
  assert.strictEqual(isTrustedSender({ sender: {}, senderFrame: mainFrame }, win), false);
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: mainFrame }, null), false);
  assert.strictEqual(isTrustedSender({ sender: wc, senderFrame: mainFrame }, { webContents: wc, isDestroyed: () => true }), false);
  assert.strictEqual(isTrustedSender(undefined, win), false);
});

test("guard runs the handler for the main window and throws otherwise", () => {
  const h = guard("pe-read-range", () => win, (_e, a, b) => a + b);
  assert.strictEqual(h({ sender: wc, senderFrame: mainFrame }, 2, 3), 5);
  assert.throws(() => h({ sender: {}, senderFrame: mainFrame }, 2, 3), /pe-read-range.*refused/);
});

test("main.js registers every invoke handler through the guard", () => {
  const src = require("fs").readFileSync(require("path").join(__dirname, "main.js"), "utf8");
  const direct = src.match(/ipcMain\.handle\(/g) || [];
  assert.strictEqual(direct.length, 1, "only the guarded handle() helper may call ipcMain.handle");
  for (const ch of ["pe-case-report", "pe-locate", "pe-read-range", "pe-analyze", "query", "lookup-hash", "bazaar-fetch"]) {
    assert.ok(src.includes(`handle("${ch}"`), ch);
  }
});
