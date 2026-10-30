// Start-up update logic against a local mock abuse.ch server.
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const bz = require("./bazaar-fetch");
const { runStartupUpdate } = require("./bazaar-autoupdate");

const KEY = "test-key-0123456789abcdef";

function server(status, body) {
  return new Promise((resolve) => {
    const s = http.createServer((_req, res) => { res.writeHead(status); res.end(body); });
    s.listen(0, "127.0.0.1", () => resolve({ s, base: `http://127.0.0.1:${s.address().port}` }));
  });
}

function setup(base, over) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bza-"));
  const dump = path.join(dir, "dump.csv");
  fs.writeFileSync(dump, "old");
  const reports = [];
  let fetches = 0;
  const deps = {
    isInstalled: async () => true,
    loadKey: () => KEY,
    loadConfig: async () => ({ exportUrl: `${base}/v2/files/exports/{key}/recent.csv` }),
    fetchAndImport: async (key, config) => {
      fetches += 1;
      const got = await bz.fetchExport({ template: config.exportUrl, key, dir, requireHttps: false });
      try {
        fs.copyFileSync(got.file, dump);
        return { code: 0, counts: { added: 2, updated: 1, unchanged: 0 }, info: { newest_first_seen: "2026-10-29 10:00:00" } };
      } finally { fs.unlinkSync(got.file); }
    },
    redact: bz.redact,
    report: (p) => reports.push(p),
    ...over,
  };
  return { dir, dump, reports, deps, fetches: () => fetches };
}

const leftovers = (dir) => fs.readdirSync(dir).filter((f) => f.endsWith(".download"));

test("skips silently when not installed", async () => {
  const t = setup("http://127.0.0.1:1", { isInstalled: async () => false });
  assert.deepStrictEqual(await runStartupUpdate(t.deps, {}), { skipped: "not-installed" });
  assert.strictEqual(t.reports.length, 0);
  assert.strictEqual(t.fetches(), 0);
});

test("skips silently when no key is stored", async () => {
  const t = setup("http://127.0.0.1:1", { loadKey: () => { throw new Error("No key is stored"); } });
  assert.deepStrictEqual(await runStartupUpdate(t.deps, {}), { skipped: "no-key" });
  assert.strictEqual(t.reports.length, 0);
});

test("skips when autoUpdate is false", async () => {
  const t = setup("http://127.0.0.1:1", { loadConfig: async () => ({ autoUpdate: false }) });
  assert.deepStrictEqual(await runStartupUpdate(t.deps, {}), { skipped: "disabled" });
  assert.strictEqual(t.reports.length, 0);
});

test("runs once per start and reports counts and newest date", async () => {
  const { s, base } = await server(200, "csv-data");
  try {
    const t = setup(base);
    const state = {};
    const first = await runStartupUpdate(t.deps, state);
    const second = await runStartupUpdate(t.deps, state);
    assert.ok(first.ok);
    assert.deepStrictEqual(second, { skipped: "already-ran" });
    assert.strictEqual(t.fetches(), 1);
    assert.strictEqual(t.reports[0].text, "Updating MalwareBazaar.....");
    assert.match(t.reports[1].text, /2 added, 1 updated, 0 unchanged, newest sample 2026-10-29/);
    assert.strictEqual(fs.readFileSync(t.dump, "utf8"), "csv-data");
    assert.deepStrictEqual(leftovers(t.dir), []);
  } finally { s.close(); }
});

for (const status of [401, 403, 429, 500]) {
  test(`HTTP ${status} leaves the dump intact, no temp file, no key in message`, async () => {
    const { s, base } = await server(status, "nope");
    try {
      const t = setup(base);
      const r = await runStartupUpdate(t.deps, {});
      assert.ok(r.error.includes(String(status)), r.error);
      assert.ok(!r.error.includes(KEY));
      assert.strictEqual(t.reports[1].phase, "error");
      assert.strictEqual(fs.readFileSync(t.dump, "utf8"), "old");
      assert.deepStrictEqual(leftovers(t.dir), []);
    } finally { s.close(); }
  });
}

test("offline leaves the dump intact with a clear message", async () => {
  const t = setup("http://127.0.0.1:1");
  const r = await runStartupUpdate(t.deps, {});
  assert.match(r.error, /offline/);
  assert.strictEqual(fs.readFileSync(t.dump, "utf8"), "old");
  assert.deepStrictEqual(leftovers(t.dir), []);
});
