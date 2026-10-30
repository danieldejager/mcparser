// Offline tests: a local http server stands in for abuse.ch.
const test = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const bz = require("./bazaar-fetch");

const KEY = "test-key-0123456789abcdef";

function server(handler) {
  return new Promise((resolve) => {
    const s = http.createServer(handler);
    s.listen(0, "127.0.0.1", () => resolve({ s, base: `http://127.0.0.1:${s.address().port}` }));
  });
}

function leftovers(dir) {
  return fs.readdirSync(dir).filter((f) => f.endsWith(".download"));
}

test("redact hides the key and the export path segment", () => {
  assert.strictEqual(bz.redact(`GET https://x/v2/files/exports/${KEY}/recent.csv failed`, KEY), "GET https://x/v2/files/exports/***/recent.csv failed");
  assert.strictEqual(bz.redact("https://x/v2/files/exports/other/recent.csv"), "https://x/v2/files/exports/***/recent.csv");
  assert.throws(() => bz.exportUrl("https://x/no-placeholder", KEY));
});

test("fetchExport streams to a temp file and reports the date", async () => {
  const csv = '# "first_seen_utc","sha256_hash"\n"2026-10-01 00:00:00", "' + "a".repeat(64) + '"\n';
  let seen = "";
  const { s, base } = await server((req, res) => {
    seen = req.url;
    res.writeHead(200, { "content-type": "text/csv", "last-modified": "Wed, 28 Oct 2026 00:00:00 GMT" });
    res.end(csv);
  });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bzf-"));
  try {
    const got = await bz.fetchExport({ template: `${base}/v2/files/exports/{key}/recent.csv`, key: KEY, dir, requireHttps: false });
    assert.strictEqual(seen, `/v2/files/exports/${KEY}/recent.csv`);
    assert.strictEqual(fs.readFileSync(got.file, "utf8"), csv);
    assert.strictEqual(got.bytes, Buffer.byteLength(csv));
    assert.match(got.lastModified, /2026/);
  } finally { s.close(); }
});

for (const status of [401, 403, 429, 500]) {
  test(`fetchExport HTTP ${status} gives a clear message, no key, no temp file`, async () => {
    const { s, base } = await server((_req, res) => { res.writeHead(status); res.end("nope"); });
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bzf-"));
    try {
      await assert.rejects(bz.fetchExport({ template: `${base}/v2/files/exports/{key}/recent.csv`, key: KEY, dir, requireHttps: false }), (err) => {
        assert.ok(err.message.includes(String(status)), err.message);
        assert.ok(!err.message.includes(KEY));
        if (status === 429) assert.match(err.message, /rate limit/);
        if (status === 401 || status === 403) assert.match(err.message, /rejected the key/);
        return true;
      });
      assert.deepStrictEqual(leftovers(dir), []);
    } finally { s.close(); }
  });
}

test("fetchExport network errors are redacted and clean up", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bzf-"));
  const fetchImpl = async (url) => { throw new Error("connect failed for " + url); };
  await assert.rejects(bz.fetchExport({ template: "http://127.0.0.1:9/v2/files/exports/{key}/recent.csv", key: KEY, dir, fetchImpl, requireHttps: false }), (err) => {
    assert.ok(!err.message.includes(KEY), err.message);
    assert.match(err.message, /exports\/\*\*\*/);
    return true;
  });
  assert.deepStrictEqual(leftovers(dir), []);
});

test("lookupHashes respects max, waits once on 429 and records finds", async () => {
  let calls = 0;
  let limited = false;
  const keys = new Set();
  const { s, base } = await server((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      calls += 1;
      keys.add(req.headers["auth-key"]);
      const hash = new URLSearchParams(body).get("hash");
      if (hash === "b".repeat(64) && !limited) { limited = true; res.writeHead(429, { "retry-after": "1" }); return res.end("{}"); }
      res.writeHead(200, { "content-type": "application/json" });
      if (hash === "b".repeat(64)) return res.end(JSON.stringify({ query_status: "ok", data: [{ sha256_hash: hash, signature: "RedLine", file_name: "x.exe" }] }));
      res.end(JSON.stringify({ query_status: "hash_not_found" }));
    });
  });
  const waits = [];
  try {
    const out = await bz.lookupHashes({ endpoint: `${base}/api/v1/`, key: KEY, hashes: ["a".repeat(64), "b".repeat(64), "c".repeat(64)], max: 2, sleep: async (ms) => { waits.push(ms); }, requireHttps: false });
    assert.strictEqual(out.looked, 2);
    assert.deepStrictEqual(out.found, [["b".repeat(64), "b".repeat(64), "RedLine", "x.exe"]]);
    assert.deepStrictEqual(waits, [1000]);
    assert.strictEqual(calls, 3);
    assert.deepStrictEqual([...keys], [KEY]);
  } finally { s.close(); }
});

test("lookupHashes stops on repeated 429 and on a rejected key", async () => {
  for (const status of [429, 401]) {
    const { s, base } = await server((_req, res) => { res.writeHead(status); res.end("{}"); });
    try {
      const out = await bz.lookupHashes({ endpoint: `${base}/api/v1/`, key: KEY, hashes: ["a".repeat(64), "c".repeat(64)], max: 5, sleep: async () => {}, requireHttps: false });
      assert.strictEqual(out.looked, 0);
      assert.ok(out.note.includes(String(status)));
      assert.ok(!out.note.includes(KEY));
    } finally { s.close(); }
  }
});
