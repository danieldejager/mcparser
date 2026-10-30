// https only settings and requests. No network: fetch is a stub.
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const bz = require("./bazaar-fetch");

const KEY = "test-key-0123456789abcdef";
const CURRENT = { lookupEndpoint: bz.DEFAULT_LOOKUP_ENDPOINT, exportUrl: bz.DEFAULT_EXPORT_TEMPLATE, onlineLookup: false, onlineMax: 25 };

test("defaults are https abuse.ch", () => {
  assert.strictEqual(bz.DEFAULT_LOOKUP_ENDPOINT, "https://mb-api.abuse.ch/api/v1/");
  assert.strictEqual(bz.DEFAULT_EXPORT_TEMPLATE, "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv");
  assert.strictEqual(bz.endpointWarning(CURRENT), "");
});

test("http lookupEndpoint is refused and nothing changes", () => {
  const got = bz.applyEndpointSettings(CURRENT, { lookupEndpoint: "http://mb-api.abuse.ch/api/v1/" });
  assert.match(got.error, /https/);
  assert.match(got.error, /Nothing was saved/);
  assert.deepStrictEqual(got.next, CURRENT);
});

test("http exportUrl is refused and nothing changes", () => {
  const got = bz.applyEndpointSettings(CURRENT, { lookupEndpoint: "https://mb-api.abuse.ch/api/v2/", exportUrl: "http://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv" });
  assert.match(got.error, /https/);
  assert.deepStrictEqual(got.next, CURRENT);
});

test("other schemes are refused", () => {
  for (const v of ["ftp://mb-api.abuse.ch/api/v1/", "file:///etc/passwd", "mb-api.abuse.ch/api/v1/", ""]) {
    assert.ok(bz.applyEndpointSettings(CURRENT, { lookupEndpoint: v }).error, v);
  }
});

test("https abuse.ch values are accepted without a warning", () => {
  const got = bz.applyEndpointSettings(CURRENT, { lookupEndpoint: "https://mb-api.abuse.ch/api/v1/", exportUrl: "https://bazaar.abuse.ch/export/{key}/recent.csv" });
  assert.strictEqual(got.error, undefined);
  assert.strictEqual(got.warning, "");
  assert.strictEqual(got.next.exportUrl, "https://bazaar.abuse.ch/export/{key}/recent.csv");
});

test("https non-abuse.ch host is accepted with a warning", () => {
  const got = bz.applyEndpointSettings(CURRENT, { lookupEndpoint: "https://abuse.ch.evil.example/api/v1/" });
  assert.strictEqual(got.error, undefined);
  assert.strictEqual(got.next.lookupEndpoint, "https://abuse.ch.evil.example/api/v1/");
  assert.match(got.warning, /not an abuse.ch host/);
  assert.match(bz.endpointWarning(got.next), /abuse.ch.evil.example/);
  assert.ok(!bz.isAbuseChHost("notabuse.ch"));
  assert.ok(bz.isAbuseChHost("abuse.ch"));
});

test("fetchExport refuses http before sending the key", async () => {
  let calls = 0;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bzh-"));
  await assert.rejects(bz.fetchExport({ template: "http://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv", key: KEY, dir, fetchImpl: async () => { calls += 1; } }), (err) => {
    assert.match(err.message, /https/);
    assert.ok(!err.message.includes(KEY));
    return true;
  });
  assert.strictEqual(calls, 0);
});

test("lookupHashes refuses http before sending the key", async () => {
  let calls = 0;
  const out = await bz.lookupHashes({ endpoint: "http://mb-api.abuse.ch/api/v1/", key: KEY, hashes: ["a".repeat(64)], max: 1, fetchImpl: async () => { calls += 1; } });
  assert.strictEqual(calls, 0);
  assert.match(out.note, /https/);
});

test("an https to http redirect is refused", async () => {
  const seen = [];
  const fetchImpl = async (url, init) => {
    seen.push(url);
    assert.strictEqual(init.redirect, "manual");
    return new Response(null, { status: 302, headers: { location: "http://mb-api.abuse.ch/v2/files/exports/" + KEY + "/recent.csv" } });
  };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "bzh-"));
  await assert.rejects(bz.fetchExport({ template: bz.DEFAULT_EXPORT_TEMPLATE, key: KEY, dir, fetchImpl }), (err) => {
    assert.match(err.message, /redirect must use https/);
    assert.ok(!err.message.includes(KEY));
    return true;
  });
  assert.strictEqual(seen.length, 1);
  const post = async () => new Response(null, { status: 307, headers: { location: "http://example.org/api/v1/" } });
  await assert.rejects(bz.safeFetch(bz.DEFAULT_LOOKUP_ENDPOINT, { method: "POST" }, { fetchImpl: post }), /redirect must use https/);
});

test("an https to https redirect is followed", async () => {
  const fetchImpl = async (url) => url.includes("mb-api")
    ? new Response(null, { status: 302, headers: { location: "https://cdn.abuse.ch/x.csv" } })
    : new Response("ok", { status: 200 });
  const res = await bz.safeFetch(bz.DEFAULT_LOOKUP_ENDPOINT, {}, { fetchImpl });
  assert.strictEqual(await res.text(), "ok");
});
