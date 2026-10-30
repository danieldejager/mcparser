// MalwareBazaar network helpers. Pure Node so they can be tested against a
// local mock server. The API key is only ever placed in a request; every
// message that leaves this module goes through redact() first.
const fs = require("fs");
const path = require("path");
const os = require("os");
const { Readable } = require("stream");
const { pipeline } = require("stream/promises");

const DEFAULT_LOOKUP_ENDPOINT = "https://mb-api.abuse.ch/api/v1/";
const DEFAULT_EXPORT_TEMPLATE = "https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv";

function redact(text, key) {
  let out = String(text == null ? "" : text);
  if (key) {
    out = out.split(key).join("***");
    const encoded = encodeURIComponent(key);
    if (encoded !== key) out = out.split(encoded).join("***");
  }
  return out.replace(/(\/exports\/)[^/\s]+/g, "$1***");
}

function exportUrl(template, key) {
  const t = template || DEFAULT_EXPORT_TEMPLATE;
  if (!t.includes("{key}")) throw new Error("The export URL setting must contain {key}");
  return t.replace("{key}", encodeURIComponent(key));
}

// Settings and requests are https only, so the key is never sent in clear.
// Tests against a local http mock pass requireHttps: false; the app never does.
function checkHttps(url, label, requireHttps = true) {
  let u;
  try { u = new URL(String(url).replace("{key}", "KEY")); } catch (_) { throw new Error(`${label} is not a valid URL`); }
  if (requireHttps !== false && u.protocol !== "https:") throw new Error(`${label} must use https://, refused ${u.protocol}`);
  return u;
}

function isAbuseChHost(host) {
  const h = String(host || "").toLowerCase().replace(/\.$/, "");
  return h === "abuse.ch" || h.endsWith(".abuse.ch");
}

// Applies endpoint changes to a settings object. Returns { next, error, warning }.
// On error nothing in next has changed and the caller must not save.
function applyEndpointSettings(current, changes) {
  const next = { ...current };
  const warnings = [];
  const fields = [["lookupEndpoint", "The lookup endpoint"], ["exportUrl", "The export URL"]];
  for (const [field, label] of fields) {
    if (!changes || changes[field] === undefined) continue;
    const value = changes[field];
    if (typeof value !== "string" || !value) return { next: { ...current }, error: `${label} must be a non-empty https:// URL. Nothing was saved.` };
    let u;
    try { u = checkHttps(value, label); } catch (err) { return { next: { ...current }, error: `${redact(err.message)}. Nothing was saved.` }; }
    if (field === "exportUrl" && !value.includes("{key}")) return { next: { ...current }, error: "The export URL setting must contain {key}. Nothing was saved." };
    if (!isAbuseChHost(u.hostname)) warnings.push(`${label} host ${u.hostname} is not an abuse.ch host. The API key will be sent to it.`);
    next[field] = value;
  }
  return { next, warning: warnings.join(" ") };
}

// Warning text for the current settings, empty when every host is abuse.ch.
function endpointWarning(config) {
  const out = [];
  for (const [field, label] of [["lookupEndpoint", "The lookup endpoint"], ["exportUrl", "The export URL"]]) {
    try {
      const u = new URL(String(config[field] || "").replace("{key}", "KEY"));
      if (!isAbuseChHost(u.hostname)) out.push(`${label} host ${u.hostname} is not an abuse.ch host. The API key will be sent to it.`);
    } catch (_) { /* invalid values are refused at request time */ }
  }
  return out.join(" ");
}

// fetch that checks the scheme before sending and follows redirects by hand,
// refusing any hop that is not https.
async function safeFetch(url, init, { fetchImpl, requireHttps } = {}) {
  const doFetch = fetchImpl || fetch;
  let current = url;
  let options = { ...(init || {}), redirect: "manual" };
  for (let hop = 0; hop < 5; hop += 1) {
    checkHttps(current, hop ? "A redirect" : "The request URL", requireHttps);
    const response = await doFetch(current, options);
    if (response.status < 300 || response.status > 399 || !response.headers.get("location")) return response;
    current = new URL(response.headers.get("location"), current).toString();
    if (response.status === 303) options = { redirect: "manual", headers: options.headers, method: "GET" };
  }
  throw new Error("Too many redirects");
}

function statusMessage(status) {
  if (status === 401 || status === 403) return `abuse.ch rejected the key (HTTP ${status}). Check the key on the MalwareBazaar card.`;
  if (status === 429) return "abuse.ch is rate limiting this key (HTTP 429). Try again later.";
  return `abuse.ch answered HTTP ${status}`;
}

// Stream the recent export to a temp file. Returns { file, bytes, lastModified }.
async function fetchExport({ template, key, dir, fetchImpl, onProgress, requireHttps }) {
  if (!key) throw new Error("No key is stored");
  const file = path.join(dir || os.tmpdir(), `mcparser-bazaar-${process.pid}-${Date.now()}.download`);
  try {
    const response = await safeFetch(exportUrl(template, key), {}, { fetchImpl, requireHttps });
    if (!response.ok) throw new Error(statusMessage(response.status));
    if (!response.body) throw new Error("abuse.ch sent an empty response");
    let bytes = 0;
    const counter = new (require("stream").Transform)({
      transform(chunk, _enc, cb) {
        bytes += chunk.length;
        if (onProgress) onProgress(bytes);
        cb(null, chunk);
      },
    });
    await pipeline(Readable.fromWeb(response.body), counter, fs.createWriteStream(file));
    if (bytes === 0) throw new Error("abuse.ch sent an empty file");
    return { file, bytes, lastModified: response.headers.get("last-modified") || "" };
  } catch (err) {
    try { fs.unlinkSync(file); } catch (_) { /* nothing to remove */ }
    throw new Error(redact(err && err.message, key));
  }
}

const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));

async function getInfo({ endpoint, key, hash, fetchImpl, requireHttps }) {
  const body = new URLSearchParams({ query: "get_info", hash });
  const response = await safeFetch(endpoint || DEFAULT_LOOKUP_ENDPOINT, { method: "POST", headers: { "Auth-Key": key }, body }, { fetchImpl, requireHttps });
  const json = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, retryAfter: Number(response.headers.get("retry-after") || 0), json };
}

// Opt-in per-hash lookups for hashes the dump did not know. Stops at `max`,
// waits once on HTTP 429 (Retry-After, capped) and stops if it repeats.
async function lookupHashes({ endpoint, key, hashes, max, fetchImpl, sleep, onProgress, requireHttps }) {
  const wait = sleep || sleepMs;
  const list = hashes.slice(0, Math.max(0, Number(max) || 0));
  const found = [];
  let looked = 0;
  let note = "";
  try {
    for (const hash of list) {
      let res = await getInfo({ endpoint, key, hash, fetchImpl, requireHttps });
      if (res.status === 429) {
        await wait(Math.min(Math.max(res.retryAfter, 1), 30) * 1000);
        res = await getInfo({ endpoint, key, hash, fetchImpl, requireHttps });
        if (res.status === 429) { note = statusMessage(429); break; }
      }
      if (res.status === 401 || res.status === 403) { note = statusMessage(res.status); break; }
      looked += 1;
      if (onProgress) onProgress(looked, list.length);
      const row = res.json && res.json.query_status === "ok" && Array.isArray(res.json.data) && res.json.data[0];
      if (row) found.push([hash, row.sha256_hash || "", row.signature || "", row.file_name || ""]);
    }
  } catch (err) {
    note = redact(err && err.message, key);
  }
  return { found, looked, note: redact(note, key) };
}

module.exports = { DEFAULT_LOOKUP_ENDPOINT, DEFAULT_EXPORT_TEMPLATE, redact, checkHttps, isAbuseChHost, applyEndpointSettings, endpointWarning, safeFetch, exportUrl, fetchExport, getInfo, lookupHashes, statusMessage };
