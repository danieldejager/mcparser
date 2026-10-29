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

function statusMessage(status) {
  if (status === 401 || status === 403) return `abuse.ch rejected the key (HTTP ${status}). Check the key on the MalwareBazaar card.`;
  if (status === 429) return "abuse.ch is rate limiting this key (HTTP 429). Try again later.";
  return `abuse.ch answered HTTP ${status}`;
}

// Stream the recent export to a temp file. Returns { file, bytes, lastModified }.
async function fetchExport({ template, key, dir, fetchImpl, onProgress }) {
  if (!key) throw new Error("No key is stored");
  const doFetch = fetchImpl || fetch;
  const file = path.join(dir || os.tmpdir(), `mcparser-bazaar-${process.pid}-${Date.now()}.download`);
  try {
    const response = await doFetch(exportUrl(template, key));
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

async function getInfo({ endpoint, key, hash, fetchImpl }) {
  const doFetch = fetchImpl || fetch;
  const body = new URLSearchParams({ query: "get_info", hash });
  const response = await doFetch(endpoint || DEFAULT_LOOKUP_ENDPOINT, { method: "POST", headers: { "Auth-Key": key }, body });
  const json = await response.json().catch(() => ({}));
  return { status: response.status, ok: response.ok, retryAfter: Number(response.headers.get("retry-after") || 0), json };
}

// Opt-in per-hash lookups for hashes the dump did not know. Stops at `max`,
// waits once on HTTP 429 (Retry-After, capped) and stops if it repeats.
async function lookupHashes({ endpoint, key, hashes, max, fetchImpl, sleep, onProgress }) {
  const wait = sleep || sleepMs;
  const list = hashes.slice(0, Math.max(0, Number(max) || 0));
  const found = [];
  let looked = 0;
  let note = "";
  try {
    for (const hash of list) {
      let res = await getInfo({ endpoint, key, hash, fetchImpl });
      if (res.status === 429) {
        await wait(Math.min(Math.max(res.retryAfter, 1), 30) * 1000);
        res = await getInfo({ endpoint, key, hash, fetchImpl });
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

module.exports = { DEFAULT_LOOKUP_ENDPOINT, DEFAULT_EXPORT_TEMPLATE, redact, exportUrl, fetchExport, getInfo, lookupHashes, statusMessage };
