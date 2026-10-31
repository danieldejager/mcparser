// Bounded read of a byte range from the PE file being viewed. Used by the
// main process for the paged hex view so the whole file is never loaded.
// Only the file picked in the last "Analyze PE file" dialog, or a file
// whose sha256 matched the case row being viewed, can be read.
const fs = require("fs");

const MAX_RANGE = 1024 * 1024;
const PAGE_SIZES = [4096, 65536];

// Returns { offset, length } clamped to the file, or { error }.
function validateRange(offset, length, fileSize) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length)) return { error: "offset and length must be integers" };
  if (offset < 0 || length <= 0) return { error: "offset must be >= 0 and length > 0" };
  if (length > MAX_RANGE) return { error: `length over the ${MAX_RANGE} byte cap` };
  if (!Number.isSafeInteger(fileSize) || fileSize < 0) return { error: "bad file size" };
  if (offset >= fileSize) return { error: `offset past end of file (${fileSize} bytes)` };
  return { offset, length: Math.min(length, fileSize - offset) };
}

function readRange(filePath, offset, length) {
  if (!filePath) return { error: "no PE file open" };
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const size = fs.fstatSync(fd).size;
    const v = validateRange(offset, length, size);
    if (v.error) return { error: v.error, size };
    const buf = Buffer.alloc(v.length);
    const n = fs.readSync(fd, buf, 0, v.length, v.offset);
    return { offset: v.offset, size, base64: buf.subarray(0, n).toString("base64") };
  } catch (err) {
    return { error: "read failed: " + err.code };
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

// SHA256 of a file, streamed so a large file is never held in memory.
// Resolves "" when the file cannot be read.
function sha256File(filePath) {
  const crypto = require("crypto");
  return new Promise((resolve) => {
    if (!filePath) { resolve(""); return; }
    const h = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => h.update(chunk));
    stream.on("end", () => resolve(h.digest("hex")));
    stream.on("error", () => resolve(""));
  });
}

// True when the file at filePath is a regular file whose sha256 matches.
async function fileMatches(filePath, sha256) {
  try { if (!filePath || !fs.statSync(filePath).isFile()) return false; } catch { return false; }
  return (await sha256File(filePath)) === String(sha256 || "").toLowerCase();
}

// Open file reference for the hex view. The file is opened once and kept
// open; hashing (when a sha256 is given) reads from that same descriptor,
// and every later read checks that the descriptor and the path still point
// at the same unchanged file (dev, ino, size, mtime). A file replaced or
// modified after the check is refused instead of trusting a stale check.
const CHANGED = "The file changed on disk since it was verified. Close the PE view and locate or analyze it again.";

function identity(st) {
  return { dev: st.dev, ino: st.ino, size: st.size, mtimeMs: st.mtimeMs };
}

function sameIdentity(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.size === b.size && a.mtimeMs === b.mtimeMs;
}

function hashFd(fd, size) {
  const crypto = require("crypto");
  const h = crypto.createHash("sha256");
  const buf = Buffer.alloc(Math.min(MAX_RANGE, Math.max(size, 1)));
  let pos = 0;
  for (;;) {
    const n = fs.readSync(fd, buf, 0, buf.length, pos);
    if (n <= 0) break;
    h.update(buf.subarray(0, n));
    pos += n;
  }
  return h.digest("hex");
}

// Opens filePath and returns a reference, or null. With sha256, the
// content read through the descriptor must match it.
function openRef(filePath, sha256) {
  if (!filePath) return null;
  let fd;
  try {
    fd = fs.openSync(filePath, "r");
    const st = fs.fstatSync(fd);
    if (!st.isFile()) throw new Error("not a regular file");
    const ident = identity(st);
    if (sha256 !== undefined) {
      if (hashFd(fd, st.size) !== String(sha256 || "").toLowerCase()) throw new Error("sha256 mismatch");
      if (!sameIdentity(ident, identity(fs.fstatSync(fd)))) throw new Error("changed while hashing");
    }
    return { path: filePath, fd, ident, sha256: sha256 === undefined ? "" : String(sha256).toLowerCase() };
  } catch {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* already closed */ }
    return null;
  }
}

// Closes the descriptor once. Safe to call with null or twice.
function closeRef(ref) {
  if (!ref || ref.fd === undefined) return;
  const fd = ref.fd;
  ref.fd = undefined;
  try { fs.closeSync(fd); } catch { /* already closed */ }
}

// Bounded read through an open reference, refused if the file changed.
function readRef(ref, offset, length) {
  if (!ref || ref.fd === undefined) return { error: "no PE file open" };
  try {
    const now = identity(fs.fstatSync(ref.fd));
    let onDisk;
    try { onDisk = identity(fs.statSync(ref.path)); } catch { return { error: CHANGED }; }
    if (!sameIdentity(ref.ident, now) || !sameIdentity(ref.ident, onDisk)) return { error: CHANGED };
    const v = validateRange(offset, length, now.size);
    if (v.error) return { error: v.error, size: now.size };
    const buf = Buffer.alloc(v.length);
    const n = fs.readSync(ref.fd, buf, 0, v.length, v.offset);
    return { offset: v.offset, size: now.size, base64: buf.subarray(0, n).toString("base64") };
  } catch (err) {
    return { error: "read failed: " + err.code };
  }
}

module.exports = { MAX_RANGE, PAGE_SIZES, CHANGED, validateRange, readRange, sha256File, fileMatches, openRef, closeRef, readRef };
