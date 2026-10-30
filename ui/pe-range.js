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

module.exports = { MAX_RANGE, PAGE_SIZES, validateRange, readRange, sha256File, fileMatches };
