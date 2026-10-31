const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { validateRange, readRange, MAX_RANGE } = require("./pe-range.js");

test("validateRange clamps and rejects hostile values", () => {
  assert.deepStrictEqual(validateRange(0, 4096, 100), { offset: 0, length: 100 });
  assert.deepStrictEqual(validateRange(96, 4096, 100), { offset: 96, length: 4 });
  for (const [o, l] of [[-1, 10], [0, 0], [0, -5], [1.5, 10], [0, MAX_RANGE + 1], [100, 1], [Number.MAX_VALUE, 1], ["0", 10], [NaN, 1], [0, Infinity]]) {
    assert.ok(validateRange(o, l, 100).error, `${o},${l}`);
  }
});

test("readRange reads only the window asked for", () => {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pe-range-")), "x.bin");
  fs.writeFileSync(f, Buffer.from("MZ0123456789"));
  const r = readRange(f, 2, 4);
  assert.strictEqual(Buffer.from(r.base64, "base64").toString(), "0123");
  assert.strictEqual(r.size, 12);
  assert.ok(readRange(f, 12, 4).error);
  assert.ok(readRange("", 0, 4).error);
  assert.match(readRange(f + ".missing", 0, 4).error, /read failed/);
});

test("fileMatches checks sha256 before a file can be used", async () => {
  const { fileMatches, sha256File } = require("./pe-range.js");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "pe-range-"));
  const f = path.join(dir, "x.bin");
  fs.writeFileSync(f, Buffer.from("MZ0123456789"));
  const sha = require("crypto").createHash("sha256").update("MZ0123456789").digest("hex");
  assert.strictEqual(await sha256File(f), sha);
  assert.ok(await fileMatches(f, sha.toUpperCase()));
  assert.ok(!(await fileMatches(f, "0".repeat(64))));
  assert.ok(!(await fileMatches(f + ".missing", sha)));
  assert.ok(!(await fileMatches(dir, sha)));
  assert.ok(!(await fileMatches("", sha)));
});

const { openRef, readRef, closeRef, CHANGED } = require("./pe-range.js");
const crypto = require("crypto");

function tmpFile(content) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "pe-ref-")), "x.bin");
  fs.writeFileSync(f, content);
  return f;
}
const sha = (b) => crypto.createHash("sha256").update(b).digest("hex");

test("openRef verifies sha256 through the open descriptor", () => {
  const f = tmpFile("MZ0123456789");
  assert.strictEqual(openRef(f, sha("other")), null);
  const ref = openRef(f, sha("MZ0123456789").toUpperCase());
  assert.ok(ref);
  assert.strictEqual(Buffer.from(readRef(ref, 2, 4).base64, "base64").toString(), "0123");
  assert.ok(readRef(ref, 0, MAX_RANGE + 1).error);
  closeRef(ref);
});

test("file replaced between verify and read is refused", () => {
  const f = tmpFile("MZ0123456789");
  const ref = openRef(f, sha("MZ0123456789"));
  const other = f + ".new";
  fs.writeFileSync(other, "MZevilevilev");
  fs.renameSync(other, f);
  assert.strictEqual(readRef(ref, 0, 4).error, CHANGED);
  closeRef(ref);
});

test("file modified in place after verify is refused", () => {
  const f = tmpFile("MZ0123456789");
  const ref = openRef(f, sha("MZ0123456789"));
  fs.appendFileSync(f, "more");
  assert.strictEqual(readRef(ref, 0, 4).error, CHANGED);
  closeRef(ref);
});

test("file deleted after verify is refused", () => {
  const f = tmpFile("MZ0123456789");
  const ref = openRef(f);
  fs.unlinkSync(f);
  assert.strictEqual(readRef(ref, 0, 4).error, CHANGED);
  closeRef(ref);
});

test("closeRef clears the reference and releases the descriptor", () => {
  const f = tmpFile("MZ0123456789");
  const ref = openRef(f);
  const fd = ref.fd;
  closeRef(ref);
  closeRef(ref);
  assert.strictEqual(ref.fd, undefined);
  assert.deepStrictEqual(readRef(ref, 0, 4), { error: "no PE file open" });
  assert.throws(() => fs.fstatSync(fd), /EBADF/);
  assert.deepStrictEqual(readRef(null, 0, 4), { error: "no PE file open" });
});

test("main.js clears the PE reference on sheet close, case close and window close", () => {
  const main = fs.readFileSync(path.join(__dirname, "main.js"), "utf8");
  const renderer = fs.readFileSync(path.join(__dirname, "renderer.js"), "utf8");
  assert.match(main, /handle\("pe-close", \(\) => \{ clearPe\(\);/);
  assert.match(main, /if \(!caseOpen\) clearPe\(\);/);
  assert.match(main, /win\.on\("closed", \(\) => clearPe\(\)\)/);
  assert.match(main, /function setPeRef\(ref\) \{ peRange\.closeRef\(peRef\);/);
  assert.ok(!/peFile/.test(main), "no path-only reference left");
  assert.match(renderer, /"pe-close"\)\.addEventListener\("click", \(\) => closePeView\(\)\)/);
  assert.match(renderer, /peViewCase !== caseDir\(\)\) closePeView\(\)/);
});
