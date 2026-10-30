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
