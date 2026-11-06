const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

const root = path.resolve(__dirname, "..");
const lockupPath = path.join(root, "docs", "readme_lockup.png");
const readmePath = path.join(root, "README.md");

// Company-suffix forms. Built from parts so this file does not contain them.
function suffixPattern() {
  const pty = "p" + "ty";
  const ltd = "l" + "td";
  const proprietary = "prop" + "rietary";
  const limited = "lim" + "ited";
  return new RegExp(
    "(?<![A-Za-z])(?:" +
      pty + "\\.?\\s*" + ltd + "\\.?|" +
      proprietary + "\\s+" + limited +
    ")(?![A-Za-z])",
    "i"
  );
}

function walkText(dir, out) {
  const skip = new Set([".git", "node_modules", "target", "dist", "fixtures"]);
  for (const name of fs.readdirSync(dir)) {
    if (skip.has(name)) continue;
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      walkText(full, out);
      continue;
    }
    const ext = path.extname(name).toLowerCase();
    if ([".png", ".jpg", ".jpeg", ".gif", ".ico", ".icns", ".evtx", ".duckdb", ".zip", ".wasm"].includes(ext)) continue;
    const buf = fs.readFileSync(full);
    if (buf.includes(0)) continue;
    out.push([path.relative(root, full), buf.toString("utf8")]);
  }
}

function decodePng(buf) {
  assert.strictEqual(buf.readUInt32BE(0), 0x89504e47);
  let off = 8;
  let width = 0;
  let height = 0;
  let bitDepth = 0;
  let colorType = 0;
  const idat = [];
  while (off + 8 <= buf.length) {
    const len = buf.readUInt32BE(off);
    const type = buf.toString("ascii", off + 4, off + 8);
    const data = buf.subarray(off + 8, off + 8 + len);
    if (type === "IHDR") {
      width = data.readUInt32BE(0);
      height = data.readUInt32BE(4);
      bitDepth = data[8];
      colorType = data[9];
    } else if (type === "IDAT") {
      idat.push(data);
    } else if (type === "IEND") {
      break;
    }
    off += 12 + len;
  }
  assert.strictEqual(bitDepth, 8);
  assert.strictEqual(colorType, 6, "lockup is 8-bit RGBA");
  const raw = zlib.inflateSync(Buffer.concat(idat));
  const bpp = 4;
  const stride = width * bpp;
  const out = Buffer.alloc(height * stride);
  let s = 0;
  const paeth = (a, b, c) => {
    const p = a + b - c;
    const pa = Math.abs(p - a);
    const pb = Math.abs(p - b);
    const pc = Math.abs(p - c);
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
  };
  for (let y = 0; y < height; y++) {
    const filter = raw[s++];
    const rowStart = y * stride;
    const prevStart = (y - 1) * stride;
    for (let i = 0; i < stride; i++) {
      const x = raw[s++];
      const a = i >= bpp ? out[rowStart + i - bpp] : 0;
      const b = y > 0 ? out[prevStart + i] : 0;
      const c = y > 0 && i >= bpp ? out[prevStart + i - bpp] : 0;
      let v = x;
      if (filter === 1) v = x + a;
      else if (filter === 2) v = x + b;
      else if (filter === 3) v = x + Math.floor((a + b) / 2);
      else if (filter === 4) v = x + paeth(a, b, c);
      else if (filter !== 0) throw new Error("bad png filter " + filter);
      out[rowStart + i] = v & 255;
    }
  }
  return { width, height, data: out };
}

function pixel(img, x, y) {
  const i = (y * img.width + x) * 4;
  return [img.data[i], img.data[i + 1], img.data[i + 2], img.data[i + 3]];
}

test("public text does not use a company suffix on our name", () => {
  const pattern = suffixPattern();
  const files = [];
  walkText(root, files);
  const hits = [];
  for (const [rel, text] of files) {
    if (pattern.test(text)) hits.push(rel);
    pattern.lastIndex = 0;
  }
  assert.deepStrictEqual(hits, []);
});

test("README lockup alt text is Phantom Technologies", () => {
  const readme = fs.readFileSync(readmePath, "utf8");
  assert.ok(readme.includes("![McParser by Phantom Technologies](docs/readme_lockup.png)"));
  assert.ok(!suffixPattern().test(readme));
});

test("lockup keeps the wordmark and drops the suffix glyphs", () => {
  const img = decodePng(fs.readFileSync(lockupPath));
  assert.deepStrictEqual([img.width, img.height], [1342, 460]);
  const bg = [16, 17, 21, 255];
  // Former suffix rectangle, measured on the existing lockup. It must be background.
  for (let y = 311; y <= 357; y++) {
    for (let x = 1058; x <= 1255; x++) {
      assert.deepStrictEqual(pixel(img, x, y), bg, x + "," + y);
    }
  }
  // "Phantom Technologies" remains, left aligned under the wordmark.
  let subtitle = 0;
  for (let y = 311; y <= 357; y++) {
    for (let x = 467; x <= 1039; x++) {
      const p = pixel(img, x, y);
      if (p[0] !== bg[0] || p[1] !== bg[1] || p[2] !== bg[2]) subtitle++;
    }
  }
  assert.ok(subtitle > 1000, "subtitle ink missing");
  // McParser wordmark remains silver.
  let wordmark = 0;
  for (let y = 185; y <= 270; y++) {
    for (let x = 468; x <= 1280; x++) {
      const p = pixel(img, x, y);
      if (p[0] > 200 && p[1] > 200 && p[2] > 200) wordmark++;
    }
  }
  assert.ok(wordmark > 1000, "wordmark missing");
});
