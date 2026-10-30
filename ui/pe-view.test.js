const test = require("node:test");
const assert = require("node:assert");
const { flattenTree, summaryItems, TABS, hexRows, decodeBase64, sectionFlags } = require("./pe-view.js");

test("flattenTree keeps order and depth", () => {
  const flat = flattenTree([{ id: "dos", label: "DOS header", rows: [{ field: "e_magic" }] }, { id: "nt", label: "NT", children: [{ id: "file", label: "File header" }] }]);
  assert.deepStrictEqual(flat.map((n) => [n.id, n.depth]), [["dos", 0], ["nt", 0], ["file", 1]]);
  assert.strictEqual(flat[0].rows.length, 1);
  assert.deepStrictEqual(flat[2].rows, []);
});

test("flattenTree tolerates junk", () => {
  assert.deepStrictEqual(flattenTree(null), []);
  assert.deepStrictEqual(flattenTree([{}]).map((n) => n.label), [""]);
});

test("summary shows MalwareBazaar hit plainly and skips it when not installed", () => {
  const hit = summaryItems({ sha256: "a", malwarebazaar: { result: "hit", signature: "AgentTesla" } });
  assert.deepStrictEqual(hit.find(([k]) => k === "MalwareBazaar"), ["MalwareBazaar", "HIT AgentTesla"]);
  const none = summaryItems({ sha256: "a", malwarebazaar: { result: "no hit" } });
  assert.deepStrictEqual(none.find(([k]) => k === "MalwareBazaar"), ["MalwareBazaar", "no hit"]);
  assert.strictEqual(summaryItems({ sha256: "a" }).find(([k]) => k === "MalwareBazaar"), undefined);
});

test("tabs follow the agreed order and leave out excluded views", () => {
  assert.deepStrictEqual(TABS.map((t) => t.id), ["general", "pe", "mz", "sections", "imports", "resources", "debug", "version", "hex"]);
  assert.ok(!TABS.some((t) => /disasm|virus|process|memory|score/i.test(t.label)));
});

test("hex rows and base64 decode", () => {
  const bytes = decodeBase64(Buffer.from("MZ\x90\x00hello world, PE!").toString("base64"));
  const rows = hexRows(bytes);
  assert.strictEqual(rows[0][0], "00000000");
  assert.ok(rows[0][1].startsWith("4D 5A"));
  assert.ok(rows[0][2].startsWith("MZ"));
  assert.deepStrictEqual(hexRows(new Uint8Array(0)), []);
});

test("section flags", () => {
  assert.strictEqual(sectionFlags({ read: true, write: true, execute: true }), "RWX");
  assert.strictEqual(sectionFlags(null), "---");
});

const { parseOffset, pageStart, severityOf, entropyLevel, importTree, resourceTree, safeIconUrl, PAGE_SIZES } = require("./pe-view.js");

test("jump box accepts hex and decimal offsets only", () => {
  assert.strictEqual(parseOffset("0x1F0"), 0x1f0);
  assert.strictEqual(parseOffset("1f0h"), 0x1f0);
  assert.strictEqual(parseOffset(" 496 "), 496);
  for (const bad of ["", "-1", "0x", "zz", "1e9", "0x" + "f".repeat(20), "12345678901234567", null, "<b>"]) assert.strictEqual(parseOffset(bad), null, String(bad));
});

test("hex pages align to 4 KB or 64 KB", () => {
  assert.deepStrictEqual(PAGE_SIZES, [4096, 65536]);
  assert.strictEqual(pageStart(5000, 4096), 4096);
  assert.strictEqual(pageStart(70000, 65536), 65536);
  assert.strictEqual(pageStart(-5, 4096), 0);
  assert.strictEqual(pageStart(5000, 123), 4096);
  assert.strictEqual(hexRows(new Uint8Array(16), 1, 0x1000)[0][0], "00001000");
});

test("severity and entropy bands", () => {
  assert.deepStrictEqual(["HIGH", "medium", "low", "weird", undefined].map(severityOf), ["high", "medium", "low", "low", "low"]);
  assert.deepStrictEqual([7.9, 6.8, 3, NaN, "x"].map(entropyLevel), ["high", "medium", "normal", "none", "none"]);
});

test("import and resource trees group in order", () => {
  const t = importTree([{ dll: "A.dll", name: "f" }, { dll: "B.dll", ordinal: 7 }, { dll: "A.dll", name: "g" }, { dll: "C.dll", name: "h", delayed: true }]);
  assert.deepStrictEqual(t, [["A.dll", ["f", "g"]], ["B.dll", ["ordinal 7"]], ["C.dll (delay)", ["h"]]]);
  assert.deepStrictEqual(importTree(null), []);
  assert.deepStrictEqual(resourceTree([{ type: "ICON" }, { type: "VERSION" }, { type: "ICON" }]).map(([k, v]) => [k, v.length]), [["ICON", 2], ["VERSION", 1]]);
});

test("only parser-built image data URLs are shown", () => {
  assert.ok(safeIconUrl("data:image/png;base64,iVBORw0KGgo="));
  assert.ok(safeIconUrl("data:image/x-icon;base64,AAABAA=="));
  for (const bad of ["data:image/svg+xml;base64,PHN2Zz4=", "javascript:alert(1)", "data:image/png;base64,abc\"onerror=1", "https://x/y.png", null]) assert.ok(!safeIconUrl(bad), String(bad));
});
