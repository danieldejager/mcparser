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
