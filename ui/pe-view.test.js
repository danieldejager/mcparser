const test = require("node:test");
const assert = require("node:assert");
const { flattenTree, summaryItems } = require("./pe-view.js");

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
