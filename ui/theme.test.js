const test = require("node:test");
const assert = require("node:assert");
const T = require("./theme.js");

const mem = (init) => { const m = new Map(init ? [[T.KEY, init]] : []); return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, v), m }; };

test("default is follow system", () => {
  assert.strictEqual(T.load(mem()), "system");
  assert.strictEqual(T.load(mem("purple")), "system");
  assert.strictEqual(T.load(null), "system");
});

test("system resolves from prefers-color-scheme, explicit choices win", () => {
  assert.strictEqual(T.resolve("system", true), "dark");
  assert.strictEqual(T.resolve("system", false), "light");
  assert.strictEqual(T.resolve("light", true), "light");
  assert.strictEqual(T.resolve("dark", false), "dark");
  assert.strictEqual(T.resolve(undefined, true), "dark");
});

test("save persists normalized choice and round trips", () => {
  const s = mem();
  assert.strictEqual(T.save(s, "dark"), "dark");
  assert.strictEqual(T.load(s), "dark");
  T.save(s, "bogus");
  assert.strictEqual(s.m.get(T.KEY), "system");
});

test("storage errors fall back quietly", () => {
  const bad = { getItem() { throw new Error("x"); }, setItem() { throw new Error("x"); } };
  assert.strictEqual(T.load(bad), "system");
  assert.strictEqual(T.save(bad, "light"), "light");
});

test("arrow keys wrap through the radio group", () => {
  assert.strictEqual(T.step("light", "ArrowRight"), "dark");
  assert.strictEqual(T.step("system", "ArrowDown"), "light");
  assert.strictEqual(T.step("light", "ArrowLeft"), "system");
  assert.strictEqual(T.step("dark", "Home"), "light");
  assert.strictEqual(T.step("light", "End"), "system");
  assert.strictEqual(T.step("light", "a"), null);
});
