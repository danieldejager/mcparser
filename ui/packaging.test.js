const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

// Every local file that main.js or preload.js loads (directly or through
// another local file) must be listed in build.files, or the packaged app
// crashes at launch with "Cannot find module".
test("every locally required module is packaged", () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, "package.json"), "utf8"));
  const packaged = new Set(pkg.build.files);
  const seen = new Set();
  const queue = ["main.js", "preload.js"];
  const missing = [];
  while (queue.length) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const src = fs.readFileSync(path.join(__dirname, file), "utf8");
    for (const m of src.matchAll(/require\(\s*["'](\.\/[^"']+)["']\s*\)/g)) {
      let rel = m[1].slice(2);
      if (!path.extname(rel)) rel += ".js";
      if (!packaged.has(rel)) missing.push(`${file} requires ${rel}`);
      if (rel.endsWith(".js") && fs.existsSync(path.join(__dirname, rel))) queue.push(rel);
    }
  }
  assert.deepStrictEqual(missing, []);
});
