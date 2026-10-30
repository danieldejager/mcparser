const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { devBinary, binaryName } = require("./parser-binary.js");

function repoWith(builds) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "mcparser-bin-"));
  for (const [profile, secondsAgo] of Object.entries(builds)) {
    const dir = path.join(repo, "target", profile);
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, binaryName(process.platform));
    fs.writeFileSync(file, "x");
    const t = new Date(Date.now() - secondsAgo * 1000);
    fs.utimesSync(file, t, t);
  }
  return repo;
}
const bin = (repo, profile) => path.join(repo, "target", profile, binaryName(process.platform));

test("dev picks the newer of target/release and target/debug", () => {
  let repo = repoWith({ release: 10, debug: 3600 });
  assert.strictEqual(devBinary(repo, process.platform), bin(repo, "release"), "a stale debug build no longer wins");
  repo = repoWith({ release: 3600, debug: 10 });
  assert.strictEqual(devBinary(repo, process.platform), bin(repo, "debug"));
});

test("dev uses whichever single build exists, release path when none", () => {
  let repo = repoWith({ debug: 5 });
  assert.strictEqual(devBinary(repo, process.platform), bin(repo, "debug"));
  repo = repoWith({ release: 5 });
  assert.strictEqual(devBinary(repo, process.platform), bin(repo, "release"));
  repo = repoWith({});
  assert.strictEqual(devBinary(repo, process.platform), bin(repo, "release"));
});

test("windows name and main.js wiring", () => {
  assert.strictEqual(binaryName("win32"), "mcparser.exe");
  assert.strictEqual(binaryName("linux"), "mcparser");
  const m = fs.readFileSync(path.join(__dirname, "main.js"), "utf8");
  assert.ok(m.includes("return parserBin.devBinary(repo, process.platform);"));
  assert.ok(!m.includes('path.join(repo, "target", "debug"'));
});
