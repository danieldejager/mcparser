// Which mcparser binary the UI spawns. Packaged builds use the one shipped in
// resources. In dev (npm start) both `cargo build` (target/debug) and
// `cargo build --release` (target/release) are common, so the most recently
// built of the two wins. A stale debug build can no longer hide a fresh
// release build, or the other way round.
const path = require("path");
const fs = require("fs");

function binaryName(platform) { return platform === "win32" ? "mcparser.exe" : "mcparser"; }

function devBinary(repo, platform, stat = fs.statSync) {
  const name = binaryName(platform);
  let best = null;
  for (const profile of ["release", "debug"]) {
    const file = path.join(repo, "target", profile, name);
    let s;
    try { s = stat(file); } catch (_) { continue; }
    if (!s || !s.isFile()) continue;
    if (!best || s.mtimeMs > best.mtimeMs) best = { file, mtimeMs: s.mtimeMs };
  }
  // Nothing built yet: point at release so the error names the documented path.
  return best ? best.file : path.join(repo, "target", "release", name);
}

module.exports = { binaryName, devBinary };
