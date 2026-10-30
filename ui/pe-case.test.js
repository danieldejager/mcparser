const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const { isPeFilesResult, targetFromRow, queries, parseJsonl, buildReport } = require("./pe-case.js");
const PeView = require("./pe-view.js");

const SHA = "a".repeat(64);

test("pe_files results are detected by columns, not SQL text", () => {
  assert.ok(isPeFilesResult(["sha256", "path", "file_size"]));
  assert.ok(isPeFilesResult(["\"SHA256\"", "is_pe"]));
  assert.ok(!isPeFilesResult(["sha256", "dll", "name"]));
  assert.ok(!isPeFilesResult(["path", "file_size"]));
  assert.ok(!isPeFilesResult(null));
});

test("targetFromRow takes the clicked row's sha256, host and path", () => {
  const h = ["host_id", "path", "sha256"];
  assert.deepStrictEqual(targetFromRow(h, ["h1", "C:\\a.exe", SHA.toUpperCase()]), { sha256: SHA, host_id: "h1", path: "C:\\a.exe" });
  assert.deepStrictEqual(targetFromRow(["sha256", "is_pe"], [SHA, "true"]), { sha256: SHA, host_id: null, path: null });
  assert.strictEqual(targetFromRow(h, ["h1", "x", "not-a-hash"]), null);
});

test("queries are read-only, quote literals and refuse a bad hash", () => {
  const q = queries({ sha256: SHA, host_id: "h'1", path: "C:\\it's.exe" });
  assert.match(q.files, /WHERE sha256 = 'a{64}' AND host_id = 'h''1' AND path = 'C:\\it''s\.exe' LIMIT 1$/);
  for (const sql of Object.values(q)) assert.match(sql, /^SELECT /);
  for (const sql of Object.values(q)) assert.ok(!/;|DELETE|INSERT|UPDATE|DROP/i.test(sql));
  assert.throws(() => queries({ sha256: "1' OR '1'='1" }));
  assert.ok(!/host_id/.test(queries({ sha256: SHA, host_id: null, path: null }).files.split("WHERE")[1]));
});

test("parseJsonl skips junk lines", () => {
  assert.deepStrictEqual(parseJsonl("[\"a\",\"1\"]\nnoise\n[bad\n"), [["a", "1"]]);
});

test("buildReport gives the pe --json shape the view reads", () => {
  const rows = {
    files: [[SHA, "m", "s1", "imp", "h1", "C:\\x.exe", "2048", "true", "true", "false", "false", "x64", "Windows GUI", "EXECUTABLE_IMAGE|LARGE_ADDRESS_AWARE", "2024-01-01T00:00:00Z", "true", "0", "", "false", "0", "100", "x.pdb", "4096"]],
    sections: [["0", ".text", "4096", "512", "1024", "512", "1610612768", "6.1", "ab"]],
    imports: [["KERNEL32.dll", "CreateFileW", "", "false"], ["WS2_32.dll", "", "23", "true"]],
    exports: [["1", "Run", "4096", ""]],
    resources: [["VERSION", "1", "1033", "8192", "300", "cd"]],
    indicators: [["packed", "high", "entropy"]],
    strings: [["10", "ascii", "url", "http://x"]],
    rich: [["259", "30729", "4"]],
    certificates: [["0", "0", "true", "CN=A", "A", "", "", "", "CN=B", "B", "", "", "01", "1", "3", "sha256RSA", "sha256", "2020", "2030", "false"]],
    version: [["fixed", "", "FileVersion", "1.0"], ["string", "040904B0", "ProductName", "X"], ["translation", "040904B0", "Translation", ""]],
    manifest: [["120", "false", "asInvoker", "false", "<assembly/>"]],
    checks: [["hit", "AgentTesla", "x.exe", "2026"]],
  };
  const r = buildReport(rows);
  assert.strictEqual(r.path, "C:\\x.exe");
  assert.strictEqual(r.summary.sha256, SHA);
  assert.strictEqual(r.summary.file_size, 2048);
  assert.strictEqual(r.summary.is_pe, true);
  assert.deepStrictEqual(r.summary.characteristics, ["EXECUTABLE_IMAGE", "LARGE_ADDRESS_AWARE"]);
  assert.deepStrictEqual(r.summary.malwarebazaar, { result: "hit", signature: "AgentTesla", file_name: "x.exe" });
  assert.deepStrictEqual(r.sections[0].flags, { read: true, write: false, execute: true, shared: false, code: true });
  assert.strictEqual(r.imports[0].ordinal, null);
  assert.strictEqual(r.imports[1].ordinal, 23);
  assert.strictEqual(r.imports[1].delayed, true);
  assert.strictEqual(r.signatures[0].certificates[0].subject.cn, "A");
  assert.deepStrictEqual(r.version_info.translations, ["040904B0"]);
  assert.strictEqual(r.manifest.execution_level, "asInvoker");
  assert.strictEqual(r.debug[0].pdb_path, "x.pdb");
  assert.ok(PeView.flattenTree(r.tree).some((n) => n.id === "saved"));
  assert.strictEqual(PeView.importTree(r.imports).length, 2);
  assert.strictEqual(buildReport({ files: [] }), null);
});

test("renderer offers Open PE analysis with keyboard access", () => {
  const src = fs.readFileSync(path.join(__dirname, "renderer.js"), "utf8");
  assert.match(src, /"Open PE analysis"/);
  assert.match(src, /event\.key === "ContextMenu"/);
  assert.match(src, /event\.shiftKey && event\.key === "F10"/);
  assert.match(src, /role", "menuitem"/);
  const view = fs.readFileSync(path.join(__dirname, "pe-view.js"), "utf8");
  assert.match(view, /Locate file\.\.\./);
  const main = fs.readFileSync(path.join(__dirname, "main.js"), "utf8");
  assert.match(main, /fileMatches\(picked\.filePaths\[0\], peCaseSha\)/);
});
