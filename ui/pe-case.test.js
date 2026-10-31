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
  assert.match(main, /openRef\(picked\.filePaths\[0\], peCaseSha\)/);
});

test("buildReport fills headers, mitigations, debug, signer and icons from newer cases", () => {
  const png = Buffer.from([0x89, 0x50, 0x4e, 0x47]).toString("base64");
  const rows = {
    files: [[SHA, "m", "s1", "imp", "h1", "C:\\x.exe", "2048", "true", "true", "false", "false", "x64", "Windows GUI", "EXECUTABLE_IMAGE", "2024", "true", "0", "", "false", "0", "100", "x.pdb", "4096"]],
    files_ext: [[".text", "true", "false"]],
    resources: [["ICON", "1", "1033", "8192", "300", "cd"]],
    resources_ext: [["ICON", "1", "1033", "8192", "300", "cd", "1536", "md", "no hit"]],
    certificates: [["0", "0", "true", "CN=A", "A", "", "", "", "CN=B", "B", "", "", "01", "1", "3", "sha256RSA", "sha256", "2020", "2030", "false"]],
    certificates_ext: [["0", "0", "Unit"]],
    icons_ext: [["1", "2", "16", "16", "32", "png", png], ["1", "3", "256", "256", "32", "png", null]],
    headers: [["dos", "e_magic", "0x0", "2", "0x5A4D", "MZ"], ["file", "Machine", "0x84", "2", "0x8664", "AMD64"], ["optional", "Magic", "0x98", "2", "0x20B", "PE32+"], ["dirs", "IMPORT", "", "0x28", "0x2000", "present"]],
    mitigations: [["ASLR (DYNAMIC_BASE)", "true"], ["DEP (NX_COMPAT)", "false"]],
    debug: [["2", "2024-01-01T00:00:00Z", "40", "x.pdb", "1200"]],
    signatures: [["0", "4096", "900", "0x0200", "0x0002", "1", "sha256", "sha256RSA", "0A", "10", "CN=B", "B", "BO", "", "US", "0", ""]],
  };
  const r = buildReport(rows);
  assert.strictEqual(r.case_extended, true);
  assert.strictEqual(r.entry_section, ".text");
  assert.deepStrictEqual(r.mitigations, [{ name: "ASLR (DYNAMIC_BASE)", enabled: true }, { name: "DEP (NX_COMPAT)", enabled: false }]);
  assert.deepStrictEqual(r.debug, [{ type: 2, timestamp: "2024-01-01T00:00:00Z", size: 40, pdb_path: "x.pdb", raw_offset: 1200 }]);
  assert.strictEqual(r.resources[0].offset, 1536);
  assert.strictEqual(r.resources[0].md5, "md");
  assert.strictEqual(r.resources[0].malwarebazaar, "no hit");
  assert.strictEqual(r.signatures[0].offset, 4096);
  assert.strictEqual(r.signatures[0].signer_issuer.o, "BO");
  assert.strictEqual(r.signatures[0].certificates[0].issuer.ou, "Unit");
  assert.strictEqual(r.signatures[0].status, "signature present, not verified");
  assert.strictEqual(r.icons.length, 1);
  assert.ok(PeView.safeIconUrl(r.icons[0].data_url));
  const flat = PeView.flattenTree(r.tree);
  for (const id of ["dos", "nt", "file", "optional", "dirs", "debug", "clr"]) assert.ok(flat.some((n) => n.id === id), id);
  assert.ok(!flat.some((n) => n.id === "saved"));
  assert.strictEqual(flat.find((n) => n.id === "dos").rows[0].meaning, "MZ");
});

test("buildReport keeps the old behaviour for cases from earlier builds", () => {
  const rows = { files: [[SHA, "m", "s1", "imp", "h1", "C:\\x.exe", "2048", "true", "true", "false", "false", "x64", "GUI", "", "2024", "false", "0", "", "false", "0", "0", "x.pdb", "4096"]],
    files_ext: [], headers: [], mitigations: [], resources: [["VERSION", "1", "1033", "8192", "300", "cd"]] };
  const r = buildReport(rows);
  assert.strictEqual(r.case_extended, false);
  assert.strictEqual(r.entry_section, undefined);
  assert.deepStrictEqual(r.mitigations, []);
  assert.strictEqual(r.resources[0].offset, null);
  assert.strictEqual(r.debug[0].pdb_path, "x.pdb");
  assert.ok(PeView.flattenTree(r.tree).some((n) => n.id === "saved"));
  // A row saved before the new columns existed reads NULL.
  assert.strictEqual(buildReport({ ...rows, files_ext: [[null, null, null]] }).case_extended, false);
});

test("newer case queries are read-only and scoped to the file", () => {
  const q = queries({ sha256: SHA, host_id: "h", path: "p" });
  assert.match(q.files_ext, /AND host_id = 'h' AND path = 'p' LIMIT 1$/);
  for (const k of ["headers", "mitigations", "debug", "signatures", "resources_ext", "icons_ext", "certificates_ext"]) assert.match(q[k], new RegExp("^SELECT .* WHERE sha256 = 'a{64}'"), k);
});

test("buildReport reads pe_iocs and marks a case without the table", () => {
  const base = { files: [[SHA, "m", "s1", "imp", "h1", "C:\\x.exe", "2048", "true", "true", "false", "false", "x64", "Windows GUI", "", "", "false", "0", "", "false", "0", "100", "", "0"]] };
  const r = buildReport({ ...base, iocs: [["url", "http://c2.example.com/gate", "768", "ascii", "false", "false", "1", "http://c2.example.com/gate"], ["ipv4", "10.0.0.5", "", "ascii", "true", "false", "4", "10.0.0.5"]] });
  assert.deepStrictEqual(r.iocs[0], { type: "url", value: "http://c2.example.com/gate", offset: 768, encoding: "ascii", is_private: false, benign_hint: false, source_string_idx: 1, source_string: "http://c2.example.com/gate" });
  assert.strictEqual(r.iocs[1].is_private, true);
  assert.strictEqual(r.iocs[1].offset, null);
  assert.match(queries({ sha256: SHA }).iocs, /FROM pe_iocs WHERE sha256 = .a{64}. ORDER BY idx LIMIT 5000$/);
  const old = buildReport({ ...base, iocs: [], _failed: ["iocs"] });
  assert.strictEqual(old.iocs, undefined);
});
