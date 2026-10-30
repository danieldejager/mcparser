const test = require("node:test");
const assert = require("node:assert");
const ask = require("./ask-context");

const csv = (names) => "table_name\n" + names.join("\n") + "\n";

test("parseTables reads the information_schema csv", () => {
  const t = ask.parseTables(csv(["events", "\"pe_files\"", "Malwarebazaar"]));
  assert.deepStrictEqual([...t].sort(), ["events", "malwarebazaar", "pe_files"]);
  assert.strictEqual(ask.parseTables("").size, 0);
});

test("schema without PE tables names no pe_* table", () => {
  const s = ask.buildSchema(ask.parseTables(csv(["events", "prefetch"])));
  assert.match(s, /Table events\(/);
  assert.match(s, /Table prefetch\(/);
  assert.doesNotMatch(s, /pe_files|pe_imports|malwarebazaar|Table amcache|Table srum/);
  assert.strictEqual(ask.peSummarySql(ask.parseTables(csv(["events"]))), null);
});

test("schema with PE and MalwareBazaar tables describes them as hints", () => {
  const t = new Set(Object.keys(ask.TABLES));
  const s = ask.buildSchema(t);
  for (const name of ["pe_files", "pe_sections", "pe_imports", "pe_exports", "pe_resources", "pe_indicators", "pe_strings", "pe_rich", "pe_certificates", "pe_version_info", "pe_manifest", "pe_icons", "pe_checks", "pe_header_fields", "pe_mitigations", "pe_debug", "pe_signatures", "malwarebazaar", "malwarebazaar_full"]) {
    assert.match(s, new RegExp("Table " + name + "\\("), name);
  }
  assert.match(s, /hints, not verdicts/);
  assert.match(s, /verified is always false/);
  assert.match(s, /imphash/);
});

test("missing tables get no coverage query", () => {
  const names = ask.coverageQueries(ask.parseTables(csv(["malwarebazaar", "pe_indicators"]))).map(([n]) => n);
  assert.deepStrictEqual(names, ["pe_indicators", "malwarebazaar"]);
  assert.deepStrictEqual(ask.coverageQueries(new Set()), []);
  assert.match(ask.buildSchema(new Set()), /No tables are loaded/);
});

test("PE summary only references tables that exist", () => {
  const only = ask.peSummarySql(new Set(["pe_files"]));
  assert.doesNotMatch(only, /pe_imports|pe_indicators|pe_rich|pe_checks|pe_sections/);
  const full = ask.peSummarySql(new Set(Object.keys(ask.TABLES)), 10);
  for (const t of ["pe_imports", "pe_indicators", "pe_rich", "pe_checks", "pe_sections"]) assert.match(full, new RegExp(t));
  assert.match(full, /LIMIT 10$/);
  assert.match(full, /signature_present/);
  assert.doesNotMatch(full, /verified/);
  assert.doesNotThrow(() => ask.readOnlySql(full));
});

test("readOnlySql allows joins, CTEs and UNION but not writes", () => {
  assert.match(ask.readOnlySql("SELECT f.path FROM pe_files f JOIN pe_imports i ON i.sha256 = f.sha256"), /LIMIT 50$/);
  assert.ok(ask.readOnlySql("```sql\nWITH x AS (SELECT sha256 FROM pe_files) SELECT * FROM x UNION ALL SELECT sha256 FROM malwarebazaar LIMIT 5;\n```").startsWith("WITH"));
  for (const bad of ["DROP TABLE pe_files", "SELECT 1; DELETE FROM pe_files", "SELECT * FROM read_csv('/etc/passwd')",
    "WITH x AS (SELECT 1) INSERT INTO pe_files SELECT * FROM x", "SELECT 1 FROM pe_files; ATTACH 'x'", "COPY pe_files TO 'x'",
    "SELECT getenv('HOME')"]) {
    assert.throws(() => ask.readOnlySql(bad), bad);
  }
});

test("newer PE tables and columns are described only when the table exists", () => {
  const old = ask.buildSchema(ask.parseTables(csv(["pe_files", "pe_certificates"])));
  for (const t of ["pe_header_fields", "pe_mitigations", "pe_debug", "pe_signatures"]) assert.doesNotMatch(old, new RegExp("Table " + t + "\\("), t);
  assert.match(old, /entry_section/);
  assert.match(old, /earlier builds/);
  assert.match(old, /hints, not verdicts/);
  const full = ask.buildSchema(ask.parseTables(csv(["pe_files", "pe_resources", "pe_icons", "pe_header_fields", "pe_mitigations", "pe_debug", "pe_signatures"])));
  for (const c of ["file_offset, resource_md5, malwarebazaar", "data_base64", "Table pe_header_fields(", "Table pe_mitigations(", "Table pe_debug(", "Table pe_signatures("]) assert.ok(full.includes(c), c);
  assert.match(full, /never verified/);
  assert.match(full, /not a verdict/);
});
