// What the Ask models are told about a case: the schema text, the coverage
// queries and the per-file PE summaries, built only from tables that exist.
// Pure functions; main.js runs the SQL through the read-only query command.
const PE_HINT = "PE rows are static parse results: indicators and compiler details are hints, not verdicts. The file is never run or loaded.";

const BASE = [
  "Return one DuckDB SELECT and no other text.",
];

const TABLES = {
  events: "Table events(source_sha256, record_id, event_id, channel, provider, computer, time_created, event_data, host_id, log_name). Columns, never read these from event_data: computer, channel, provider, host_id, log_name, event_id, time_created, record_id, source_sha256. host_id is a UUID from the host list. A hostname is not a host_id. log_name is a path. Match a file with LIKE '%Security.evtx'. Use a log_name value from the case context. event_data is JSON. Read TargetUserName, LogonType and IpAddress with json_extract_string(event_data, '$.TargetUserName'). A successful logon is event_id 4624.",
  prefetch: "Table prefetch(host_id, pf_name, executable, run_count, last_run, version, path). Use it for what ran on the machine and how often.",
  userassist: "Table userassist(host_id, guid, name, run_count, last_run). Programs Explorer launched for one user. Ignore names starting with UEME_CTL.",
  amcache: "Table amcache(host_id, kind, name, path, sha1, size, modified, publisher, version, key_path). kind is file or program. A file row means the executable was inventoried, not that it ran. modified on a file row is the compile time, not a run time. A program row is an installed product and its modified value is the install date. Match a hash with amcache.sha1.",
  shimcache: "Table shimcache(host_id, path, modified, position, executed, control_set). A row means Windows recorded the path. modified is the file time, not a run time. position 0 is the newest entry.",
  srum: "Table srum(host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received, foreground_cycles, background_cycles). kind is network or app. A network row is hourly bytes for an application. timestamp is when the record was written, not a start time.",
  services: "Table services(host_id, name, display_name, state, start_mode, path, user_id). A row is a Windows service. path is the program it runs.",
  tasks: "Table tasks(host_id, path, command, arguments, user_id, enabled). A row is a scheduled task. command plus arguments is what runs with no one at the keyboard.",
  pe_files: "Table pe_files(sha256, md5, sha1, imphash, host_id, path, file_size, is_pe, is_64, is_dll, is_dotnet, architecture, machine, subsystem, characteristics, dll_characteristics, compile_time, timestamp, entry_point, image_base, section_count, import_count, export_count, resource_count, tls_present, tls_callbacks, signed, certificate_size, overlay_size, pdb_path, warnings, analyzed_at, entry_section, certificate_present, clr_present): one row per analyzed PE file. entry_section is the section holding the entry point ('' when outside any section, a packing hint); entry_section, certificate_present and clr_present are newer columns and may be missing or NULL in cases saved by earlier builds. Every pe_* table joins on sha256. signed means a signature blob is present, not that it is valid. compile_time comes from the header and can be forged. is_dotnet marks a .NET assembly. pdb_path is the debug path the compiler left.",
  pe_sections: "Table pe_sections(sha256, idx, name, virtual_address, virtual_size, raw_offset, raw_size, characteristics, entropy, md5). entropy above 7.2 hints at packed or encrypted data; raw_size 0 with a large virtual_size hints at unpacking at run time.",
  pe_imports: "Table pe_imports(sha256, dll, name, ordinal, delayed). Imported functions. MSVCP*/VCRUNTIME*/libstdc++ hint at C++, mscoree.dll at .NET. VirtualAlloc, WriteProcessMemory, CreateRemoteThread, LoadLibrary plus GetProcAddress, URLDownloadToFile and similar are worth a look, not proof.",
  pe_exports: "Table pe_exports(sha256, ordinal, name, rva, forwarder).",
  pe_resources: "Table pe_resources(sha256, type, name, language, rva, size, resource_sha256, file_offset, resource_md5, malwarebazaar). file_offset is where the data sits in the file (NULL when outside it); malwarebazaar is the local dump result for resource_sha256 ('hit' is a known sample, a hint about an embedded payload). file_offset, resource_md5 and malwarebazaar are newer columns and may be missing in older cases.",
  pe_iocs: "Table pe_iocs(sha256, idx, type, value, source_string_idx, source_string, file_offset, is_private, benign_hint, encoding): IOC candidates pulled from the PE strings; type is url, domain, ipv4, ipv6, email, registry, path, pipe or user_agent. They are hints, not verdicts: a string in a file is not proof of a connection, and packed or encrypted malware may hide its C2 addresses from plain strings. benign_hint marks well-known hosts such as Microsoft or certificate authorities; is_private marks private, loopback or link-local addresses. Prefer rows WHERE NOT benign_hint AND NOT is_private. value is raw; defang it in answers.",
  pe_indicators: "Table pe_indicators(sha256, rule, severity, reason): heuristic hints from the analyzer, not verdicts.",
  pe_strings: "Table pe_strings(sha256, file_offset, encoding, category, value): extracted strings; category groups urls, paths, registry keys and the like. Filter by category or value LIKE; never select it unfiltered.",
  pe_rich: "Table pe_rich(sha256, product_id, build, count): the Rich header, which names the Microsoft toolchain (compiler, linker, C or C++ objects) that built the file. No rows means no Rich header (not MSVC, or stripped).",
  pe_certificates: "Table pe_certificates(sha256, signature_idx, cert_idx, is_signer, subject, subject_cn, subject_o, subject_ou, subject_c, issuer, issuer_cn, issuer_o, issuer_c, serial_hex, serial_dec, version, signature_algorithm, digest_algorithm, not_before, not_after, self_signed, verified, issuer_ou). issuer_ou is a newer column and may be missing in older cases. Parsed only: verified is always false because the chain is not checked. Never call a signature valid or trusted.",
  pe_version_info: "Table pe_version_info(sha256, kind, lang_codepage, key, value): CompanyName, ProductName, OriginalFilename and similar. Self-reported, easily faked.",
  pe_manifest: "Table pe_manifest(sha256, size, truncated, execution_level, ui_access, text).",
  pe_icons: "Table pe_icons(sha256, group_name, icon_id, width, height, bit_count, format, size, icon_sha256, data_base64). data_base64 is the image for small icons only (newer column, may be missing); never select it, use icon_sha256 to compare icons.",
  pe_header_fields: "Table pe_header_fields(sha256, node, idx, field, file_offset, size, value, meaning): raw header fields as text. node is dos, file, optional or dirs (data directories: value is the RVA, size the directory size). Values are hex strings such as 0x14C; meaning decodes some of them.",
  pe_mitigations: "Table pe_mitigations(sha256, idx, name, enabled): exploit mitigations from DllCharacteristics (ASLR, DEP, CFG and so on). Missing mitigations are a hint about an old or unusual toolchain, not a verdict.",
  pe_debug: "Table pe_debug(sha256, idx, type, timestamp, size, pdb_path, raw_offset): debug directory entries. type 2 is CodeView (pdb_path). timestamp is self-reported and can be forged.",
  pe_signatures: "Table pe_signatures(sha256, signature_idx, file_offset, length, revision, cert_type, signed_data_version, digest_algorithm, signature_algorithm, signer_serial_hex, signer_serial_dec, signer_issuer, signer_issuer_cn, signer_issuer_o, signer_issuer_ou, signer_issuer_c, signer_index, error): one row per Authenticode blob; joins pe_certificates on sha256 and signature_idx. Parsed only, never verified; error says why decoding stopped.",
  pe_checks: "Table pe_checks(sha256, source, result, signature, file_name, checked_at): the local MalwareBazaar lookup made when the file was analyzed. result is the match state, signature the malware family when known.",
  malwarebazaar: "Table malwarebazaar(sha256, sha1, md5, signature, file_name, first_seen) is the narrow lookup view of the machine-local MalwareBazaar dump. Match a hash with sha256, sha1 or md5.",
  malwarebazaar_full: "Table malwarebazaar_full(sha256, md5, sha1, sha3_384, imphash, tlsh, ssdeep, telfhash, gimphash, dhash_icon, first_seen, last_seen, reporter, file_name, file_type, mime_type, file_size, signature, clamav, vtpercent, tags, delivery_method, origin_country, intelligence, note) has every column, all VARCHAR. Join pe_files.imphash = malwarebazaar_full.imphash to find known malware built the same way (a similarity hint, not identity); lower(pe_files.sha256) = malwarebazaar_full.sha256 is an exact match.",
};

const COVERAGE = [
  ["events", "SELECT event_id, count(*) AS events FROM events GROUP BY event_id ORDER BY events DESC LIMIT 3"],
  ["prefetch", "SELECT executable, run_count, last_run FROM prefetch ORDER BY run_count DESC LIMIT 3"],
  ["userassist", "SELECT \"name\", run_count FROM userassist WHERE \"name\" NOT LIKE 'UEME_CTL%' ORDER BY run_count DESC LIMIT 3"],
  ["amcache", "SELECT \"name\", sha1, path FROM amcache WHERE kind = 'file' LIMIT 3"],
  ["shimcache", "SELECT position, path FROM shimcache WHERE lower(path) NOT LIKE '%\\\\windows\\\\%' ORDER BY position LIMIT 3"],
  ["srum", "SELECT app, bytes_sent FROM srum WHERE kind = 'network' ORDER BY bytes_sent DESC LIMIT 3"],
  ["services", "SELECT name, start_mode, path FROM services WHERE lower(path) NOT LIKE '%\\\\windows\\\\system32\\\\%' LIMIT 3"],
  ["tasks", "SELECT command, arguments, path FROM tasks WHERE command <> '' AND lower(command) NOT LIKE '%\\\\windows\\\\system32\\\\%' LIMIT 3"],
  ["pe_indicators", "SELECT severity, count(*) AS hits, count(DISTINCT sha256) AS files FROM pe_indicators GROUP BY severity ORDER BY hits DESC LIMIT 5"],
  ["malwarebazaar", "SELECT sha256, file_name, signature FROM malwarebazaar LIMIT 3"],
];

const TABLES_SQL = "SELECT DISTINCT table_name FROM information_schema.tables ORDER BY table_name";

function parseTables(csv) {
  return new Set(String(csv || "").split(/\r?\n/).slice(1).map((l) => l.trim().replace(/^"|"$/g, "").toLowerCase()).filter(Boolean));
}

function buildSchema(tables) {
  const parts = Object.keys(TABLES).filter((t) => tables.has(t)).map((t) => TABLES[t]);
  if (!parts.length) parts.push("No tables are loaded in this case.");
  if ([...tables].some((t) => t.startsWith("pe_"))) parts.push(PE_HINT);
  parts.push("Only the tables above exist; do not query any other table.");
  return parts.concat(BASE).join(" ");
}

function coverageQueries(tables) {
  return COVERAGE.filter(([t]) => tables.has(t));
}

// One row per analyzed PE file with its hints folded into short columns.
function peSummarySql(tables, limit = 25) {
  if (!tables.has("pe_files")) return null;
  const sub = (t, expr) => tables.has(t) ? `(${expr})` : "NULL";
  const cols = [
    "f.sha256", "f.path", "f.architecture", "f.is_dll", "f.is_dotnet", "f.compile_time", "f.imphash",
    "f.signed AS signature_present", "f.pdb_path", "f.overlay_size",
    sub("pe_rich", "SELECT count(*) FROM pe_rich r WHERE r.sha256 = f.sha256") + " AS rich_entries",
    sub("pe_imports", "SELECT string_agg(DISTINCT lower(i.dll), ' ') FROM pe_imports i WHERE i.sha256 = f.sha256 AND regexp_matches(lower(i.dll), '^(msvcp|vcruntime|msvcr|libstdc|libgcc|mscoree|ucrtbase)')") + " AS runtime_dlls",
    sub("pe_sections", "SELECT string_agg(s.name || '=' || round(s.entropy, 2), ' ') FROM pe_sections s WHERE s.sha256 = f.sha256 AND (s.entropy > 7.2 OR (s.raw_size = 0 AND s.virtual_size > 0))") + " AS section_anomalies",
    sub("pe_indicators", "SELECT string_agg(x.severity || ':' || x.rule || ' (' || left(x.reason, 80) || ')', ' | ') FROM (SELECT * FROM pe_indicators n WHERE n.sha256 = f.sha256 ORDER BY CASE lower(n.severity) WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END LIMIT 8) x") + " AS indicators",
    sub("pe_imports", "SELECT string_agg(x.dll || '!' || coalesce(x.name, '#' || x.ordinal), ' ') FROM (SELECT * FROM pe_imports i WHERE i.sha256 = f.sha256 AND regexp_matches(lower(coalesce(i.name, '')), '(virtualalloc|virtualprotect|writeprocessmemory|createremotethread|ntunmapviewofsection|setwindowshookex|getasynckeystate|loadlibrary|getprocaddress|urldownloadtofile|internetopen|winhttp|isdebuggerpresent|cryptencrypt|adjusttokenprivileges|shellexecute|createprocess)') LIMIT 12) x") + " AS notable_imports",
    sub("pe_iocs", "SELECT string_agg(x.type || '=' || x.n, ' ') FROM (SELECT type, count(*) AS n FROM pe_iocs c WHERE c.sha256 = f.sha256 GROUP BY type ORDER BY n DESC, type) x") + " AS ioc_counts",
    sub("pe_iocs", "SELECT string_agg(x.type || ':' || replace(replace(replace(replace(left(x.value, 120), '.', '[.]'), '@', '[@]'), 'http', 'hxxp'), 'ftp://', 'fxp://'), ' | ') FROM (SELECT * FROM pe_iocs c WHERE c.sha256 = f.sha256 ORDER BY (c.benign_hint OR c.is_private), c.idx LIMIT 10) x") + " AS ioc_candidates_defanged",
    sub("pe_checks", "SELECT c.result || coalesce(' ' || nullif(c.signature, ''), '') FROM pe_checks c WHERE c.sha256 = f.sha256 ORDER BY c.checked_at DESC LIMIT 1") + " AS malwarebazaar",
  ];
  return "SELECT " + cols.join(", ") + " FROM pe_files f ORDER BY " +
    (tables.has("pe_indicators") ? "(SELECT count(*) FROM pe_indicators n WHERE n.sha256 = f.sha256) DESC, " : "") +
    "f.path LIMIT " + Number(limit);
}

// Accept one read-only statement: SELECT, or WITH ... SELECT. Joins, CTEs
// and UNION are fine; anything that writes, attaches or reads files is not.
function readOnlySql(text) {
  const fenced = String(text).match(/```(?:sql)?\s*([\s\S]*?)```/i);
  let sql = (fenced ? fenced[1] : String(text)).trim().replace(/;+\s*$/, "");
  if (sql.includes(";")) throw new Error("The model returned more than one statement");
  if (!/^(select|with)\b/i.test(sql)) throw new Error("The model did not return a SELECT");
  if (/\b(attach|detach|copy|pragma|insert|update|delete|drop|create|alter|install|load|export|import|set|call|checkpoint|vacuum)\b/i.test(sql)) {
    throw new Error("The model returned a statement that is not a read");
  }
  if (/\b(read_csv\w*|read_parquet|read_json\w*|read_text|read_blob|glob|httpfs|sqlite_scan|getenv)\s*\(/i.test(sql)) {
    throw new Error("The model returned a statement that reads outside the case");
  }
  if (!/\blimit\b/i.test(sql)) sql += " LIMIT 50";
  return sql;
}

const RULES = "\nWrite one read-only DuckDB statement: a SELECT, optionally with WITH, JOINs (pe_* tables and malwarebazaar_full join on sha256 or imphash) or UNION ALL. No other text. Only use tables from the schema above.\n";

const ANSWER_RULES = "Answer from these rows only. Be brief. Do not invent rows. If a source says not loaded or query failed, say so. " +
  "For PE files say hints, not verdicts: an indicator, packer entropy or a suspicious import is a reason to look, a MalwareBazaar sha256 match is a known sample, an imphash match is only similar. Never call a certificate valid or verified. " +
  "IOC candidates from PE strings are hints, not verdicts: never call one confirmed malicious or a confirmed C2, and say that packed or encrypted malware may hide its C2 addresses. Always write IOC values defanged (hxxp, [.] and [@]).\n";

module.exports = { TABLES, TABLES_SQL, parseTables, buildSchema, coverageQueries, peSummarySql, readOnlySql, RULES, ANSWER_RULES };
