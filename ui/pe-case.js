// Rebuild the PE view report from the pe_* tables saved in an open case.
// Read only: plain SELECTs on the case database. The file itself is not
// opened here; the hex view reads it only after its sha256 is checked.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PeCase = api;
})(typeof self !== "undefined" ? self : this, function () {
  const SHA256 = /^[0-9a-f]{64}$/i;
  const clean = (h) => String(h || "").trim().replaceAll("\"", "").toLowerCase();

  // A result grid holds pe_files rows when it has sha256 plus at least one
  // pe_files column that other tables with a sha256 do not have.
  function isPeFilesResult(headers) {
    const h = (headers || []).map(clean);
    return h.includes("sha256") && ["path", "file_size", "is_pe"].some((c) => h.includes(c));
  }

  // The clicked row's file: sha256, plus host_id and path when shown.
  function targetFromRow(headers, row) {
    const h = (headers || []).map(clean);
    const at = (name) => { const i = h.indexOf(name); return i >= 0 && row[i] !== undefined ? String(row[i]) : null; };
    const sha256 = (at("sha256") || "").trim().toLowerCase();
    if (!SHA256.test(sha256)) return null;
    return { sha256, host_id: at("host_id"), path: at("path") };
  }

  const lit = (v) => "'" + String(v).replaceAll("'", "''") + "'";

  // Column order matters: jsonl rows are arrays without a header.
  const QUERIES = {
    files: "SELECT sha256, md5, sha1, imphash, host_id, path, file_size, is_pe, is_64, is_dll, is_dotnet, architecture, subsystem, characteristics, compile_time, signed, overlay_size, warnings, tls_present, tls_callbacks, certificate_size, pdb_path, entry_point FROM pe_files",
    sections: "SELECT idx, name, virtual_address, virtual_size, raw_offset, raw_size, characteristics, entropy, md5 FROM pe_sections",
    imports: "SELECT dll, name, ordinal, delayed FROM pe_imports",
    exports: "SELECT ordinal, name, rva, forwarder FROM pe_exports",
    resources: "SELECT type, name, language, rva, size, resource_sha256 FROM pe_resources",
    indicators: "SELECT rule, severity, reason FROM pe_indicators",
    strings: "SELECT file_offset, encoding, category, value FROM pe_strings",
    rich: "SELECT product_id, build, count FROM pe_rich",
    certificates: "SELECT signature_idx, cert_idx, is_signer, subject, subject_cn, subject_o, subject_ou, subject_c, issuer, issuer_cn, issuer_o, issuer_c, serial_hex, serial_dec, version, signature_algorithm, digest_algorithm, not_before, not_after, self_signed FROM pe_certificates",
    version: "SELECT kind, lang_codepage, key, value FROM pe_version_info",
    manifest: "SELECT size, truncated, execution_level, ui_access, text FROM pe_manifest",
    icons: "SELECT group_name, icon_id, width, height, bit_count FROM pe_icons",
    checks: "SELECT result, signature, file_name, checked_at FROM pe_checks",
    // Added by later builds. Cases from earlier builds do not have these
    // tables or columns; their query fails and the base query above is used.
    files_ext: "SELECT entry_section, certificate_present, clr_present FROM pe_files",
    resources_ext: "SELECT type, name, language, rva, size, resource_sha256, file_offset, resource_md5, malwarebazaar FROM pe_resources",
    certificates_ext: "SELECT signature_idx, cert_idx, issuer_ou FROM pe_certificates",
    icons_ext: "SELECT group_name, icon_id, width, height, bit_count, format, data_base64 FROM pe_icons",
    headers: "SELECT node, field, file_offset, size, value, meaning FROM pe_header_fields",
    mitigations: "SELECT name, enabled FROM pe_mitigations",
    debug: "SELECT type, timestamp, size, pdb_path, raw_offset FROM pe_debug",
    signatures: "SELECT signature_idx, file_offset, length, revision, cert_type, signed_data_version, digest_algorithm, signature_algorithm, signer_serial_hex, signer_serial_dec, signer_issuer, signer_issuer_cn, signer_issuer_o, signer_issuer_ou, signer_issuer_c, signer_index, error FROM pe_signatures",
  };
  const ORDER = { files: "", sections: " ORDER BY idx", imports: "", exports: " ORDER BY ordinal", resources: "", indicators: "", strings: " ORDER BY file_offset LIMIT 5000", rich: "", certificates: " ORDER BY signature_idx, cert_idx", version: "", manifest: " LIMIT 1", icons: "", checks: " ORDER BY checked_at DESC LIMIT 1",
    files_ext: "", resources_ext: "", certificates_ext: " ORDER BY signature_idx, cert_idx", icons_ext: "", headers: " ORDER BY idx", mitigations: " ORDER BY idx", debug: " ORDER BY idx", signatures: " ORDER BY signature_idx" };

  // SQL per table for one target. Only a validated sha256 and quoted
  // literals are put into the text.
  function queries(target) {
    if (!target || !SHA256.test(target.sha256 || "")) throw new Error("bad sha256");
    const where = " WHERE sha256 = " + lit(target.sha256);
    const out = {};
    for (const [k, q] of Object.entries(QUERIES)) {
      let w = where;
      if (k === "files" || k === "files_ext") {
        if (target.host_id !== null && target.host_id !== undefined) w += " AND host_id = " + lit(target.host_id);
        if (target.path !== null && target.path !== undefined) w += " AND path = " + lit(target.path);
        out[k] = q + w + " LIMIT 1";
      } else out[k] = q + w + ORDER[k];
    }
    return out;
  }

  function parseJsonl(text) {
    return String(text || "").split("\n").filter((l) => l.trim().startsWith("[")).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  }

  const num = (v) => (v === null || v === undefined || v === "" ? 0 : Number(v));
  const bool = (v) => v === true || /^(true|1|yes)$/i.test(String(v));
  const hexv = (v) => "0x" + num(v).toString(16).toUpperCase();

  // Same shape as `mcparser pe --json` (crates/case/src/pe.rs report_json),
  // limited to what the case keeps. A case from an earlier build has no
  // header fields, mitigations, debug details, signer details or icon images;
  // `case_extended` is false then and those parts are empty.
  function buildReport(rows) {
    const f = (rows.files || [])[0];
    if (!f) return null;
    const [sha256, md5, sha1, imphash, , path, file_size, is_pe, is_64, is_dll, is_dotnet, architecture, subsystem, characteristics, compile_time, signed, overlay_size, warnings, tls_present, tls_callbacks, certificate_size, pdb_path] = f;
    const R = (k) => rows[k] || [];
    const check = R("checks")[0];
    const sections = R("sections").map(([, name, va, vs, ro, rs, ch, entropy, smd5]) => {
      const c = num(ch);
      return { name, virtual_size: num(vs), virtual_address: num(va), raw_size: num(rs), raw_offset: num(ro), entropy: num(entropy), md5: smd5,
        flags: { read: (c & 0x40000000) !== 0, write: c >= 0x80000000, execute: (c & 0x20000000) !== 0, shared: (c & 0x10000000) !== 0, code: (c & 0x20) !== 0 },
        ratio: num(file_size) > 0 ? Math.round(num(rs) / num(file_size) * 100) : 0 };
    });
    const imports = R("imports").map(([dll, name, ordinal, delayed]) => ({ dll, name, ordinal: ordinal === "" || ordinal === null ? null : num(ordinal), delayed: bool(delayed) }));
    const exports = R("exports").map(([ordinal, name, rva, forwarder]) => ({ ordinal: num(ordinal), name, rva: num(rva), forwarder: forwarder || "" }));
    // Saved by this build: certificate_present is never NULL in new rows.
    const ext = R("files_ext")[0];
    const extended = Boolean(ext) && ext[1] !== null && ext[1] !== undefined && ext[1] !== "";
    const offOrNull = (v) => (v === null || v === undefined || v === "" ? null : num(v));
    const resources = (extended && R("resources_ext").length ? R("resources_ext") : R("resources")).map(([type, name, language, rva, size, rsha, off, rmd5, mbz]) => ({ type, name, language: num(language), rva: num(rva), size: num(size), sha256: rsha, md5: rmd5 || "", offset: offOrNull(off), malwarebazaar: mbz || null }));
    const issuerOu = new Map(R("certificates_ext").map(([si, ci, ou]) => [num(si) + ":" + num(ci), ou || ""]));
    const sigs = new Map();
    for (const c of R("certificates")) {
      const [si, ci, signer, subject, scn, so, sou, sc, issuer, icn, io, ic, serial_hex, serial_dec, version, alg, digest, nb, na, self] = c;
      if (!sigs.has(num(si))) sigs.set(num(si), { status: "signature present, not verified", digest_algorithm: digest, certificates: [] });
      sigs.get(num(si)).certificates.push({ index: num(ci), is_signer: bool(signer), self_signed: bool(self), version: num(version),
        subject: { full: subject, cn: scn, o: so, ou: sou, c: sc }, issuer: { full: issuer, cn: icn, o: io, ou: issuerOu.get(num(si) + ":" + num(ci)) || "", c: ic },
        serial_hex, serial_dec, signature_algorithm: alg, not_before: nb, not_after: na });
    }
    for (const [si, off, length, revision, cert_type, version, digest, alg, shex, sdec, iss, icn, io, iou, ic, sidx, error] of R("signatures")) {
      const k = num(si);
      if (!sigs.has(k)) sigs.set(k, { status: "signature present, not verified", digest_algorithm: digest, certificates: [] });
      Object.assign(sigs.get(k), { offset: num(off), length: num(length), revision, cert_type, version: num(version), digest_algorithm: digest, signature_algorithm: alg,
        signer_serial_hex: shex, signer_serial_dec: sdec, signer_issuer: { full: iss, cn: icn, o: io, ou: iou, c: ic }, signer_index: offOrNull(sidx), error: error || "" });
    }
    const ver = R("version");
    const m = R("manifest")[0];
    const row = (field, value, meaning) => ({ field, offset: "", size: "", value: String(value ?? ""), meaning: meaning || "" });
    const flag = (b) => (bool(b) ? "yes" : "no");
    const hrow = ([, field, offset, size, value, meaning]) => ({ field, offset: offset || "", size: String(size ?? ""), value: String(value ?? ""), meaning: meaning || "" });
    const hnode = (n) => R("headers").filter((h) => h[0] === n).map(hrow);
    const headerTree = extended && R("headers").length ? [
      { id: "dos", label: "DOS header", rows: hnode("dos") },
      { id: "nt", label: "NT headers", children: [
        { id: "file", label: "File header", rows: hnode("file") },
        { id: "optional", label: "Optional header", rows: hnode("optional") },
        { id: "dirs", label: "Data directories", rows: hnode("dirs") },
      ] },
    ] : [{ id: "saved", label: "Saved in case", rows: [row("Characteristics", characteristics), row("Subsystem", subsystem), row("Compile time", compile_time), row("Certificate size", hexv(certificate_size))] }];
    const debug = extended
      ? R("debug").map(([type, timestamp, size, pdb, raw]) => ({ type: num(type), timestamp: timestamp || "", size: num(size), pdb_path: pdb || "", raw_offset: num(raw) }))
      : (pdb_path ? [{ type: 2, timestamp: "", size: 0, pdb_path, raw_offset: 0 }] : []);
    const icons = extended ? R("icons_ext").filter((i) => i[6]).map(([group, icon_id, width, height, bit_count, format, b64]) => ({ group, icon_id: num(icon_id), width: num(width), height: num(height), bit_count: num(bit_count),
      data_url: `data:${format === "png" ? "image/png" : "image/x-icon"};base64,${b64}` })) : [];
    return {
      path,
      from_case: true,
      case_extended: extended,
      summary: { md5, sha1, sha256, imphash, file_size: num(file_size), is_pe: bool(is_pe), architecture, is_64: bool(is_64), subsystem,
        characteristics: String(characteristics || "").split("|").filter(Boolean), compile_time, signed: bool(signed), dotnet: bool(is_dotnet), dll: bool(is_dll),
        overlay_size: num(overlay_size), warnings: String(warnings || "").split("; ").filter(Boolean),
        malwarebazaar: check ? { result: check[0], signature: check[1], file_name: check[2] } : null },
      mitigations: extended ? R("mitigations").map(([name, enabled]) => ({ name, enabled: bool(enabled) })) : [],
      ...(extended ? { entry_section: ext[0] || null } : {}),
      indicators: R("indicators").map(([rule, severity, reason]) => ({ rule, severity, reason })),
      rich: R("rich").map(([product_id, build, count]) => ({ product_id: num(product_id), build: num(build), count: num(count) })),
      strings: R("strings").map(([offset, encoding, category, value]) => ({ offset: num(offset), encoding, category, value })),
      sections, imports, exports, resources,
      debug,
      signatures: [...sigs.values()],
      tls: { present: bool(tls_present), callbacks: num(tls_callbacks) },
      version_info: ver.length ? {
        fixed: ver.filter((v) => v[0] === "fixed").map((v) => ({ key: v[2], value: v[3] })),
        strings: ver.filter((v) => v[0] === "string").map((v) => ({ table: v[1], key: v[2], value: v[3] })),
        translations: ver.filter((v) => v[0] === "translation").map((v) => v[1]),
        warnings: [],
      } : null,
      manifest: m ? { size: num(m[0]), truncated: bool(m[1]), execution_level: m[2], ui_access: m[3], text: m[4] } : null,
      icons,
      tree: [
        ...headerTree,
        { id: "sections", label: "Section table", rows: sections.map((s) => row(s.name, hexv(s.virtual_address), `raw ${hexv(s.raw_offset)}, vsize ${hexv(s.virtual_size)}, entropy ${s.entropy.toFixed(3)}`)) },
        { id: "imports", label: `Imports (${imports.length})`, rows: imports.map((i) => row(i.dll, i.ordinal !== null ? "ord " + i.ordinal : i.name, i.delayed ? "delay load" : "")) },
        { id: "exports", label: `Exports (${exports.length})`, rows: exports.map((e) => row(e.name, hexv(e.rva), `ordinal ${e.ordinal}`)) },
        { id: "tls", label: "TLS", rows: [row("present", flag(tls_present), `${num(tls_callbacks)} callbacks`)] },
        { id: "debug", label: "Debug", rows: debug.map((d) => row(`type ${d.type}`, d.timestamp, d.pdb_path)) },
        { id: "cert", label: "Certificate", rows: [row("present", flag(extended ? ext[1] : signed), "Authenticode blob present, signature not verified")] },
        ...(extended ? [{ id: "clr", label: ".NET (CLR)", rows: [row("present", flag(ext[2]), "")] }] : []),
      ],
    };
  }

  return { SHA256, isPeFilesResult, targetFromRow, queries, parseJsonl, buildReport };
});
