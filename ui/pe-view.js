// PE structure viewer. Layout only; all data comes from `mcparser pe --json`
// and, for the hex view, bounded reads through `opts.readRange`. Nothing here
// runs or loads the file. All text is set with textContent, never as HTML.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PeView = api;
})(typeof self !== "undefined" ? self : this, function () {
  const COLUMNS = ["field", "offset", "size", "value", "meaning"];
  const PAGE_SIZES = [4096, 65536];
  const MAX_RANGE = 1024 * 1024;

  // Depth-first list of { id, label, depth, rows } for the tree.
  function flattenTree(nodes, depth = 0, out = []) {
    for (const node of Array.isArray(nodes) ? nodes : []) {
      out.push({ id: String(node.id || ""), label: String(node.label || ""), depth, rows: Array.isArray(node.rows) ? node.rows : [] });
      if (node.children) flattenTree(node.children, depth + 1, out);
    }
    return out;
  }

  function summaryItems(summary) {
    const s = summary || {};
    const mb = s.malwarebazaar;
    const items = [
      ["SHA256", s.sha256], ["MD5", s.md5], ["SHA1", s.sha1], ["Imphash", s.imphash || "none"],
      ["Architecture", s.architecture], ["Subsystem", s.subsystem], ["Compiled", s.compile_time],
      ["Characteristics", (s.characteristics || []).join(" | ")], ["Signed", s.signed ? "yes" : "no"],
      [".NET", s.dotnet ? "yes" : "no"], ["Size", s.file_size],
    ];
    if (mb) items.push(["MalwareBazaar", mb.result === "hit" ? "HIT " + (mb.signature || mb.file_name || "") : "no hit"]);
    return items.map(([k, v]) => [k, v === undefined || v === null ? "" : String(v)]);
  }

  const MISSING_PE = "This McParser build does not include the PE analyzer. Rebuild with cargo build and restart.";
  // Text for a failed `mcparser pe` run. An older binary without the pe
  // command, or no binary at all, gets one plain instruction instead of a raw
  // error.
  function failureMessage(result) {
    const r = result || {};
    const text = String(r.err || "") + "\n" + String(r.out || "");
    if (/unknown command:\s*pe\b/i.test(text) || /\bENOENT\b/.test(text) || /spawn .*mcparser(\.exe)?\b.*(ENOENT|not found)/i.test(text)) return MISSING_PE;
    return (r.err || r.out || "").trim() || "Analysis failed";
  }

  const TABS = [
    { id: "general", label: "General" },
    { id: "pe", label: "PE Header", nodes: ["nt", "file", "optional", "dirs"] },
    { id: "mz", label: "MZ Header", nodes: ["dos"] },
    { id: "sections", label: "Sections / Overlay" },
    { id: "imports", label: "Imports / Exports / TLS" },
    { id: "resources", label: "Resources" },
    { id: "debug", label: "Debug" },
    { id: "version", label: "Version Info / Signature" },
    { id: "hex", label: "Hex / Strings" },
  ];

  const hex = (n) => (typeof n === "number" ? "0x" + n.toString(16).toUpperCase() : n === undefined || n === null ? "" : String(n));

  // Rows of a hex dump: offset, 16 bytes, ASCII. `base` is the file offset
  // of bytes[0].
  function hexRows(bytes, limit = 4096, base = 0) {
    const out = [];
    for (let o = 0; o < Math.min(bytes.length, limit * 16); o += 16) {
      const chunk = Array.from(bytes.slice(o, o + 16));
      out.push([(base + o).toString(16).padStart(8, "0").toUpperCase(), chunk.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" "), chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")]);
    }
    return out;
  }

  function decodeBase64(text) {
    if (!text) return new Uint8Array(0);
    const bin = typeof atob === "function" ? atob(text) : Buffer.from(text, "base64").toString("binary");
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function sectionFlags(f) {
    f = f || {};
    return (f.read ? "R" : "-") + (f.write ? "W" : "-") + (f.execute ? "X" : "-") + (f.shared ? "S" : "") + (f.code ? " code" : "");
  }

  // "0x1F0", "1f0h", "496" -> number; anything else -> null.
  function parseOffset(text) {
    const t = String(text || "").trim().replace(/_/g, "");
    let n = null;
    if (/^0x[0-9a-f]{1,13}$/i.test(t)) n = parseInt(t.slice(2), 16);
    else if (/^[0-9a-f]{1,13}h$/i.test(t)) n = parseInt(t.slice(0, -1), 16);
    else if (/^[0-9]{1,16}$/.test(t)) n = Number(t);
    return n !== null && Number.isSafeInteger(n) && n >= 0 ? n : null;
  }

  // Page start for an offset, aligned down to the page size.
  function pageStart(offset, pageSize) {
    const size = PAGE_SIZES.includes(pageSize) ? pageSize : PAGE_SIZES[0];
    return Math.floor(Math.max(0, offset) / size) * size;
  }

  const SEVERITIES = ["high", "medium", "low"];
  const severityOf = (s) => (SEVERITIES.includes(String(s).toLowerCase()) ? String(s).toLowerCase() : "low");

  // Entropy band: > 7.2 packed/encrypted-looking, < 1 mostly empty.
  function entropyLevel(e) {
    if (typeof e !== "number" || !isFinite(e)) return "none";
    return e > 7.2 ? "high" : e > 6.5 ? "medium" : "normal";
  }

  // { dll: [functions...] } in first-seen order.
  function importTree(imports) {
    const map = new Map();
    for (const i of Array.isArray(imports) ? imports : []) {
      const k = String(i.dll || "?") + (i.delayed ? " (delay)" : "");
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(i.name ? String(i.name) : "ordinal " + i.ordinal);
    }
    return [...map.entries()];
  }

  function resourceTree(resources) {
    const map = new Map();
    for (const r of Array.isArray(resources) ? resources : []) {
      const k = String(r.type || "?");
      if (!map.has(k)) map.set(k, []);
      map.get(k).push(r);
    }
    return [...map.entries()];
  }

  // Resource tree for the Resources tab: type folders, then names or ids,
  // then languages. Order is first seen in the file.
  function resourceNodes(resources) {
    const types = new Map();
    for (const r of Array.isArray(resources) ? resources : []) {
      const t = String(r.type || "?");
      if (!types.has(t)) types.set(t, new Map());
      const names = types.get(t);
      const n = String(r.name === undefined || r.name === null ? "" : r.name);
      if (!names.has(n)) names.set(n, []);
      names.get(n).push(r);
    }
    return [...types.entries()].map(([type, names]) => ({ type, label: rtLabel(type), names: [...names.entries()].map(([name, langs]) => ({ name, langs })) }));
  }
  // "ICON" -> "RT_ICON"; numeric or custom types are shown as they are.
  const rtLabel = (t) => (/^[A-Z_]+$/.test(String(t)) ? "RT_" + t : String(t));
  const LANGS = { 0: "Neutral", 1024: "Process default", 1025: "Arabic - Saudi Arabia", 1028: "Chinese - Taiwan", 1031: "German - Germany", 1033: "English - United States", 1036: "French - France", 1040: "Italian - Italy", 1041: "Japanese", 1042: "Korean", 1046: "Portuguese - Brazil", 1049: "Russian", 2052: "Chinese - PRC", 2057: "English - United Kingdom", 3082: "Spanish - Spain", 3081: "English - Australia" };
  function langLabel(id) {
    const n = Number(id);
    if (!Number.isInteger(n) || n < 0) return String(id === undefined || id === null ? "" : id);
    return `${n} (0x${n.toString(16).toUpperCase()})` + (LANGS[n] ? " " + LANGS[n] : "");
  }
  // Hex preview of a resource reads at most this many bytes.
  const RES_PREVIEW_MAX = 4096;
  const previewLength = (size) => Math.max(0, Math.min(Number(size) || 0, RES_PREVIEW_MAX));
  const bazaarState = (v) => (v === "hit" ? "hit" : v === "no hit" ? "no hit" : "not checked");

  // Only data URLs the parser built from validated PNG/ICO bytes are shown.
  const safeIconUrl = (u) => typeof u === "string" && /^data:image\/(png|x-icon);base64,[A-Za-z0-9+/=]+$/.test(u) && u.length < 2 * 1024 * 1024;

  function render(container, report, opts = {}) {
    const doc = container.ownerDocument;
    const win = doc.defaultView;
    const el = (tag, cls, text) => { const e = doc.createElement(tag); if (cls) e.className = cls; if (text !== undefined && text !== null) e.textContent = String(text); return e; };
    const s = report.summary || {};
    let goHex = () => {};

    // Offset cell: monospace, and a link into the hex view when it is a number.
    const offsetCell = (n) => {
      if (typeof n !== "number" || n < 0) return el("span", "pe-mono pe-dim", n === undefined || n === null ? "" : String(n));
      const a = el("button", "pe-link pe-mono", hex(n));
      a.type = "button";
      a.title = "Show in hex view";
      a.addEventListener("click", () => goHex(n));
      return a;
    };
    // cols: [{ label, cls, render? }]; rows: arrays of values or nodes.
    const table = (cols, rows, rowClass) => {
      if (!rows.length) return empty("Nothing here", "This file has no entries for this table.");
      const wrap = el("div", "pe-tablewrap");
      const t = el("table", "pe-table");
      const thead = el("thead");
      const tr = el("tr");
      for (const c of cols) tr.append(el("th", c.cls || "", c.label));
      thead.append(tr);
      const tb = el("tbody");
      for (const row of rows) {
        const r = el("tr", rowClass ? rowClass(row) : "");
        row.forEach((v, i) => {
          const td = el("td", (cols[i] && cols[i].cls) || "");
          if (v && typeof v === "object" && v.nodeType) td.append(v);
          else td.textContent = v === undefined || v === null ? "" : String(v);
          r.append(td);
        });
        tb.append(r);
      }
      t.append(thead, tb);
      wrap.append(t);
      return wrap;
    };
    const empty = (title, text) => { const d = el("div", "pe-empty"); d.append(el("div", "pe-empty-icon", "\u2205"), el("div", "pe-empty-title", title), el("div", "pe-empty-text", text)); return d; };
    const card = (title, ...kids) => { const d = el("section", "pe-card"); const h = el("h3", "pe-card-title", title); d.append(h, ...kids.filter(Boolean)); return d; };
    const badge = (level, text) => el("span", "pe-badge pe-badge-" + level, text);
    const copyBtn = (value) => {
      const b = el("button", "pe-copy", "Copy");
      b.type = "button";
      b.setAttribute("aria-label", "Copy value");
      b.addEventListener("click", () => {
        const done = () => { b.textContent = "Copied"; win.setTimeout(() => { b.textContent = "Copy"; }, 1200); };
        try { win.navigator.clipboard.writeText(value).then(done, () => {}); } catch (_) { /* no clipboard */ }
      });
      return b;
    };
    const kv = (pairs) => {
      const dl = el("dl", "pe-kv");
      for (const [k, v] of pairs) { dl.append(el("dt", "", k)); const dd = el("dd"); if (v && v.nodeType) dd.append(v); else dd.textContent = v === undefined || v === null || v === "" ? "\u2014" : String(v); dl.append(dd); }
      return dl;
    };
    const checks = (items) => {
      const g = el("div", "pe-checks");
      for (const [name, on] of items) {
        const c = el("div", "pe-check " + (on ? "pe-on" : "pe-off"));
        c.setAttribute("role", "checkbox");
        c.setAttribute("aria-checked", on ? "true" : "false");
        c.append(el("span", "pe-box", on ? "\u2713" : ""), el("span", "", name));
        g.append(c);
      }
      return g;
    };
    const flat = flattenTree(report.tree);
    const byId = Object.fromEntries(flat.map((n) => [n.id, n]));
    const fieldTable = (node) => table(
      [{ label: "Field" }, { label: "Offset", cls: "pe-mono pe-num" }, { label: "Size", cls: "pe-mono pe-num" }, { label: "Value", cls: "pe-mono" }, { label: "Meaning" }],
      node.rows.map((r) => [r.field, /^0x[0-9a-f]+$/i.test(r.offset || "") ? offsetCell(parseInt(r.offset, 16)) : r.offset, r.size, r.value, r.meaning]));

    function treeView(ids) {
      const body = el("div", "pe-split");
      const tree = el("ul", "pe-tree");
      tree.setAttribute("role", "tree");
      const detail = el("div", "pe-detail");
      ids.map((id) => byId[id]).filter(Boolean).forEach((node, i) => {
        const li = el("li", "pe-node", node.label);
        li.tabIndex = 0;
        li.setAttribute("role", "treeitem");
        li.style.paddingLeft = 10 + node.depth * 16 + "px";
        const show = () => {
          for (const x of tree.querySelectorAll(".pe-selected")) x.classList.remove("pe-selected");
          li.classList.add("pe-selected");
          detail.replaceChildren(card(node.label, fieldTable(node)));
        };
        li.addEventListener("click", show);
        li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); show(); } });
        tree.append(li);
        if (i === 0) show();
      });
      body.append(tree, detail);
      return body;
    }

    // Collapsible tree with <details>; leaves are nodes built by `leaf`.
    const collapsible = (groups, leaf, open = 6) => {
      const d = el("div", "pe-ctree");
      groups.forEach(([name, items], i) => {
        const det = el("details");
        if (i < open) det.open = true;
        const sum = el("summary");
        sum.append(el("span", "pe-ctree-name", name), el("span", "pe-count", String(items.length)));
        det.append(sum);
        const ul = el("ul");
        for (const it of items) { const li = el("li"); li.append(leaf(it)); ul.append(li); }
        det.append(ul);
        d.append(det);
      });
      return groups.length ? d : empty("Nothing here", "No entries in this file.");
    };

    const builders = {
      general: () => {
        const d = el("div", "pe-stack");
        const ind = report.indicators || [];
        d.append(card(`Hints (${ind.length}), not verdicts`, ind.length ? table([{ label: "Severity" }, { label: "Rule", cls: "pe-mono" }, { label: "Reason" }],
          ind.map((i) => [badge(severityOf(i.severity), severityOf(i.severity)), i.rule, i.reason]), (r) => "pe-row-" + r[0].textContent) : empty("No hints", "None of the hint rules matched this file.")));
        const facts = summaryItems(s).filter(([k]) => !["SHA256", "MD5", "SHA1", "Imphash", "MalwareBazaar"].includes(k));
        if (report.entry_section !== undefined) facts.push(["Entry point section", report.entry_section || "outside any section"]);
        const grid = el("div", "pe-grid2");
        grid.append(card("File", kv(facts)));
        const mit = (report.mitigations || []).map((m) => [m.name, !!m.enabled]);
        grid.append(card("Mitigations", mit.length ? checks(mit) : empty("No data", "Not a PE image.")));
        d.append(grid);
        d.append(card("Characteristics", checks(["EXECUTABLE_IMAGE", "DLL", "LARGE_ADDRESS_AWARE", "32BIT_MACHINE", "RELOCS_STRIPPED", "DEBUG_STRIPPED", "SYSTEM"].map((n) => [n, (s.characteristics || []).includes(n)]))));
        if ((s.warnings || []).length) d.append(card("Parser warnings", ...(s.warnings || []).map((w) => el("div", "pe-warn", w))));
        return d;
      },
      pe: () => (byId.nt ? treeView(["nt", "file", "optional", "dirs"]) : treeView(["saved"])),
      mz: () => (byId.dos ? treeView(["dos"]) : empty("Not saved in the case", "MZ header fields are read from the file. Use File > Analyze PE File to see them.")),
      sections: () => {
        const d = el("div", "pe-stack");
        const bar = (e) => { const lvl = entropyLevel(e); const w = el("div", "pe-ebar pe-e-" + lvl); const f = el("div", "pe-efill"); f.style.width = Math.max(0, Math.min(100, (e || 0) / 8 * 100)) + "%"; w.append(f, el("span", "pe-mono", typeof e === "number" ? e.toFixed(3) : "")); w.title = lvl === "high" ? "High entropy: packed or encrypted data is likely" : ""; return w; };
        const rows = (report.sections || []).map((x) => {
          const flags = sectionFlags(x.flags);
          const sus = flags.startsWith("RWX") || entropyLevel(x.entropy) === "high";
          return [x.name, hex(x.virtual_address), hex(x.virtual_size), offsetCell(x.raw_offset), hex(x.raw_size), flags, bar(x.entropy), x.ratio + "%", x.md5, sus];
        });
        d.append(card("Sections", table([{ label: "Name", cls: "pe-mono" }, { label: "Virt addr", cls: "pe-mono pe-num" }, { label: "Virt size", cls: "pe-mono pe-num" }, { label: "Raw offset", cls: "pe-mono pe-num" }, { label: "Raw size", cls: "pe-mono pe-num" }, { label: "Flags", cls: "pe-mono" }, { label: "Entropy" }, { label: "% of file", cls: "pe-num" }, { label: "MD5", cls: "pe-mono pe-hash" }],
          rows.map((r) => r.slice(0, 9)), (r) => (rows.find((x) => x[0] === r[0] && x[9]) ? "pe-row-suspicious" : ""))));
        d.append(card("Overlay", s.overlay_size ? kv([["Size", s.overlay_size + " bytes"], ["Where", "after the last section"]]) : empty("No overlay", "Nothing follows the last section.")));
        return d;
      },
      imports: () => {
        const d = el("div", "pe-stack");
        const imp = importTree(report.imports);
        d.append(card(`Imports (${(report.imports || []).length} from ${imp.length} DLLs)`, collapsible(imp, (f) => el("span", "pe-mono", f))));
        d.append(card("Exports", table([{ label: "Ordinal", cls: "pe-num" }, { label: "Name", cls: "pe-mono" }, { label: "RVA", cls: "pe-mono pe-num" }, { label: "Forwarder", cls: "pe-mono" }], (report.exports || []).map((e) => [e.ordinal, e.name, hex(e.rva), e.forwarder]))));
        const tls = report.tls || {};
        d.append(card("TLS", tls.present ? kv([["Directory", "present"], ["Callbacks", tls.callbacks]]) : empty("No TLS directory", "No thread-local storage callbacks run before the entry point.")));
        return d;
      },
      resources: () => resourcesView(),
      debug: () => {
        const d = el("div", "pe-stack");
        d.append(card("Debug directory", table([{ label: "Type", cls: "pe-num" }, { label: "Timestamp", cls: "pe-mono" }, { label: "Size", cls: "pe-num" }, { label: "Raw offset", cls: "pe-mono pe-num" }, { label: "PDB path", cls: "pe-mono" }], (report.debug || []).map((x) => [x.type, x.timestamp, x.size, x.raw_offset ? offsetCell(x.raw_offset) : "", x.pdb_path]))));
        d.append(card("Rich header (compiler and linker stamps)", table([{ label: "Product id", cls: "pe-num" }, { label: "Build", cls: "pe-num" }, { label: "Count", cls: "pe-num" }], (report.rich || []).map((r) => [r.product_id, r.build, r.count]))));
        return d;
      },
      version: () => {
        const d = el("div", "pe-stack");
        const v = report.version_info;
        if (v) {
          const grid = el("div", "pe-grid2");
          grid.append(card("Fixed file info", (v.fixed || []).length ? kv(v.fixed.map((f) => [f.key, f.value])) : empty("Missing", "VS_FIXEDFILEINFO is absent or has a bad signature.")));
          grid.append(card("String file info", table([{ label: "Key" }, { label: "Value" }, { label: "Table", cls: "pe-mono" }], (v.strings || []).map((t) => [t.key, t.value, t.table]))));
          d.append(grid);
          if ((v.translations || []).length) d.append(card("Var file info", kv([["Translation", v.translations.join(", ")]])));
        } else d.append(card("Version info", empty("No version resource", "This file has no VS_VERSIONINFO resource.")));
        const m = report.manifest;
        if (m) {
          const lvl = m.execution_level || "not set";
          const pre = el("pre", "pe-code", m.text);
          d.append(card("Manifest", kv([["requestedExecutionLevel", badge(m.execution_level === "requireAdministrator" ? "medium" : "low", lvl)], ["uiAccess", m.ui_access || "not set"], ["Size", m.size + " bytes" + (m.truncated ? " (truncated for display)" : "")]]), pre));
        }
        const sigs = report.signatures || [];
        if (!sigs.length) d.append(card("Digital signature", empty("Not signed", "No Authenticode certificate table in this file.")));
        sigs.forEach((sg, i) => {
          const c = card(`Digital signature ${sigs.length > 1 ? i + 1 : ""}`.trim());
          c.append(el("div", "pe-notice", "Signature present, not verified. Fields are parsed from the certificate table; trust, chain building and the file hash are not checked."));
          if (sg.error) c.append(el("div", "pe-warn", sg.error));
          c.append(kv([["Digest", sg.digest_algorithm], ["Signature algorithm", sg.signature_algorithm], ["SignedData version", sg.version], ["Offset", offsetCell(sg.offset)], ["Length", sg.length + " bytes"]]));
          const chain = el("div", "pe-certs");
          for (const ct of sg.certificates || []) {
            const cc = el("div", "pe-cert" + (ct.is_signer ? " pe-cert-signer" : ""));
            const top = el("div", "pe-cert-top");
            top.append(el("span", "pe-cert-cn", ct.subject.cn || ct.subject.full || "(no name)"));
            if (ct.is_signer) top.append(badge("info", "signer"));
            if (ct.self_signed) top.append(badge("low", "self-signed"));
            cc.append(top, kv([["Subject", [ct.subject.o, ct.subject.ou, ct.subject.c].filter(Boolean).join(", ")], ["Issuer", ct.issuer.cn || ct.issuer.full], ["Issuer org", [ct.issuer.o, ct.issuer.c].filter(Boolean).join(", ")], ["Serial (hex)", el("span", "pe-mono", ct.serial_hex)], ["Serial (dec)", el("span", "pe-mono", ct.serial_dec)], ["Valid", `${ct.not_before} to ${ct.not_after}`], ["Version", "v" + ct.version], ["Algorithm", ct.signature_algorithm]]));
            chain.append(cc);
          }
          c.append(chain);
          d.append(c);
        });
        return d;
      },
      hex: () => {
        const d = el("div", "pe-stack");
        d.append(hexCard());
        d.append(card(`Strings (${(report.strings || []).length})`, table([{ label: "Offset", cls: "pe-mono pe-num" }, { label: "Encoding" }, { label: "Category" }, { label: "Value", cls: "pe-mono" }], (report.strings || []).map((t) => [offsetCell(t.offset), t.encoding, t.category, t.value]))));
        return d;
      },
    };

    // Resources: tree on the left, details, hex preview and parsed text on
    // the right. Bytes come from opts.readRange, capped at RES_PREVIEW_MAX.
    function resourcesView() {
      const nodes = resourceNodes(report.resources);
      const icons = (report.icons || []).filter((i) => safeIconUrl(i.data_url));
      const wrap = el("div", "pe-stack");
      if (!nodes.length) { wrap.append(card("Resources", empty("No resources", "This file has no resource directory entries."))); return wrap; }
      const body = el("div", "pe-split pe-res");
      const tree = el("ul", "pe-rtree");
      tree.setAttribute("role", "tree");
      tree.setAttribute("aria-label", "Resources");
      const detail = el("div", "pe-detail");
      const leaves = [];
      let first = null;
      const folder = (label, count, depth, kids) => {
        const li = el("li");
        li.setAttribute("role", "treeitem");
        li.setAttribute("aria-expanded", "true");
        const row = el("div", "pe-rnode pe-rfolder");
        row.style.paddingLeft = 6 + depth * 14 + "px";
        row.tabIndex = -1;
        row.append(el("span", "pe-twisty", "\u25BE"), el("span", "pe-folder-icon", "\u25A0"), el("span", depth ? "pe-mono" : "pe-mono pe-rtype", label));
        if (count !== null) row.append(el("span", "pe-count", String(count)));
        const ul = el("ul");
        ul.setAttribute("role", "group");
        const toggle = () => { const open = li.getAttribute("aria-expanded") !== "true"; li.setAttribute("aria-expanded", String(open)); ul.hidden = !open; row.firstChild.textContent = open ? "\u25BE" : "\u25B8"; };
        row.addEventListener("click", toggle);
        row.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); } });
        kids.forEach((k) => ul.append(k));
        li.append(row, ul);
        return li;
      };
      for (const t of nodes) {
        const names = t.names.map((n) => {
          const langs = n.langs.map((r) => {
            const li = el("li");
            li.setAttribute("role", "treeitem");
            const row = el("div", "pe-rnode pe-rleaf");
            row.style.paddingLeft = 6 + 2 * 14 + "px";
            row.tabIndex = -1;
            row.append(el("span", "pe-leaf-icon", "\u25A1"), el("span", "pe-mono", String(r.language)));
            const pick = () => {
              for (const x of tree.querySelectorAll(".pe-selected")) x.classList.remove("pe-selected");
              for (const x of tree.querySelectorAll("[aria-selected]")) x.setAttribute("aria-selected", "false");
              row.classList.add("pe-selected");
              li.setAttribute("aria-selected", "true");
              leaves.forEach((l) => { l.tabIndex = l === row ? 0 : -1; });
              detail.replaceChildren(resourceDetail(t, n, r));
            };
            row.addEventListener("click", pick);
            row.addEventListener("keydown", (e) => {
              if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); return; }
              const i = leaves.indexOf(row);
              const to = e.key === "ArrowDown" ? i + 1 : e.key === "ArrowUp" ? i - 1 : e.key === "Home" ? 0 : e.key === "End" ? leaves.length - 1 : null;
              if (to !== null && leaves[to]) { e.preventDefault(); leaves[to].focus(); leaves[to].click(); }
            });
            leaves.push(row);
            if (!first) first = pick;
            li.append(row);
            return li;
          });
          return folder(n.name || "(unnamed)", null, 1, langs);
        });
        tree.append(folder(t.label, t.names.reduce((a, n) => a + n.langs.length, 0), 0, names));
      }
      body.append(tree, detail);
      if (icons.length) {
        const sw = el("div", "pe-theme pe-resview");
        sw.setAttribute("role", "radiogroup");
        sw.setAttribute("aria-label", "Resources view");
        const g = el("div", "pe-icons");
        for (const i of icons) { const f = el("figure", "pe-icon"); const img = el("img"); img.src = i.data_url; img.alt = `icon ${i.icon_id}`; img.width = Math.min(64, i.width); img.height = Math.min(64, i.height); f.append(img, el("figcaption", "", `${i.width}\u00d7${i.height} ${i.bit_count}bpp`)); g.append(f); }
        const gallery = card(`Icons (${icons.length})`, g);
        gallery.hidden = true;
        const opts2 = [["tree", "Tree"], ["icons", "Icons"]].map(([id, label]) => {
          const b = el("button", "pe-theme-opt", label); b.type = "button"; b.setAttribute("role", "radio"); b.dataset.view = id;
          b.addEventListener("click", () => { body.hidden = id !== "tree"; gallery.hidden = id !== "icons"; opts2.forEach((o) => { const on = o === b; o.setAttribute("aria-checked", String(on)); o.tabIndex = on ? 0 : -1; }); });
          sw.append(b); return b;
        });
        opts2[0].setAttribute("aria-checked", "true"); opts2[1].setAttribute("aria-checked", "false"); opts2[1].tabIndex = -1;
        wrap.append(sw, body, gallery);
      } else wrap.append(body);
      if (leaves[0]) leaves[0].tabIndex = 0;
      if (first) first();
      return wrap;
    }

    function resourceDetail(t, n, r) {
      const d = el("div", "pe-stack");
      const mb = bazaarState(r.malwarebazaar);
      const mbNode = badge(mb === "hit" ? "high" : mb === "no hit" ? "ok" : "none", mb === "hit" ? "MalwareBazaar HIT" : mb === "no hit" ? "No hit" : "Not checked (dump not installed)");
      const hashRow = (v) => { if (!v) return "\u2014"; const sp = el("span", "pe-hashline"); sp.append(el("span", "pe-mono pe-hashval", v), copyBtn(v)); return sp; };
      d.append(card("Resource", kv([
        ["Name", el("span", "pe-mono", n.name || "(unnamed)")],
        ["Type", t.label],
        ["Language", langLabel(r.language)],
        ["MD5", hashRow(r.md5)],
        ["SHA256", hashRow(r.sha256)],
        ["Size", `${hex(r.size)} (${Number(r.size) || 0} bytes)`],
        ["Offset", typeof r.offset === "number" ? offsetCell(r.offset) : "not in file"],
        ["MalwareBazaar", mbNode],
      ])));
      const parsed = parsedText(t.type);
      const grid = el("div", parsed ? "pe-resgrid" : "pe-resgrid pe-resgrid-one");
      grid.append(resourceHex(r));
      if (parsed) grid.append(card(parsed[0], el("pre", "pe-code pe-restext", parsed[1])));
      d.append(grid);
      return d;
    }

    // Parsed text beside the hex preview for VERSION and MANIFEST.
    function parsedText(type) {
      if (type === "VERSION" && report.version_info) {
        const v = report.version_info;
        const lines = [];
        if ((v.translations || []).length) lines.push("VarFileInfo", "  Translation: " + v.translations.join(", "), "");
        const tables = new Map();
        for (const x of v.strings || []) { if (!tables.has(x.table)) tables.set(x.table, []); tables.get(x.table).push(x); }
        if (tables.size) lines.push("StringFileInfo");
        for (const [tb, rows] of tables) { lines.push("  " + tb); for (const x of rows) lines.push(`    ${x.key}: ${x.value}`); }
        if ((v.fixed || []).length) { lines.push("", "VS_FIXEDFILEINFO"); for (const f of v.fixed) lines.push(`  ${f.key}: ${f.value}`); }
        return ["Version info (parsed)", lines.join("\n")];
      }
      if (type === "MANIFEST" && report.manifest) return ["Manifest (parsed)", String(report.manifest.text || "") + (report.manifest.truncated ? "\n\n(truncated for display)" : "")];
      return null;
    }

    function resourceHex(r) {
      const c = card("Bytes");
      const len = previewLength(r.size);
      if (typeof opts.readRange !== "function") { c.append(empty("Preview unavailable", "Byte ranges are read on demand from the file on disk; no reader is attached.")); return c; }
      if (typeof r.offset !== "number" || !len) { c.append(empty("No bytes", "The resource data is not inside the file.")); return c; }
      const note = el("div", "pe-dim pe-resnote", `${hex(r.offset)}, first ${len} of ${Number(r.size) || 0} bytes` + (len < (Number(r.size) || 0) ? " (preview capped; open the Hex tab for the rest)" : ""));
      const dump = el("div", "pe-hex pe-reshex");
      c.append(note, dump);
      Promise.resolve(opts.readRange(r.offset, len)).then((res) => {
        if (!res || res.error) { dump.replaceChildren(el("div", "pe-warn", (res && res.error) || "Read failed")); return; }
        const bytes = decodeBase64(res.base64).subarray(0, len);
        for (const [off, hx, asc] of hexRows(bytes, Math.ceil(RES_PREVIEW_MAX / 16), r.offset)) {
          const line = el("div", "pe-hexline");
          line.append(el("span", "pe-gutter", off), el("span", "pe-hexbytes", hx), el("span", "pe-ascii", asc));
          dump.append(line);
        }
      }, () => dump.replaceChildren(el("div", "pe-warn", "Read failed")));
      return c;
    }

    // Paged hex view. Reads one page at a time through opts.readRange.
    const hexState = { offset: 0, size: PAGE_SIZES[0] };
    function hexCard() {
      const c = card("Hex");
      const total = Number(s.file_size) || 0;
      if (typeof opts.readRange !== "function" && typeof opts.locateFile === "function") {
        // Opened from the case: bytes are not stored. The analyst can pick
        // the file; main checks its sha256 before any byte is read.
        const msg = el("div", "pe-warn");
        msg.hidden = true;
        const btn = el("button", "pe-locate", "Locate file...");
        btn.type = "button";
        btn.addEventListener("click", async () => {
          msg.hidden = true;
          const res = await opts.locateFile();
          if (res && res.ok && typeof res.readRange === "function") { opts.readRange = res.readRange; c.replaceWith(hexCard()); return; }
          if (res && res.error) { msg.hidden = false; msg.textContent = res.error; }
        });
        c.append(empty("File not available", "This view was rebuilt from the case. The file bytes are not stored, so the hex view needs the original file. Its SHA256 is checked before any byte is shown."), btn, msg);
        return c;
      }
      if (typeof opts.readRange !== "function") { c.append(empty("Hex view unavailable", "Byte ranges are read on demand from the file on disk; no reader is attached.")); return c; }
      const tools = el("div", "pe-hextools");
      const input = el("input", "pe-mono");
      input.placeholder = "Offset (0x1F0 or 496)";
      input.setAttribute("aria-label", "Jump to offset");
      const go = el("button", "", "Go"); go.type = "button";
      const prev = el("button", "", "\u2039 Prev"); prev.type = "button";
      const next = el("button", "", "Next \u203a"); next.type = "button";
      const sizeSel = el("select");
      for (const p of PAGE_SIZES) { const o = el("option", "", p / 1024 + " KB"); o.value = String(p); sizeSel.append(o); }
      sizeSel.value = String(hexState.size);
      const where = el("span", "pe-dim pe-mono");
      const readout = el("div", "pe-readout pe-mono", "Click a byte to see its offset and value.");
      const msg = el("div", "pe-warn");
      msg.hidden = true;
      tools.append(input, go, prev, next, sizeSel, where);
      const dump = el("div", "pe-hex");
      c.append(tools, msg, dump, readout);
      const load = async (target, mark) => {
        msg.hidden = true;
        const start = pageStart(target, hexState.size);
        if (total && start >= total) { msg.hidden = false; msg.textContent = `Offset is past the end of the file (${total} bytes).`; return; }
        const res = await opts.readRange(start, Math.min(hexState.size, MAX_RANGE));
        if (!res || res.error) { msg.hidden = false; msg.textContent = (res && res.error) || "Read failed"; return; }
        hexState.offset = start;
        const bytes = decodeBase64(res.base64);
        where.textContent = `${hex(start)} to ${hex(start + bytes.length)} of ${hex(res.size || total)}`;
        prev.disabled = start === 0;
        next.disabled = start + bytes.length >= (res.size || total);
        dump.replaceChildren();
        for (let o = 0; o < bytes.length; o += 16) {
          const line = el("div", "pe-hexline");
          line.append(el("span", "pe-gutter", (start + o).toString(16).padStart(8, "0").toUpperCase()));
          const hx = el("span", "pe-hexbytes");
          const asc = el("span", "pe-ascii");
          for (let i = o; i < Math.min(o + 16, bytes.length); i++) {
            const b = bytes[i];
            const off = start + i;
            const hb = el("span", "pe-b" + (b === 0 ? " pe-zero" : ""), b.toString(16).padStart(2, "0").toUpperCase());
            const ab = el("span", "pe-a", b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".");
            const pick = () => {
              for (const x of dump.querySelectorAll(".pe-sel")) x.classList.remove("pe-sel");
              hb.classList.add("pe-sel"); ab.classList.add("pe-sel");
              readout.textContent = `Offset ${hex(off)} (${off})  byte ${hex(b)} (${b})` + (i + 1 < bytes.length ? `  u16le ${hex(b | (bytes[i + 1] << 8))}` : "") + (i + 3 < bytes.length ? `  u32le ${hex((b | (bytes[i + 1] << 8) | (bytes[i + 2] << 16)) + bytes[i + 3] * 0x1000000)}` : "");
            };
            hb.addEventListener("click", pick); ab.addEventListener("click", pick);
            hx.append(hb); asc.append(ab);
            if (off === mark) pick();
          }
          line.append(hx, asc);
          dump.append(line);
        }
        if (mark !== undefined) { const sel = dump.querySelector(".pe-sel"); if (sel && sel.scrollIntoView) sel.scrollIntoView({ block: "center" }); }
      };
      const jump = () => { const n = parseOffset(input.value); if (n === null) { msg.hidden = false; msg.textContent = "Enter a hex (0x1F0) or decimal offset."; return; } load(n, n); };
      go.addEventListener("click", jump);
      input.addEventListener("keydown", (e) => { if (e.key === "Enter") jump(); });
      prev.addEventListener("click", () => load(Math.max(0, hexState.offset - hexState.size)));
      next.addEventListener("click", () => load(hexState.offset + hexState.size));
      sizeSel.addEventListener("change", () => { hexState.size = Number(sizeSel.value); load(hexState.offset); });
      hexCard.load = load;
      load(hexState.pending !== undefined ? hexState.pending : hexState.offset, hexState.pending);
      hexState.pending = undefined;
      return c;
    }

    // Header: name, size, type, hashes with copy, MalwareBazaar badge.
    container.replaceChildren();
    container.classList.add("pe-root");
    const header = el("header", "pe-header");
    const title = el("div", "pe-title");
    const name = String(report.path || "").split(/[\\/]/).pop();
    title.append(el("div", "pe-filename", name || "(unnamed)"));
    const meta = el("div", "pe-meta");
    meta.append(el("span", "pe-chip", s.is_pe ? (s.dll ? "DLL" : s.dotnet ? ".NET EXE" : "EXE") : "not PE"), el("span", "pe-chip", s.architecture || "?"), el("span", "pe-chip", s.subsystem || "?"), el("span", "pe-chip", (Number(s.file_size) || 0).toLocaleString("en-AU") + " bytes"), el("span", "pe-chip", s.signed ? "signed (not verified)" : "unsigned"));
    title.append(meta, el("div", "pe-path pe-dim", report.path || ""));
    const mb = s.malwarebazaar;
    const mbBadge = !mb ? badge("none", "MalwareBazaar: not checked") : mb.result === "hit" ? badge("high", "MalwareBazaar HIT " + (mb.signature || mb.file_name || "")) : badge("ok", "MalwareBazaar: no hit");
    mbBadge.classList.add("pe-mb");
    const top = el("div", "pe-header-top");
    top.append(title, mbBadge);
    const hashes = el("div", "pe-hashes");
    for (const [k, v] of [["SHA256", s.sha256], ["SHA1", s.sha1], ["MD5", s.md5], ["Imphash", s.imphash]]) {
      if (!v) continue;
      const h = el("div", "pe-hashrow");
      h.append(el("span", "pe-hashkey", k), el("span", "pe-mono pe-hashval", v), copyBtn(v));
      hashes.append(h);
    }
    header.append(top, hashes);

    const bar = el("div", "pe-tabs");
    bar.setAttribute("role", "tablist");
    const pane = el("div", "pe-pane");
    pane.setAttribute("role", "tabpanel");
    const buttons = [];
    const open = (idx, focus) => {
      buttons.forEach((b, i) => { const on = i === idx; b.classList.toggle("pe-tab-on", on); b.setAttribute("aria-selected", on ? "true" : "false"); b.tabIndex = on ? 0 : -1; });
      if (focus) buttons[idx].focus();
      pane.replaceChildren(builders[TABS[idx].id]());
      pane.scrollTop = 0;
    };
    TABS.forEach((tab, i) => {
      const b = el("button", "pe-tab", tab.label);
      b.type = "button";
      b.setAttribute("role", "tab");
      b.dataset.tab = tab.id;
      b.addEventListener("click", () => open(i));
      b.addEventListener("keydown", (e) => {
        const n = TABS.length;
        const to = e.key === "ArrowRight" ? (i + 1) % n : e.key === "ArrowLeft" ? (i + n - 1) % n : e.key === "Home" ? 0 : e.key === "End" ? n - 1 : -1;
        if (to >= 0) { e.preventDefault(); open(to, true); }
      });
      buttons.push(b);
      bar.append(b);
    });
    const hexIdx = TABS.findIndex((t) => t.id === "hex");
    goHex = (offset) => { hexState.pending = offset; open(hexIdx); };
    container.append(header, bar, pane);
    open(Math.max(0, TABS.findIndex((t) => t.id === opts.tab)));
    return { open: (id) => open(Math.max(0, TABS.findIndex((t) => t.id === id))), goHex: (o) => goHex(o) };
  }

  return { COLUMNS, TABS, PAGE_SIZES, MAX_RANGE, flattenTree, summaryItems, hexRows, decodeBase64, sectionFlags, parseOffset, pageStart, severityOf, entropyLevel, importTree, resourceTree, resourceNodes, rtLabel, langLabel, previewLength, bazaarState, RES_PREVIEW_MAX, safeIconUrl, MISSING_PE, failureMessage, render };
});
