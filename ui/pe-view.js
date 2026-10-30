// PE structure viewer: left tree, right detail table (field, offset, size,
// value, meaning), summary header on top. Layout only; all data comes from
// `mcparser pe --json`. Kept in one file so the look can change without
// touching the rest of the renderer.
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.PeView = api;
})(typeof self !== "undefined" ? self : this, function () {
  const COLUMNS = ["field", "offset", "size", "value", "meaning"];

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

  // Tabs in display order. `unfinished` tabs say so on screen.
  const TABS = [
    { id: "general", label: "General" },
    { id: "pe", label: "PE Header", nodes: ["nt", "file", "optional", "dirs"] },
    { id: "mz", label: "MZ Header", nodes: ["dos"] },
    { id: "sections", label: "Sections / Overlay" },
    { id: "imports", label: "Imports / Exports / TLS" },
    { id: "resources", label: "Resources" },
    { id: "debug", label: "Debug" },
    { id: "version", label: "Version Info / Signature", unfinished: "Version info and certificate details are not parsed yet. Only signature presence and size are shown." },
    { id: "hex", label: "Hex / Strings" },
  ];

  const hex = (n) => (typeof n === "number" ? "0x" + n.toString(16).toUpperCase() : n === undefined || n === null ? "" : String(n));

  // Rows of a classic hex dump: offset, 16 bytes, ASCII.
  function hexRows(bytes, limit = 4096) {
    const out = [];
    for (let o = 0; o < Math.min(bytes.length, limit * 16); o += 16) {
      const chunk = Array.from(bytes.slice(o, o + 16));
      out.push([o.toString(16).padStart(8, "0").toUpperCase(), chunk.map((b) => b.toString(16).padStart(2, "0").toUpperCase()).join(" "), chunk.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".")).join("")]);
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

  function render(container, report) {
    const doc = container.ownerDocument;
    const el = (tag, cls, text) => { const e = doc.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
    const table = (cols, rows, rowClass) => {
      const t = el("table", "pe-table");
      const tr = el("tr");
      for (const c of cols) tr.append(el("th", "", c));
      t.append(tr);
      for (const row of rows) {
        const r = el("tr", rowClass ? rowClass(row) : "");
        for (const v of row) r.append(el("td", "", v === undefined || v === null ? "" : String(v)));
        t.append(r);
      }
      return t;
    };
    const section = (title, ...kids) => { const d = el("div", "pe-block"); d.append(el("h2", "", title), ...kids); return d; };
    const flat = flattenTree(report.tree);
    const byId = Object.fromEntries(flat.map((n) => [n.id, n]));
    const fieldTable = (node) => table(COLUMNS.map((c) => c[0].toUpperCase() + c.slice(1)), node.rows.map((r) => COLUMNS.map((c) => r[c])));
    const s = report.summary || {};

    function treeView(ids) {
      const body = el("div", "pe-body");
      const tree = el("ul", "pe-tree");
      const detail = el("div", "pe-detail");
      const nodes = ids.map((id) => byId[id]).filter(Boolean);
      nodes.forEach((node, i) => {
        const li = el("li", "pe-node", node.label);
        li.style.paddingLeft = 8 + node.depth * 14 + "px";
        const show = () => {
          for (const x of tree.querySelectorAll(".pe-selected")) x.classList.remove("pe-selected");
          li.classList.add("pe-selected");
          detail.replaceChildren(el("h2", "", node.label), fieldTable(node));
        };
        li.addEventListener("click", show);
        tree.append(li);
        if (i === 0) show();
      });
      body.append(tree, detail);
      return body;
    }

    const builders = {
      general: () => {
        const d = el("div");
        const facts = el("div", "pe-summary");
        for (const [k, v] of summaryItems(s)) {
          const item = el("div", "pe-fact" + (k === "MalwareBazaar" && v.startsWith("HIT") ? " pe-hit" : ""));
          item.append(el("span", "pe-key", k), el("span", "pe-val", v));
          facts.append(item);
        }
        if (report.entry_section !== undefined) { const i = el("div", "pe-fact"); i.append(el("span", "pe-key", "Entry point section"), el("span", "pe-val", report.entry_section || "outside any section")); facts.append(i); }
        d.append(facts);
        d.append(section("Mitigations", table(["Mitigation", "Enabled"], (report.mitigations || []).map((m) => [m.name, m.enabled ? "yes" : "no"]))));
        d.append(section("Hints (not verdicts)", table(["Severity", "Rule", "Reason"], (report.indicators || []).map((i) => [i.severity, i.rule, i.reason]), (r) => "pe-sev-" + r[0])));
        for (const w of s.warnings || []) d.append(el("div", "pe-warn", w));
        return d;
      },
      pe: () => treeView(["nt", "file", "optional", "dirs"]),
      mz: () => treeView(["dos"]),
      sections: () => {
        const d = el("div");
        d.append(section("Sections", table(["Name", "VirtAddr", "VirtSize", "RawOffset", "RawSize", "Flags", "Entropy", "% of file", "MD5"],
          (report.sections || []).map((x) => [x.name, hex(x.virtual_address), hex(x.virtual_size), hex(x.raw_offset), hex(x.raw_size), sectionFlags(x.flags), typeof x.entropy === "number" ? x.entropy.toFixed(3) : "", x.ratio, x.md5]),
          (r) => (r[5].startsWith("RWX") ? "pe-sev-high" : ""))));
        d.append(section("Overlay", el("p", "", s.overlay_size ? `Overlay present: ${s.overlay_size} bytes after the last section.` : "No overlay.")));
        return d;
      },
      imports: () => {
        const d = el("div");
        d.append(section("Imports", table(["DLL", "Function", "Ordinal", "Delay loaded"], (report.imports || []).map((i) => [i.dll, i.name, i.ordinal, i.delayed ? "yes" : ""]))));
        d.append(section("Exports", table(["Ordinal", "Name", "RVA", "Forwarder"], (report.exports || []).map((e) => [e.ordinal, e.name, hex(e.rva), e.forwarder]))));
        const tls = report.tls || {};
        d.append(section("TLS", el("p", "", tls.present ? `TLS directory present, ${tls.callbacks} callback(s).` : "No TLS directory.")));
        return d;
      },
      resources: () => section("Resources", table(["Type", "Name", "Language", "RVA", "Size", "SHA256"], (report.resources || []).map((r) => [r.type, r.name, r.language, hex(r.rva), r.size, r.sha256]))),
      debug: () => {
        const d = el("div");
        d.append(section("Debug directory", table(["Type", "Timestamp", "Size", "PDB path"], (report.debug || []).map((x) => [x.type, x.timestamp, x.size, x.pdb_path]))));
        d.append(section("Rich header (compiler and linker stamps)", table(["Product id", "Build", "Count"], (report.rich || []).map((r) => [r.product_id, r.build, r.count]))));
        return d;
      },
      version: () => {
        const d = el("div");
        if (byId.cert) d.append(section("Signature", fieldTable(byId.cert)));
        if (byId.clr) d.append(section(".NET", fieldTable(byId.clr)));
        return d;
      },
      hex: () => {
        const d = el("div");
        const bytes = decodeBase64(report.hex_base64);
        d.append(section(`Hex (first ${bytes.length} bytes)`, table(["Offset", "Bytes", "ASCII"], hexRows(bytes))));
        d.append(section("Strings", table(["Offset", "Encoding", "Category", "Value"], (report.strings || []).map((t) => [hex(t.offset), t.encoding, t.category, t.value]))));
        return d;
      },
    };

    container.replaceChildren();
    const head = el("div", "pe-path", report.path || "");
    const bar = el("div", "pe-tabs");
    const pane = el("div", "pe-pane");
    const open = (tab, button) => {
      for (const b of bar.children) b.classList.remove("pe-tab-on");
      button.classList.add("pe-tab-on");
      pane.replaceChildren();
      if (tab.unfinished) pane.append(el("div", "pe-warn", "Unfinished: " + tab.unfinished));
      pane.append(builders[tab.id]());
    };
    TABS.forEach((tab, i) => {
      const b = el("button", "pe-tab", tab.label);
      b.type = "button";
      b.addEventListener("click", () => open(tab, b));
      bar.append(b);
      if (i === 0) open(tab, b);
    });
    container.append(head, bar, pane);
  }

  return { COLUMNS, TABS, flattenTree, summaryItems, hexRows, decodeBase64, sectionFlags, render };
});
