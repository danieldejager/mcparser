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

  function render(container, report) {
    const doc = container.ownerDocument;
    const el = (tag, cls, text) => { const e = doc.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; };
    container.replaceChildren();
    const head = el("div", "pe-summary");
    head.append(el("div", "pe-path", report.path || ""));
    for (const [k, v] of summaryItems(report.summary)) {
      const item = el("div", "pe-fact" + (k === "MalwareBazaar" && v.startsWith("HIT") ? " pe-hit" : ""));
      item.append(el("span", "pe-key", k), el("span", "pe-val", v));
      head.append(item);
    }
    for (const w of (report.summary && report.summary.warnings) || []) head.append(el("div", "pe-warn", w));
    const body = el("div", "pe-body");
    const tree = el("ul", "pe-tree");
    const detail = el("div", "pe-detail");
    const show = (node, li) => {
      for (const x of tree.querySelectorAll(".pe-selected")) x.classList.remove("pe-selected");
      li.classList.add("pe-selected");
      const table = el("table", "pe-table");
      const tr = el("tr");
      for (const c of COLUMNS) tr.append(el("th", "", c[0].toUpperCase() + c.slice(1)));
      table.append(tr);
      for (const row of node.rows) {
        const r = el("tr");
        for (const c of COLUMNS) r.append(el("td", "pe-" + c, row[c] === undefined ? "" : String(row[c])));
        table.append(r);
      }
      detail.replaceChildren(el("h2", "", node.label), table);
    };
    const flat = flattenTree(report.tree);
    flat.forEach((node, i) => {
      const li = el("li", "pe-node", node.label);
      li.style.paddingLeft = 8 + node.depth * 14 + "px";
      li.addEventListener("click", () => show(node, li));
      tree.append(li);
      if (i === 0) show(node, li);
    });
    body.append(tree, detail);
    container.append(head, body);
  }

  return { COLUMNS, flattenTree, summaryItems, render };
});
