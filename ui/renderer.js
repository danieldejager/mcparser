const caseInput = document.getElementById("case");
const sql = document.getElementById("sql");
const lines = document.getElementById("lines");
const results = document.getElementById("results");
const status = document.getElementById("status");
const summary = document.getElementById("summary");
let lastCsv = "";

function caseDir() {
  return caseInput.value.trim();
}

function updateLines() {
  const count = sql.value.split("\n").length;
  lines.textContent = Array.from({ length: count }, (_, i) => i + 1).join("\n");
  lines.scrollTop = sql.scrollTop;
}

function section(text, title) {
  const start = text.indexOf(`# ${title}`);
  if (start < 0) return [];
  const rest = text.slice(start + title.length + 2).split("\n# ")[0];
  return rest.split("\n").map((line) => line.split("\t")).filter((row) => row[0]);
}

function fact(label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.textContent = value || "-";
  summary.append(dt, dd);
}

function bytes(value) {
  const size = Number(value);
  if (!size) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / 1024 / 1024).toFixed(1)} MB`;
}

async function refresh() {
  const result = await window.mcparser.stats(caseDir());
  summary.replaceChildren();
  if (result.code !== 0) {
    status.textContent = result.err || "stats failed";
    return;
  }
  const range = section(result.out, "time range")[0] || [];
  const channels = section(result.out, "channels").map((row) => row[0]);
  const providers = section(result.out, "providers").map((row) => row[0]);
  const eventIds = section(result.out, "event ids");
  const source = section(result.out, "sources")[0] || [];
  fact("File", source[0] ? source[0].split("/").pop() : "-");
  fact("Size", bytes(source[2]));
  fact("SHA256", source[1]);
  fact("Events", range[2]);
  fact("Unique event IDs", String(eventIds.length));
  fact("First", range[0]);
  fact("Last", range[1]);
  fact("Channels", channels.join(", "));
  fact("Providers", providers.join(", "));
  status.textContent = "Case loaded";
}

function renderCsv(text) {
  const rows = text.trim().split("\n").filter(Boolean).map((line) => line.split(","));
  const table = document.createElement("table");
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    for (const cell of row) {
      const node = document.createElement(index === 0 ? "th" : "td");
      node.textContent = cell;
      tr.append(node);
    }
    table.append(tr);
  });
  results.replaceChildren(table);
  return Math.max(rows.length - 1, 0);
}

async function run() {
  const started = performance.now();
  const result = await window.mcparser.query(caseDir(), sql.value);
  if (result.code !== 0) {
    lastCsv = "";
    results.textContent = result.err || result.out;
    status.textContent = "Query failed";
    return;
  }
  lastCsv = result.out;
  const rows = renderCsv(result.out);
  status.textContent = `rows ${rows} | elapsed ${Math.round(performance.now() - started)} ms | case ${caseDir()}`;
}

async function exportCsv() {
  if (!lastCsv.trim()) {
    status.textContent = "No results to export";
    return;
  }
  const saved = await window.mcparser.saveCsv(lastCsv);
  if (saved.saved) status.textContent = `exported ${saved.path}`;
}

sql.addEventListener("input", updateLines);
sql.addEventListener("scroll", () => {
  lines.scrollTop = sql.scrollTop;
});
document.getElementById("refresh").onclick = refresh;
document.getElementById("run").onclick = run;
document.getElementById("export").onclick = exportCsv;
window.mcparser.onOpened((opened) => {
  caseInput.value = opened.caseDir;
  status.textContent = opened.code === 0 ? opened.out.trim() : opened.err;
  refresh().then(run);
});
updateLines();
refresh().then(run);
