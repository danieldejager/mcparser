const caseInput = document.getElementById("case");
const sql = document.getElementById("sql");
const results = document.getElementById("results");
const status = document.getElementById("status");

function caseDir() {
  return caseInput.value.trim();
}

function addFilter(clause) {
  const where = sql.value.toLowerCase().includes("where") ? ` AND ${clause}` : `\nWHERE ${clause}`;
  const limit = sql.value.search(/\n(ORDER BY|LIMIT)\b/i);
  if (limit >= 0) {
    sql.value = sql.value.slice(0, limit) + where + sql.value.slice(limit);
  } else {
    sql.value += where;
  }
}

function buttons(target, rows, clause) {
  target.replaceChildren();
  for (const row of rows) {
    const button = document.createElement("button");
    button.textContent = row;
    button.onclick = () => addFilter(clause(row));
    target.append(button);
  }
}

function section(text, title) {
  const start = text.indexOf(`# ${title}`);
  if (start < 0) return [];
  const rest = text.slice(start + title.length + 2).split("\n# ")[0];
  return rest.split("\n").map((line) => line.split("\t")[0]).filter(Boolean);
}

async function refresh() {
  const result = await window.mcparser.stats(caseDir());
  if (result.code !== 0) {
    status.textContent = result.err || "stats failed";
    return;
  }
  buttons(document.getElementById("channels"), section(result.out, "channels"), (value) => `channel = '${value}'`);
  buttons(document.getElementById("providers"), section(result.out, "providers"), (value) => `provider = '${value}'`);
  buttons(document.getElementById("events"), section(result.out, "event ids"), (value) => `event_id = ${value}`);
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
    results.textContent = result.err || result.out;
    status.textContent = "Query failed";
    return;
  }
  const rows = renderCsv(result.out);
  status.textContent = `rows ${rows} | elapsed ${Math.round(performance.now() - started)} ms | case ${caseDir()}`;
}

document.getElementById("refresh").onclick = refresh;
document.getElementById("run").onclick = run;
window.mcparser.onOpened((opened) => {
  caseInput.value = opened.caseDir;
  status.textContent = opened.code === 0 ? opened.out.trim() : opened.err;
  refresh().then(run);
});
refresh().then(run);
