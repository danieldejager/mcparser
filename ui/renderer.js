const caseInput = document.getElementById("case");
const sql = document.getElementById("sql");
const results = document.getElementById("results");
const status = document.getElementById("status");

function caseDir() {
  return caseInput.value.trim();
}

function addFilter(clause) {
  sql.value += sql.value.toLowerCase().includes("where") ? ` AND ${clause}` : `\nWHERE ${clause}`;
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
  for (const row of rows) {
    const tr = document.createElement("tr");
    for (const cell of row) {
      const td = document.createElement("td");
      td.textContent = cell;
      tr.append(td);
    }
    table.append(tr);
  }
  results.replaceChildren(table);
}

async function run() {
  const started = performance.now();
  const result = await window.mcparser.query(caseDir(), sql.value);
  if (result.code !== 0) {
    results.textContent = result.err || result.out;
    status.textContent = "Query failed";
    return;
  }
  renderCsv(result.out);
  const rows = result.out.trim() ? result.out.trim().split("\n").length : 0;
  status.textContent = `rows ${rows} | elapsed ${Math.round(performance.now() - started)} ms | case ${caseDir()}`;
}

document.getElementById("refresh").onclick = refresh;
document.getElementById("run").onclick = run;
refresh().then(run);
