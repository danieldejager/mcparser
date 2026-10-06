const caseInput = document.getElementById("case");
const sql = document.getElementById("sql");
const lines = document.getElementById("lines");
const results = document.getElementById("results");
const status = document.getElementById("status");
const summary = document.getElementById("summary");
const saved = document.getElementById("saved");
const grok = document.getElementById("grok");
const transcript = document.getElementById("transcript");
const ask = document.getElementById("ask");
const sheet = document.getElementById("sheet");
const keyInput = document.getElementById("key");
const keyHint = document.getElementById("key-hint");
let lastCsv = "";
let confirmed = false;
let rowNotes = new Map();

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
  await loadQueries();
}

function renderCsv(text) {
  const rows = text.trim().split("\n").filter(Boolean).map((line) => line.split(","));
  const table = document.createElement("table");
  const headers = rows[0] || [];
  const recordIndex = headers.indexOf("record_id");
  rows.forEach((row, index) => {
    const tr = document.createElement("tr");
    for (const cell of row) {
      const node = document.createElement(index === 0 ? "th" : "td");
      node.textContent = cell;
      tr.append(node);
    }
    if (recordIndex >= 0) {
      const node = document.createElement(index === 0 ? "th" : "td");
      node.textContent = index === 0 ? "note" : rowNotes.get(row[recordIndex]) || "";
      tr.append(node);
      if (index > 0) {
        tr.style.cursor = "pointer";
        tr.onclick = () => showNoteSheet(row[recordIndex], rowNotes.get(row[recordIndex]) || "");
      }
    }
    table.append(tr);
  });
  results.replaceChildren(table);
  return Math.max(rows.length - 1, 0);
}

async function loadNotes() {
  rowNotes = new Map();
  const result = await window.mcparser.notes(caseDir());
  if (!result || result.code !== 0) return;
  for (const line of result.out.split("\n").filter(Boolean)) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    rowNotes.set(line.slice(0, tab), line.slice(tab + 1));
  }
}

function showNoteSheet(recordId, body) {
  document.getElementById("note-record").value = recordId || "";
  document.getElementById("note-body").value = body || "";
  document.getElementById("note-sheet").hidden = false;
  document.getElementById("note-body").focus();
}

async function saveNote(event) {
  event.preventDefault();
  const recordId = document.getElementById("note-record").value.trim();
  const body = document.getElementById("note-body").value.trim();
  document.getElementById("note-sheet").hidden = true;
  if (!recordId || !body) return;
  const result = await window.mcparser.saveNote(caseDir(), recordId, body);
  if (result.code !== 0) {
    status.textContent = result.err || "note failed";
    return;
  }
  status.textContent = `noted ${recordId}`;
  await loadNotes();
  if (lastCsv) renderCsv(lastCsv);
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


async function loadQueries() {
  saved.replaceChildren();
  const result = await window.mcparser.queries(caseDir());
  if (!result || result.code !== 0) return;
  for (const line of result.out.split("\n").filter(Boolean)) {
    const tab = line.indexOf("\t");
    if (tab < 0) continue;
    const name = line.slice(0, tab);
    const sqlText = line.slice(tab + 1).replaceAll("\\n", "\n");
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.textContent = name;
    button.onclick = () => {
      sql.value = sqlText;
      updateLines();
    };
    li.append(button);
    saved.append(li);
  }
}

function showQuerySheet() {
  document.getElementById("query-name").value = "";
  document.getElementById("query-sheet").hidden = false;
  document.getElementById("query-name").focus();
}

async function saveQuery(event) {
  event.preventDefault();
  const name = document.getElementById("query-name").value.trim();
  document.getElementById("query-sheet").hidden = true;
  if (!name) return;
  const result = await window.mcparser.saveQuery(caseDir(), name, sql.value);
  if (result.code !== 0) {
    status.textContent = result.err || "save failed";
    return;
  }
  status.textContent = `saved ${name}`;
  await loadQueries();
}

function note(text) {
  const p = document.createElement("p");
  p.textContent = text;
  transcript.append(p);
  transcript.scrollTop = transcript.scrollHeight;
}

function showSheet(grokState) {
  keyHint.textContent = grokState.connected
    ? `A key is set, ending ${grokState.last4}. Save replaces it.`
    : "The key is encrypted with the macOS keychain.";
  keyInput.value = "";
  sheet.hidden = false;
  keyInput.focus();
}

function hideSheet() {
  keyInput.value = "";
  sheet.hidden = true;
}

sql.addEventListener("input", updateLines);
sql.addEventListener("scroll", () => {
  lines.scrollTop = sql.scrollTop;
});
document.getElementById("refresh").onclick = refresh;
document.getElementById("run").onclick = run;
document.getElementById("save-query").onclick = showQuerySheet;
document.getElementById("query-cancel").onclick = () => { document.getElementById("query-sheet").hidden = true; };
document.getElementById("query-form").onsubmit = saveQuery;
document.getElementById("export").onclick = exportCsv;
document.getElementById("note").onclick = () => showNoteSheet("", "");
document.getElementById("note-cancel").onclick = () => { document.getElementById("note-sheet").hidden = true; };
document.getElementById("note-form").onsubmit = saveNote;
document.getElementById("key-cancel").onclick = hideSheet;
document.getElementById("key-form").onsubmit = async (event) => {
  event.preventDefault();
  const saved = await window.mcparser.grokSave(keyInput.value);
  hideSheet();
  if (saved.error) {
    note(saved.error);
    return;
  }
  if (saved.connected) {
    grok.hidden = false;
    note("Grok connected. Ask about this case.");
  }
};
document.getElementById("send").onclick = async () => {
  const question = ask.value.trim();
  if (!question) return;
  if (!confirmed) {
    const ok = window.confirm("Row text from this case will leave the machine. The case file stays here.");
    if (!ok) return;
    confirmed = true;
  }
  note(question);
  ask.value = "";
  const result = await window.mcparser.grokAsk(caseDir(), question);
  if (result.error) {
    note(result.error);
    return;
  }
  note(result.sql);
  const runSql = document.createElement("button");
  runSql.textContent = "Run";
  runSql.onclick = () => {
    sql.value = result.sql;
    updateLines();
    run();
  };
  transcript.append(runSql);
  note(result.answer);
};
window.mcparser.onOpened((opened) => {
  caseInput.value = opened.caseDir;
  status.textContent = opened.code === 0 ? opened.out.trim() : opened.err;
  refresh().then(run);
});
window.mcparser.onGrokConnect(() => {
  window.mcparser.grokStatus().then(showSheet);
});
window.mcparser.onGrokChat((shown) => {
  grok.hidden = !shown;
});
window.mcparser.onGrokStatus((grokState) => {
  if (!grokState.connected) {
    grok.hidden = true;
    confirmed = false;
    note("Key forgotten.");
  }
});
updateLines();
loadNotes().then(() => refresh().then(run));
