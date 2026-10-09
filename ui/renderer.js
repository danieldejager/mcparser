
function keyStore() {
  if (window.mcparser.platform === "win32") return "Windows DPAPI";
  if (window.mcparser.platform === "linux") return "the system keyring";
  return "the macOS keychain";
}

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
let runLabel = "query";
let runKind = "run";
let confirmed = false;
let connectProvider = "grok";
let rowNotes = new Map();


function listModels(state) {
  const models = document.getElementById("models");
  const vendor = document.getElementById("vendor");
  if (!models || !vendor) return;
  const current = state || { provider: "grok", grok: false, claude: false, openai: false };
  vendor.value = current.provider || "grok";
  const configured = { grok: current.grok, claude: current.claude, openai: current.openai };
  models.textContent = configured[vendor.value] ? "Configured." : "Configure this integration.";
}


function fillHunts() {
  const tactic = document.getElementById("tactic");
  const technique = document.getElementById("technique");
  const list = document.getElementById("hunts");
  if (!tactic || !window.hunts) return;
  const tactics = [...new Set(window.hunts.map((hunt) => hunt.tactic))];
  if (!tactic.options.length) {
    for (const name of tactics) {
      const option = document.createElement("option");
      option.value = name;
      option.textContent = name;
      tactic.append(option);
    }
  }
  const techniques = [...new Set(window.hunts.filter((hunt) => hunt.tactic === tactic.value).map((hunt) => hunt.technique))];
  const previous = technique.value;
  technique.replaceChildren();
  for (const name of techniques) {
    const option = document.createElement("option");
    option.value = name;
    option.textContent = name;
    technique.append(option);
  }
  if (techniques.includes(previous)) technique.value = previous;
  list.replaceChildren();
  for (const hunt of window.hunts.filter((item) => item.tactic === tactic.value && item.technique === technique.value)) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.textContent = hunt.name;
    button.onclick = () => {
      sql.value = hunt.sql;
      document.getElementById("tactic").onchange = fillHunts;
document.getElementById("technique").onchange = fillHunts;
fillHunts();
const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
updateLines();
    };
    li.append(button);
    list.append(li);
  }
}

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
  await loadHosts();
  status.textContent = "Case loaded";
  await loadQueries();
}

async function loadHosts() {
  hosts.replaceChildren();
  const listed = await window.mcparser.hosts(caseDir());
  const collected = await window.mcparser.collections(caseDir());
  if (listed.code !== 0) return;
  const rows = listed.out.trim().split("\n").filter(Boolean).map((line) => line.split("\t"));
  const sessions = collected.code === 0 ? collected.out.trim().split("\n").filter(Boolean).map((line) => line.split("\t")) : [];
  if (rows.length === 0) {
    const item = document.createElement("li");
    item.textContent = "No hosts";
    hosts.append(item);
    return;
  }
  for (const row of rows) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = row[1] || row[0];
    item.append(title);
    const meta = document.createElement("div");
    meta.textContent = [row[3], row[4]].filter(Boolean).join(" ");
    item.append(meta);
    const id = document.createElement("div");
    id.textContent = row[0];
    item.append(id);
    const mine = sessions.filter((session) => session[1] === row[0]);
    for (const session of mine) {
      const line = document.createElement("div");
      line.textContent = session[3] || session[0];
      item.append(line);
    }
    hosts.append(item);
  }
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
    const parts = line.split("\t");
    if (parts.length < 2) continue;
    rowNotes.set(parts[0], parts[2] || parts[1]);
  }
}

async function showNotes() {
  await loadNotes();
  const result = await window.mcparser.notes(caseDir());
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["record", "note", "query"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  table.append(head);
  if (result && result.code === 0) {
    for (const line of result.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      const tr = document.createElement("tr");
      tr.style.cursor = "pointer";
      for (const value of [parts[0] || "", parts[2] || "", (parts[3] || "").replaceAll("\\n", "\n")]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      }
      tr.onclick = () => {
        sql.value = (parts[3] || "").replaceAll("\\n", "\n");
        document.getElementById("tactic").onchange = fillHunts;
document.getElementById("technique").onchange = fillHunts;
fillHunts();
const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
updateLines();
        if (sql.value.trim()) run();
      };
      table.append(tr);
    }
  }
  results.replaceChildren(table);
  status.textContent = "Notes";
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
  const result = await window.mcparser.saveNote(caseDir(), recordId, body, sql.value);
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
  const analyst = document.getElementById("analyst").value.trim();
  await window.mcparser.saveRun(caseDir(), rows, sql.value, runLabel, analyst, runKind);
  runLabel = "query";
  runKind = "run";
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
      document.getElementById("tactic").onchange = fillHunts;
document.getElementById("technique").onchange = fillHunts;
fillHunts();
const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
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


async function showRuns() {
  const result = await window.mcparser.runs(caseDir());
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["#", "followed", "label", "when", "rows", "sql"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  table.append(head);
  if (result && result.code === 0) {
    for (const line of result.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      const tr = document.createElement("tr");
      tr.style.cursor = "pointer";
      const when = new Date(Number(parts[1]) * 1000).toISOString();
      const sqlText = (parts[5] || "").replaceAll("\\n", "\n");
      for (const value of [parts[0] || "", parts[3] || "", parts[4] || "", when, parts[2] || "", sqlText]) {
        const td = document.createElement("td");
        td.textContent = value;
        tr.append(td);
      }
      tr.onclick = () => {
        sql.value = sqlText;
        runKind = "replay";
        runLabel = parts[4] || "replay";
        const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
updateLines();
        if (sql.value.trim()) run();
      };
      table.append(tr);
    }
  }
  results.replaceChildren(table);
  status.textContent = "Runs";
}


async function showTrail() {
  const notes = await window.mcparser.notes(caseDir());
  const runs = await window.mcparser.runs(caseDir());
  const items = [];
  if (notes && notes.code === 0) {
    for (const line of notes.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      items.push({ when: parts[1] || "0", kind: "note", label: `record ${parts[0]}`, detail: parts[2] || "" });
    }
  }
  if (runs && runs.code === 0) {
    for (const line of runs.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      items.push({ when: parts[1] || "0", kind: parts[6] || "run", label: parts[4] || "query", detail: `${parts[5] || ""}  rows ${parts[2] || ""}` });
    }
  }
  items.sort((a, b) => Number(a.when) - Number(b.when));
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["when", "kind", "label", "detail"]) {
    const th = document.createElement("th");
    th.textContent = label;
    head.append(th);
  }
  table.append(head);
  for (const item of items) {
    const tr = document.createElement("tr");
    const when = item.when && item.when !== "0" ? new Date(Number(item.when) * 1000).toISOString() : "";
    for (const value of [when, item.kind, item.label, item.detail]) {
      const td = document.createElement("td");
      td.textContent = value;
      tr.append(td);
    }
    table.append(tr);
  }
  results.replaceChildren(table);
  status.textContent = "Trail";
}

async function exportTrail() {
  const notes = await window.mcparser.notes(caseDir());
  const runs = await window.mcparser.runs(caseDir());
  const lines = ["when,kind,label,detail"];
  const add = (when, kind, label, detail) => {
    const stamp = when && when !== "0" ? new Date(Number(when) * 1000).toISOString() : "";
    lines.push([stamp, kind, label, detail].map((value) => `"${String(value).replaceAll('"', '""')}"`).join(","));
  };
  if (notes && notes.code === 0) {
    for (const line of notes.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      add(parts[1], "note", `record ${parts[0]}`, parts[2] || "");
    }
  }
  if (runs && runs.code === 0) {
    for (const line of runs.out.split("\n").filter(Boolean)) {
      const parts = line.split("\t");
      add(parts[1], parts[6] || "run", parts[4] || "query", `${parts[5] || ""} rows ${parts[2] || ""}`);
    }
  }
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = "trail.csv";
  link.click();
}


async function loadChats() {
  if (!transcript) return;
  transcript.replaceChildren();
  const result = await window.mcparser.chats(caseDir());
  if (!result || result.code !== 0) return;
  for (const line of result.out.split("\n").filter(Boolean)) {
    const parts = line.split("\t");
    const vendor = parts[2] || "Grok";
    const who = vendor === "openai" ? "OpenAI" : vendor === "claude" ? "Claude" : "Grok";
    note(parts[3] || "");
    note(`${who}: ${(parts[4] || "").replaceAll("\\n", "\n")}`);
    note(`${who}: ${(parts[5] || "").replaceAll("\\n", "\n")}`);
  }
}


function askHandoffPassword(action) {
  const sheet = document.getElementById("handoff-sheet");
  const input = document.getElementById("handoff-password");
  document.getElementById("handoff-ok").textContent = action;
  sheet.hidden = false;
  input.value = "";
  input.focus();
  return new Promise((resolve) => {
    const form = document.getElementById("handoff-form");
    const cancel = document.getElementById("handoff-cancel");
    const done = (value) => {
      sheet.hidden = true;
      form.onsubmit = null;
      cancel.onclick = null;
      resolve(value);
    };
    form.onsubmit = (event) => {
      event.preventDefault();
      done(input.value);
    };
    cancel.onclick = () => done("");
  });
}

async function exportHandoff() {
  const picked = await window.mcparser.pickHandoffSave();
  if (!picked || picked.canceled || !picked.filePath) return;
  const password = await askHandoffPassword("Encrypt");
  if (!password) return;
  const result = await window.mcparser.exportHandoff(caseDir(), password, picked.filePath);
  note(result && result.code === 0 ? `Handoff written. ${picked.filePath}` : (result.err || "handoff failed"));
}

let openingHandoff = false;

async function openHandoff() {
  if (openingHandoff) return;
  openingHandoff = true;
  try {
    const picked = await window.mcparser.pickHandoffOpen();
    if (!picked || picked.canceled || !picked.filePaths || !picked.filePaths[0]) return;
    const password = await askHandoffPassword("Decrypt");
    if (!password) return;
    const folder = await window.mcparser.pickHandoffDir();
    if (!folder || folder.canceled || !folder.filePaths || !folder.filePaths[0]) return;
    const result = await window.mcparser.openHandoff(picked.filePaths[0], password, folder.filePaths[0]);
    if (result && result.code === 0) {
      caseInput.value = folder.filePaths[0];
      await refresh();
      await loadChats();
      return;
    }
    const message = (result && result.err) || "Password rejected";
    status.textContent = message.toLowerCase().includes("password") ? "Password rejected" : message;
    note(status.textContent);
    await window.mcparser.handoffError(status.textContent);
  } finally {
    openingHandoff = false;
  }
}

function note(text) {
  const p = document.createElement("p");
  p.textContent = text;
  transcript.append(p);
  transcript.scrollTop = transcript.scrollHeight;
}

function showSheet(grokState) {
  const name = connectProvider === "claude" ? "Claude" : "Grok";
  const label = connectProvider === "claude" ? "Claude" : connectProvider === "openai" ? "OpenAI" : "Grok";
  document.querySelector("#key-form h1").textContent = `Connect ${label}`;
  keyHint.textContent = grokState.connected && grokState.provider === connectProvider
    ? `A ${label} key is set, ending ${grokState.last4}. Save replaces it.`
    : `The ${label} key is encrypted with ${keyStore()}.`;
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
  const saved = await window.mcparser.grokSave(keyInput.value, connectProvider);
  hideSheet();
  if (saved.error) {
    note(saved.error);
    return;
  }
  if (saved.connected) {
    grok.hidden = false;
    const label = connectProvider === "claude" ? "Claude" : connectProvider === "openai" ? "OpenAI" : "Grok";
    note(`${label} connected. Ask about this case.`);
    window.mcparser.grokStatus().then(listModels);
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
  const vendor = document.getElementById("vendor").value;
  const result = await window.mcparser.grokAsk(caseDir(), question, vendor);
  const who = vendor === "openai" ? "OpenAI" : vendor === "claude" ? "Claude" : "Grok";
  if (result.error) {
    note(`${who}: ${result.error}`);
    return;
  }
  note(`${who}: ${result.sql}`);
  await window.mcparser.saveChat(caseDir(), vendor, question, result.sql || "", result.answer || "");
  const runSql = document.createElement("button");
  runSql.textContent = "Run";
  runSql.onclick = () => {
    sql.value = result.sql;
    document.getElementById("tactic").onchange = fillHunts;
document.getElementById("technique").onchange = fillHunts;
fillHunts();
const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
updateLines();
    run();
  };
  transcript.append(runSql);
  note(`${who}: ${result.answer}`);
};
window.mcparser.onImportCollection(async () => {
  const name = document.getElementById("analyst").value.trim();
  if (!name) {
    status.textContent = "Add your name before saving the case";
    document.getElementById("analyst").focus();
    await window.mcparser.handoffError("Add your name before saving the case");
    return;
  }
  const picked = await window.mcparser.pickCollection();
  if (!picked || picked.canceled || !picked.filePaths[0]) return;
  const caseName = await askCaseName();
  if (!caseName) return;
  const saved = await window.mcparser.pickCaseSave();
  if (!saved || saved.canceled || !saved.filePaths[0]) return;
  const made = await window.mcparser.makeCaseDir(saved.filePaths[0], caseName);
  if (!made || made.error) {
    status.textContent = made && made.error ? made.error : "Case name is required";
    return;
  }
  const dir = made.dir;
  const result = await window.mcparser.collect(dir, picked.filePaths[0]);
  caseInput.value = dir;
  if (result.code !== 0) {
    status.textContent = "Import failed";
    results.replaceChildren(document.createTextNode(result.err || result.out || "Import failed"));
    return;
  }
  const named = await window.mcparser.saveAnalyst(dir, name);
  if (named.code !== 0) {
    status.textContent = "Case not saved";
    results.replaceChildren(document.createTextNode(named.err || "Analyst name was not saved"));
    return;
  }
  showImported(result.out);
  status.textContent = "Collection imported";
  await loadHosts();
});

function showImported(text) {
  const lines = text.trim().split("\n").filter(Boolean);
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["Kind", "Host or session", "Collected", "File"]) {
    const cell = document.createElement("th");
    cell.textContent = label;
    head.append(cell);
  }
  table.append(head);
  for (const line of lines) {
    const parts = line.split(" ");
    const row = document.createElement("tr");
    const kind = document.createElement("td");
    kind.textContent = parts[0] || "";
    const id = document.createElement("td");
    id.textContent = parts[1] || "";
    const when = document.createElement("td");
    when.textContent = parts[0] === "host" ? parts.slice(2).join(" ") : (parts[2] || "");
    const file = document.createElement("td");
    file.textContent = parts[0] === "collection" ? (parts[3] || "") : "";
    row.append(kind, id, when, file);
    table.append(row);
  }
  results.replaceChildren(table);
}

window.mcparser.onOpened((opened) => {
  caseInput.value = opened.caseDir;
  status.textContent = opened.code === 0 ? opened.out.trim() : opened.err;
  refresh().then(run);
});
window.mcparser.onGrokConnect((name) => {
  connectProvider = name || "grok";
  window.mcparser.grokStatus().then(showSheet);
});
window.mcparser.onGrokChat((shown) => {
  grok.hidden = !shown;
});
window.mcparser.onShowNotes(showNotes);
window.mcparser.onShowRuns(showRuns);
window.mcparser.onShowTrail(showTrail);
window.mcparser.onExportTrail(exportTrail);
window.mcparser.onExportHandoff(exportHandoff);
window.mcparser.onOpenHandoff(openHandoff);
window.mcparser.onGrokStatus((grokState) => {
  listModels(grokState);
  if (!grokState.connected) {
    grok.hidden = true;
    confirmed = false;
    note("Key forgotten.");
  }
});
document.getElementById("vendor").onchange = async () => {
  const chosen = await window.mcparser.setProvider(document.getElementById("vendor").value);
  listModels(chosen);
  if (chosen.error) note(chosen.error);
};
document.getElementById("tactic").onchange = fillHunts;
document.getElementById("technique").onchange = fillHunts;
fillHunts();
const analyst = document.getElementById("analyst");
if (analyst) {
  analyst.value = localStorage.getItem("mcparser-analyst") || "";
  analyst.onchange = () => localStorage.setItem("mcparser-analyst", analyst.value.trim());
}
updateLines();
window.mcparser.grokStatus().then(listModels);
loadNotes().then(() => refresh().then(run)).then(loadChats);

function askCaseName() {
  const sheet = document.getElementById("case-sheet");
  const form = document.getElementById("case-form");
  const input = document.getElementById("case-name");
  sheet.hidden = false;
  input.value = "";
  input.focus();
  return new Promise((resolve) => {
    function finish(value) {
      sheet.hidden = true;
      form.onsubmit = null;
      document.getElementById("case-cancel").onclick = null;
      resolve(value);
    }
    form.onsubmit = (event) => {
      event.preventDefault();
      finish(input.value.trim());
    };
    document.getElementById("case-cancel").onclick = () => finish("");
  });
}

function restoreWidth(pane, key) {
  const saved = localStorage.getItem(key);
  if (!saved) return;
  pane.style.width = saved;
  pane.style.flexBasis = saved;
}

function splitter(handle, pane, edge, key) {
  restoreWidth(pane, key);
  handle.onpointerdown = (event) => {
    event.preventDefault();
    handle.classList.add("dragging");
    const startX = event.clientX;
    const start = pane.getBoundingClientRect().width;
    function move(next) {
      const delta = next.clientX - startX;
      const width = Math.max(180, Math.min(720, edge === "left" ? start + delta : start - delta));
      pane.style.width = width + "px";
      pane.style.flexBasis = width + "px";
    }
    function up() {
      handle.classList.remove("dragging");
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      localStorage.setItem(key, pane.style.width);
    }
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  };
}

splitter(document.getElementById("split-left"), document.getElementById("case-pane"), "left", "mcparser-case-width");
splitter(document.getElementById("split-right"), document.getElementById("grok"), "right", "mcparser-chat-width");
