const { app, BrowserWindow, ipcMain, dialog, Menu, nativeImage, shell, safeStorage } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

app.setName("McParser");
app.setAboutPanelOptions({
  applicationName: "McParser",
  applicationVersion: "0.1.0",
  copyright: "Author: Daniel de Jager",
  credits: "https://github.com/danieldejager/mcparser\nhttps://www.linkedin.com/in/daniel-de-jager-544162135/",
  website: "https://github.com/danieldejager/mcparser",
});

const repo = path.resolve(__dirname, "..");
const repository = "https://github.com/danieldejager/mcparser";
const linkedin = "https://www.linkedin.com/in/daniel-de-jager-544162135/";
const iconPath = path.join(__dirname, "icon.png");
const iconPng = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAABxklEQVR42u3aMU7DQBCG0ZyBwpVvQMM5OC2nySloqYMokBBCilDs2d3535O2wg07X5J1nMsFAAAAAAAAAAAAoIG3fb/ZhbCB31t2KXTwQjB8ERi+CAQgAMMXgQAEIAABCEAAhi8CERi+ABAAAiAwArsoAFIjsHvBEdi10BDsUlgQdgEA8uyvz84A3Qb6tZ5e9j/X999/r/9cb5cncdRAj7jeNAqHXjHQR643pcavdO8MXuneGSoH3ykAh8jBp/fZrjf1H4N/dMM/3q/l66hgDD88gLgIznhrHRHAGR8NPuvDA2gdwZmHq04BtIzg7NN1twBanQsqbq86BtAigqr7664BLB1B5Rcvq98Gtrs7qP7mrXsAy0UggOAARnz3nhDAEhGMeviSEsD0h0IBhAcw6jFr59vAZX5YMvI5e1IA00YgAAEIQAACEIAA8gIY/SPMpNvAaR8SCaDu/4197i8AAbheAK4XgADG2rbtZs21RGD4AhCACAxfAAIQgABEYPgCEIAIDF8AAhCAAERg+AIQgAgMXwACEIAARGD4AhCACAx/MSv8Zs+UCmOYJQDTmERFAHa5WTB2AQAAAAAAAAAAAAAAAICFfALz+NrUdqiEIwAAAABJRU5ErkJggg==";
let win;
let grokKey = "";
let claudeKey = "";
let openaiKey = "";
let provider = "grok";
let chatShown = false;

function keyFile(name) {
  return path.join(app.getPath("userData"), `${name}-key.bin`);
}

function storeKey(name, key) {
  if (!safeStorage.isEncryptionAvailable()) throw new Error("The keychain is not available");
  const file = keyFile(name);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, safeStorage.encryptString(key), { mode: 0o600 });
}

function loadKey() {
  if (!safeStorage.isEncryptionAvailable()) return;
  for (const providerName of ["grok", "claude", "openai"]) {
    const file = keyFile(providerName);
    if (!fs.existsSync(file)) continue;
    try {
      const value = safeStorage.decryptString(fs.readFileSync(file));
      if (providerName === "claude") claudeKey = value;
      else if (providerName === "openai") openaiKey = value;
      else grokKey = value;
    } catch {
      if (providerName === "claude") claudeKey = "";
      else if (providerName === "openai") openaiKey = "";
      else grokKey = "";
    }
  }
  chatShown = activeKey().length > 0;
  if (claudeKey && !grokKey) provider = "claude";
}

function forgetKey() {
  grokKey = "";
  claudeKey = "";
  openaiKey = "";
  provider = "grok";
  chatShown = false;
  for (const providerName of ["grok", "claude", "openai"]) {
    const file = keyFile(providerName);
    if (fs.existsSync(file)) fs.unlinkSync(file);
  }
}

function activeKey() {
  if (provider === "claude") return claudeKey;
  if (provider === "openai") return openaiKey;
  return grokKey;
}

function parserBinary() {
  const name = process.platform === "win32" ? "mcparser.exe" : "mcparser";
  if (app.isPackaged) return path.join(process.resourcesPath, name);
  return path.join(repo, "target", "debug", name);
}

function appIcon() {
  if (fs.existsSync(iconPath)) return nativeImage.createFromPath(iconPath);
  if (app.isPackaged) return null;
  try {
    fs.writeFileSync(iconPath, Buffer.from(iconPng, "base64"));
    return nativeImage.createFromPath(iconPath);
  } catch {
    return null;
  }
}

function casePath(value) {
  const given = String(value || "");
  if (!given || path.isAbsolute(given)) return given;
  return path.resolve(repo, given);
}

function run(args, password) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.XAI_API_KEY;
    delete env.OPENAI_API_KEY;
    delete env.ANTHROPIC_API_KEY;
    if (password) env.MCPARSER_HANDOFF_PASSWORD = password;
    const child = spawn(parserBinary(), args, { cwd: app.isPackaged ? app.getPath("home") : repo, env });
    let out = "";
    let err = "";
    child.stdout.on("data", (chunk) => {
      out += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      err += chunk.toString();
    });
    child.on("close", (code) => {
      resolve({ code, out, err });
    });
    child.on("error", (error) => {
      resolve({ code: 1, out: "", err: error.message });
    });
  });
}

function grokStatus() {
  const key = activeKey();
  return {
    connected: key.length > 0,
    last4: key.slice(-4),
    provider,
    grok: grokKey.length > 0,
    claude: claudeKey.length > 0,
    openai: openaiKey.length > 0,
  };
}

function textFrom(body) {
  if (body.output_text) return body.output_text;
  const parts = [];
  for (const item of body.output || []) {
    for (const content of item.content || []) {
      if (content.text) parts.push(content.text);
    }
  }
  return parts.join("\n");
}

async function grok(input) {
  const response = await fetch("https://api.x.ai/v1/responses", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${grokKey}`,
    },
    body: JSON.stringify({ model: "grok-4.7", input }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) throw new Error("key rejected");
    throw new Error(body.error && body.error.message ? body.error.message : `HTTP ${response.status}`);
  }
  return textFrom(body);
}

async function claude(input) {
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": claudeKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify({
      model: "claude-sonnet-4-5-20250929",
      max_tokens: 1024,
      messages: [{ role: "user", content: input }],
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) throw new Error("key rejected");
    throw new Error(body.error && body.error.message ? body.error.message : `HTTP ${response.status}`);
  }
  return (body.content || []).map((part) => part.text || "").join("\n");
}

async function openai(input) {
  const response = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${openaiKey}`,
    },
    body: JSON.stringify({
      model: "gpt-4.1",
      messages: [{ role: "user", content: input }],
    }),
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) throw new Error("key rejected");
    throw new Error(body.error && body.error.message ? body.error.message : `HTTP ${response.status}`);
  }
  const choice = body.choices && body.choices[0] && body.choices[0].message;
  return choice && choice.content ? choice.content : "";
}

async function askModel(input) {
  if (provider === "claude") return claude(input);
  if (provider === "openai") return openai(input);
  return grok(input);
}

function oneSelect(text) {
  const fenced = text.match(/```sql\s*([\s\S]*?)```/i);
  let sql = (fenced ? fenced[1] : text).trim().replace(/;+\s*$/, "");
  if (sql.includes(";")) throw new Error("The model returned more than one statement");
  if (!/^select\b/i.test(sql)) throw new Error("The model did not return a SELECT");
  if (/\b(attach|copy|pragma|insert|update|delete|drop|create|alter)\b/i.test(sql)) {
    throw new Error("The model returned a statement that is not a read");
  }
  if (!/\blimit\b/i.test(sql)) sql += " LIMIT 50";
  return sql;
}

function clip(text) {
  return text.length > 4000 ? text.slice(0, 4000) : text;
}

const schema = [
  "Table events(source_sha256, record_id, event_id, channel, provider, computer, time_created, event_data, host_id, log_name).",
  "Columns, never read these from event_data: computer, channel, provider, host_id, log_name, event_id, time_created, record_id, source_sha256.",
  "host_id is a UUID from the host list. A hostname is not a host_id.",
  "log_name is a path. Match a file with LIKE '%Security.evtx'. Use a log_name value from the case context.",
  "event_data is JSON. Read TargetUserName, LogonType and IpAddress with json_extract_string(event_data, '$.TargetUserName').",
  "A successful logon is event_id 4624.",
  "Table prefetch(host_id, pf_name, executable, run_count, last_run, version, path). It is not inside events. Use it for what ran on the machine and how often.",
  "Table userassist(host_id, guid, name, run_count, last_run). It is not inside events. Use it for programs Explorer launched for one user. Ignore names starting with UEME_CTL.",
  "Table amcache(host_id, kind, name, path, sha1, size, modified, publisher, version, key_path). It is not inside events. kind is file or program. A file row means the executable was inventoried, not that it ran. modified on a file row is the compile time, not a run time. A program row is an installed product and its modified value is the install date.",
  "Table shimcache(host_id, path, modified, position, executed, control_set). It is not inside events. A row means Windows recorded the path. modified is the file time, not a run time. position 0 is the newest entry.\n" +
  "Table srum(host_id, kind, timestamp, app, user_sid, bytes_sent, bytes_received, foreground_cycles, background_cycles). It is not inside events. kind is network or app. A network row is hourly bytes for an application. timestamp is when the record was written, not a start time.\n" +
  "Table services(host_id, name, display_name, state, start_mode, path, user_id). It is not inside events. A row is a Windows service. path is the program it runs. start_mode is how it starts.\n" +
  "Table tasks(host_id, path, command, arguments, user_id, enabled). It is not inside events. A row is a scheduled task. command plus arguments is what runs with no one at the keyboard.",
  "Match a hash with amcache.sha1. Match a program name across prefetch.executable, userassist.name, amcache.path, shimcache.path, services.path and tasks.command. The case context shows non-Windows services, tasks and shimcache rows, the busiest SRUM network rows, and the top event ids. Query the table for the rest.",
  "Return one DuckDB SELECT and no other text."
].join(" ");

async function caseContext(caseDir) {
  const hosts = await run(["hosts", "--case", casePath(caseDir)]);
  const logs = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT host_id, log_name, computer, count(*) AS events FROM events GROUP BY host_id, log_name, computer ORDER BY events DESC LIMIT 30"]);
  const prefetch = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT host_id, executable, run_count, last_run, path FROM prefetch ORDER BY run_count DESC LIMIT 30"]);
  const prefetchText = prefetch.code === 0 ? prefetch.out || "" : "prefetch table is not loaded";
  const userassist = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT host_id, run_count, last_run, name FROM userassist WHERE name NOT LIKE 'UEME_CTL%' ORDER BY run_count DESC LIMIT 30"]);
  const userassistText = userassist.code === 0 ? userassist.out || "" : "userassist table is not loaded";
  const amcache = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT kind, name, sha1, modified, path FROM amcache WHERE kind = 'file' ORDER BY modified DESC LIMIT 30"]);
  const amcacheText = amcache.code === 0 ? amcache.out || "" : "amcache table is not loaded";
  const events = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT event_id, channel, count(*) AS events FROM events GROUP BY event_id, channel ORDER BY events DESC LIMIT 20"]);
  const eventsText = events.code === 0 ? events.out || "" : "events table is not loaded";
  const shimcache = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT position, executed, modified, path FROM shimcache WHERE lower(path) NOT LIKE '%\\\\windows\\\\%' ORDER BY position LIMIT 30"]);
  const shimcacheText = shimcache.code === 0 ? shimcache.out || "" : "shimcache table is not loaded";
  const srum = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT kind, timestamp, app, user_sid, bytes_sent, bytes_received, background_cycles FROM srum WHERE kind = 'network' ORDER BY bytes_sent DESC LIMIT 30"]);
  const srumText = srum.code === 0 ? srum.out || "" : "srum table is not loaded";
  const services = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT name, state, start_mode, user_id, path FROM services WHERE lower(path) NOT LIKE '%\\\\windows\\\\system32\\\\%' AND lower(path) NOT LIKE '%\\\\windows\\\\syswow64\\\\%' ORDER BY name LIMIT 40"]);
  const servicesText = services.code === 0 ? services.out || "" : "services table is not loaded";
  const tasks = await run(["query", "--case", casePath(caseDir), "--format", "csv",
    "SELECT enabled, user_id, command, arguments, path FROM tasks WHERE command <> '' AND lower(command) NOT LIKE '%\\\\windows\\\\system32\\\\%' AND lower(command) NOT LIKE '%\\\\windows\\\\syswow64\\\\%' ORDER BY command LIMIT 40"]);
  const tasksText = tasks.code === 0 ? tasks.out || "" : "tasks table is not loaded";
  return "Hosts, tab separated host_id, hostname, fqdn, os, arch:\n" + clip(hosts.out || "") +
    "\nLogs in this case, csv host_id, log_name, computer, events:\n" + clip(logs.out || "") +
    "\nEvent ids in this case, csv event_id, channel, events:\n" + clip(eventsText) +
    "\nPrefetch in this case, csv host_id, executable, run_count, last_run, path:\n" + clip(prefetchText) +
    "\nUserAssist in this case, csv host_id, run_count, last_run, name:\n" + clip(userassistText) +
    "\nAmcache file rows in this case, csv kind, name, sha1, modified, path:\n" + clip(amcacheText) +
    "\nShimcache outside Windows, newest 30, csv position, executed, modified, path:\n" + clip(shimcacheText) +
    "\nSRUM network rows, highest bytes sent, csv kind, timestamp, app, user_sid, bytes_sent, bytes_received, background_cycles:\n" + clip(srumText) +
    "\nServices outside System32, csv name, state, start_mode, user_id, path:\n" + clip(servicesText) +
    "\nScheduled tasks outside System32, csv enabled, user_id, command, arguments, path:\n" + clip(tasksText);
}

function askProgress(label) {
  if (win) win.webContents.send("ask-progress", label);
}

async function coverage(caseDir) {
  const samples = [
    ["events", "SELECT event_id, count(*) AS events FROM events GROUP BY event_id ORDER BY events DESC LIMIT 3"],
    ["prefetch", "SELECT executable, run_count, last_run FROM prefetch ORDER BY run_count DESC LIMIT 3"],
    ["userassist", "SELECT \"name\", run_count FROM userassist WHERE \"name\" NOT LIKE 'UEME_CTL%' ORDER BY run_count DESC LIMIT 3"],
    ["amcache", "SELECT \"name\", sha1, path FROM amcache WHERE kind = 'file' LIMIT 3"],
    ["shimcache", "SELECT position, path FROM shimcache WHERE lower(path) NOT LIKE '%\\\\windows\\\\%' ORDER BY position LIMIT 3"],
    ["srum", "SELECT app, bytes_sent FROM srum WHERE kind = 'network' ORDER BY bytes_sent DESC LIMIT 3"],
    ["services", "SELECT name, start_mode, path FROM services WHERE lower(path) NOT LIKE '%\\\\windows\\\\system32\\\\%' LIMIT 3"],
    ["tasks", "SELECT command, arguments, path FROM tasks WHERE command <> '' AND lower(command) NOT LIKE '%\\\\windows\\\\system32\\\\%' LIMIT 3"],
  ];
  const parts = [];
  for (const [name, sql] of samples) {
    askProgress("Querying " + name);
    const queried = await run(["query", "--case", casePath(caseDir), "--format", "csv", sql]);
    parts.push(name + "\n" + (queried.code === 0 ? queried.out || "no rows" : "query failed: " + (queried.err || queried.out || "unknown")));
  }
  return parts.join("\n");
}

async function grokAsk(caseDir, question) {
  if (!activeKey()) return { error: "Configure this integration.", provider };
  try {
    const context = await caseContext(caseDir);
    const covered = await coverage(caseDir);
    askProgress("Asking " + provider + " for a query");
    const rules = "\nWrite one SELECT only. Do not use UNION. A question about more than one table is already answered by the coverage rows; pick the single most relevant table for the SELECT.\n";
    let sql = "";
    let rows = covered;
    try {
      sql = oneSelect(await askModel(schema + "\n" + context + "\nCoverage already queried:\n" + covered + rules + "Question: " + question));
      const queried = await run(["query", "--case", casePath(caseDir), "--format", "csv", sql]);
      if (queried.code === 0) rows = queried.out || covered;
      else sql = sql + "\n-- failed, answered from coverage";
    } catch (error) {
      sql = "-- answered from coverage\n" + error.message;
    }
    askProgress("Asking " + provider + " to answer");
    const answer = await askModel(
      "Answer from these rows only. Do not invent rows. Map a host_id back to its hostname from the host list. If a source says not loaded, say so.\n" +
      context +
      "\nCoverage:\n" + covered +
      "\nQuestion: " + question +
      "\nSQL: " + sql +
      "\nRows:\n" + clip(rows)
    );
    return { sql, answer, provider };
  } catch (error) {
    return { error: error.message, provider };
  }
}

async function openEvtx() {
  const picked = await dialog.showOpenDialog(win, {
    title: "Import Windows event log",
    properties: ["openFile"],
    filters: [{ name: "Windows Event Log", extensions: ["evtx"] }],
  });
  if (picked.canceled || !picked.filePaths[0]) return;
  win.webContents.send("import-evtx", { file: picked.filePaths[0] });
}

async function showAbout() {
  const choice = await dialog.showMessageBox(win, {
    type: "info",
    title: "About McParser",
    message: "McParser",
    detail: "Offline Windows event log parser.\nQuery a case with SQL.\nVersion 0.1.0\n\nAuthor: Daniel de Jager\n" + repository + "\n" + linkedin,
    buttons: ["OK", "Open repository", "Open LinkedIn"],
    defaultId: 0,
  });
  if (choice.response === 1) shell.openExternal(repository);
  if (choice.response === 2) shell.openExternal(linkedin);
}

let caseOpen = false;

function buildMenu() {
  const connected = activeKey().length > 0;
  const template = [
    {
      label: "McParser",
      submenu: [
        { label: "About McParser", click: showAbout },
        { type: "separator" },
        { role: "hide" },
        { role: "hideOthers" },
        { role: "unhide" },
        { type: "separator" },
        { role: "quit", label: "Quit McParser" },
      ],
    },
    {
      label: "File",
      submenu: [
        {
          label: "Case",
          submenu: [
            { label: "New Case...", click: () => win.webContents.send("new-case") },
            { label: "Open Case...", accelerator: "CmdOrCtrl+O", click: () => win.webContents.send("open-case") },
            { label: "Save Case", accelerator: "CmdOrCtrl+S", enabled: caseOpen, click: () => win.webContents.send("save-case") },
            { type: "separator" },
            { label: "Close Case", enabled: caseOpen, click: () => win.webContents.send("close-case") },
            { label: "Delete Case...", enabled: caseOpen, click: () => win.webContents.send("delete-case") },
          ],
        },
        { type: "separator" },
        { label: "Import EVTX...", click: openEvtx },
        { label: "Import Collection...", click: () => win.webContents.send("import-collection") },
        {
          label: "HandOff",
          submenu: [
            { label: "Create...", enabled: caseOpen, click: () => win.webContents.send("export-handoff") },
            { label: "Open...", click: () => win.webContents.send("open-handoff") },
          ],
        },
        { type: "separator" },
        { role: "close" },
      ],
    },
    {
      label: "Edit",
      submenu: [
        { role: "undo" },
        { role: "redo" },
        { type: "separator" },
        { role: "cut" },
        { role: "copy" },
        { role: "paste" },
        { role: "selectAll" },
      ],
    },
    {
      label: "Audit",
      submenu: [
        { label: "Notes", click: () => win.webContents.send("show-notes") },
        { label: "Runs", click: () => win.webContents.send("show-runs") },
        { label: "Trail", click: () => win.webContents.send("show-trail") },
        { label: "Export trail", click: () => win.webContents.send("export-trail") },
      ],
    },
    {
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        { type: "separator" },
        { role: "front" },
      ],
    },
    {
      label: "AI Integration",
      submenu: [
        {
          label: grokKey ? "Grok key saved" : "Connect Grok...",
          click: () => win.webContents.send("grok-connect", "grok"),
        },
        {
          label: claudeKey ? "Claude key saved" : "Connect Claude...",
          click: () => win.webContents.send("grok-connect", "claude"),
        },
        {
          label: openaiKey ? "OpenAI key saved" : "Connect OpenAI...",
          click: () => win.webContents.send("grok-connect", "openai"),
        },
        {
          label: "Forget key",
          enabled: connected,
          click: () => {
            forgetKey();
            buildMenu();
            win.webContents.send("grok-status", grokStatus());
          },
        },
        {
          label: "Show chat",
          type: "checkbox",
          checked: chatShown,
          enabled: connected,
          click: (item) => {
            chatShown = item.checked;
            win.webContents.send("grok-chat", chatShown);
          },
        },
      ],
    },
    {
      label: "Help",
      submenu: [{ label: "About McParser", click: showAbout }],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createWindow() {
  const icon = appIcon();
  win = new BrowserWindow({
    width: 1200,
    height: 760,
    title: "McParser",
    icon: icon || undefined,
    backgroundColor: "#f3f3f3",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
    },
  });
  win.loadFile("index.html");
  win.webContents.once("did-finish-load", () => {
    if (chatShown) win.webContents.send("grok-chat", true);
  });
}

ipcMain.handle("stats", (_event, caseDir) => run(["stats", "--case", casePath(caseDir)]));
ipcMain.handle("hosts", (_event, caseDir) => run(["hosts", "--case", casePath(caseDir)]));
ipcMain.handle("pick-collection", async () => dialog.showOpenDialog(win, {
  title: "Import Velociraptor collection",
  properties: ["openFile"],
  filters: [{ name: "Collector zip", extensions: ["zip"] }],
}));
ipcMain.handle("set-case-open", (_event, open) => { caseOpen = Boolean(open); buildMenu(); return caseOpen; });
ipcMain.handle("pick-case-open", async () => dialog.showOpenDialog(win, {
  title: "Open case",
  properties: ["openDirectory"],
  buttonLabel: "Open case",
}));
ipcMain.handle("delete-case", async (_event, caseDir) => {
  const dir = casePath(caseDir);
  if (!dir || !dir.endsWith(".mcp")) return { error: "Only a .mcp case folder can be deleted" };
  const choice = await dialog.showMessageBox(win, {
    type: "warning",
    message: "Delete this case?",
    detail: dir,
    buttons: ["Delete", "Cancel"],
    defaultId: 1,
    cancelId: 1,
  });
  if (choice.response !== 0) return { canceled: true };
  fs.rmSync(dir, { recursive: true, force: true });
  return { deleted: true };
});
ipcMain.handle("pick-case-save", async () => dialog.showOpenDialog(win, {
  title: "Save case",
  properties: ["openDirectory", "createDirectory"],
  buttonLabel: "Save case",
}));
ipcMain.handle("make-case-dir", (_event, parent, name) => {
  const safe = String(name || "").replace(/[\\/:*?"<>|]/g, "-").trim();
  if (!safe) return { error: "Case name is required" };
  const dir = path.join(parent, safe.endsWith(".mcp") ? safe : safe + ".mcp");
  fs.mkdirSync(dir, { recursive: true });
  return { dir };
});
ipcMain.handle("collect", (_event, caseDir, file, analyst) => runCollect(["collect", "--case", casePath(caseDir), "--analyst", analyst || "", file]));

function runCollect(args) {
  return new Promise((resolve) => {
    const env = { ...process.env };
    delete env.XAI_API_KEY;
    delete env.OPENAI_API_KEY;
    delete env.ANTHROPIC_API_KEY;
    const child = spawn(parserBinary(), args, { cwd: app.isPackaged ? app.getPath("home") : repo, env });
    let out = "";
    let err = "";
    let pending = "";
    child.stdout.on("data", (chunk) => {
      pending += chunk.toString();
      const lines = pending.split(/\n/);
      pending = lines.pop() || "";
      for (const line of lines) {
        if (line.startsWith("progress\t")) {
          const parts = line.split("\t");
          if (win) win.webContents.send("collect-progress", { pct: Number(parts[1] || 0), label: parts.slice(2).join(" ") });
        } else if (line) {
          out += line + "\n";
        }
      }
    });
    child.stderr.on("data", (chunk) => { err += chunk.toString(); });
    child.on("close", (code) => resolve({ code, out, err }));
    child.on("error", (error) => resolve({ code: 1, out: "", err: error.message }));
  });
}

ipcMain.handle("ingest", (_event, caseDir, file) => run(["ingest", "--case", casePath(caseDir), file]));
ipcMain.handle("choose-case-target", async (_event, current) => dialog.showMessageBox(win, { type: "question", message: "Do you want to import this file to the existing case?", detail: current, buttons: ["Import to this case", "New case", "Cancel"], defaultId: 0, cancelId: 2 }));
ipcMain.handle("save-analyst", (_event, caseDir, name) => run(["save-analyst", "--case", casePath(caseDir), "--name", name]));
ipcMain.handle("collections", (_event, caseDir) => run(["collections", "--case", casePath(caseDir)]));
ipcMain.handle("prefetch", (_event, caseDir) => run(["prefetch", "--case", casePath(caseDir)]));
ipcMain.handle("query", (_event, caseDir, sql) => run(["query", "--case", casePath(caseDir), "--format", "csv", sql]));
ipcMain.handle("save-csv", async (_event, csv) => {
  const picked = await dialog.showSaveDialog(win, {
    title: "Export results",
    defaultPath: "results.csv",
    filters: [{ name: "CSV", extensions: ["csv"] }],
  });
  if (picked.canceled || !picked.filePath) return { saved: false };
  fs.writeFileSync(picked.filePath, csv);
  return { saved: true, path: picked.filePath };
});
ipcMain.handle("grok-status", () => grokStatus());
ipcMain.handle("set-provider", (_event, name) => {
  if (name !== "grok" && name !== "claude" && name !== "openai") return grokStatus();
  provider = name;
  buildMenu();
  if (!activeKey()) return { ...grokStatus(), error: "Configure this integration." };
  return grokStatus();
});

ipcMain.handle("grok-save", (_event, key, name) => {
  if (name === "claude" || name === "grok" || name === "openai") provider = name;
  const value = String(key || "").trim();
  if (!value) return { connected: false, error: "Enter a key" };
  try {
    const name = provider;
    storeKey(name, value);
    if (name === "claude") claudeKey = value;
    else if (name === "openai") openaiKey = value;
    else grokKey = value;
    chatShown = true;
    buildMenu();
    return grokStatus();
  } catch (error) {
    return { connected: false, error: error.message };
  }
});
ipcMain.handle("grok-forget", () => {
  forgetKey();
  buildMenu();
  return grokStatus();
});
ipcMain.handle("grok-ask", (_event, caseDir, question, name) => {
  if (name === "grok" || name === "claude" || name === "openai") provider = name;
  return grokAsk(caseDir, question);
});
ipcMain.handle("queries", (_event, caseDir) => run(["queries", "--case", casePath(caseDir)]));
ipcMain.handle("save-query", (_event, caseDir, name, sql) => run(["save-query", "--case", casePath(caseDir), "--name", name, sql]));
ipcMain.handle("notes", (_event, caseDir) => run(["notes", "--case", casePath(caseDir)]));
ipcMain.handle("runs", (_event, caseDir) => run(["runs", "--case", casePath(caseDir)]));
ipcMain.handle("chats", (_event, caseDir) => run(["chats", "--case", casePath(caseDir)]));
ipcMain.handle("save-chat", (_event, caseDir, vendor, question, sql, answer) => run(["save-chat", "--case", casePath(caseDir), "--vendor", vendor, "--question", question, "--sql", sql, "--answer", answer]));
ipcMain.handle("export-handoff", (_event, caseDir, password, out) => run(["handoff", "--case", casePath(caseDir), "--out", out], password));
ipcMain.handle("open-handoff", (_event, file, password, out) => run(["open-handoff", "--file", file, "--out", out], password));
ipcMain.handle("pick-handoff-save", async () => dialog.showSaveDialog({ defaultPath: "handoff.mcpz" }));
ipcMain.handle("pick-handoff-open", async () => dialog.showOpenDialog({ properties: ["openFile"] }));
ipcMain.handle("handoff-error", async (_event, message) => dialog.showMessageBox({ type: "error", message }));
ipcMain.handle("pick-handoff-dir", async () => dialog.showOpenDialog({ properties: ["openDirectory", "createDirectory"] }));

ipcMain.handle("save-run", (_event, caseDir, rows, sql, label, analyst, kind) => run(["save-run", "--case", casePath(caseDir), "--rows", String(rows), "--label", label || "query", "--analyst", analyst || "", "--kind", kind || "run", sql]));

ipcMain.handle("save-note", (_event, caseDir, recordId, body, sql) => run(["save-note", "--case", casePath(caseDir), "--record", String(recordId), "--sql", sql || "", body]));



app.whenReady().then(() => {
  const icon = appIcon();
  if (icon && app.dock) app.dock.setIcon(icon);
  loadKey();
  buildMenu();
  createWindow();
});
app.on("window-all-closed", () => app.quit());
