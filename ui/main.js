const { app, BrowserWindow, ipcMain, dialog, Menu, nativeImage, shell, safeStorage, Notification } = require("electron");
const { spawn } = require("child_process");
const ask = require("./ask-context");
const fs = require("fs");
const peRange = require("./pe-range.js");
const peCase = require("./pe-case.js");
const parserBin = require("./parser-binary.js");
const path = require("path");
const bazaar = require("./bazaar-fetch");
const { runStartupUpdate } = require("./bazaar-autoupdate");

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
const MAX_OUT = 50 * 1024 * 1024;

function debugLog(message) {
  if (app.isPackaged) return;
  try {
    const file = path.join(app.getPath("userData"), "debug.log");
    fs.appendFileSync(file, new Date().toISOString() + " " + message + "\n");
  } catch {}
}

process.on("uncaughtException", (err) => {
  debugLog("uncaught " + (err && err.stack ? err.stack : err));
});
process.on("unhandledRejection", (err) => {
  debugLog("rejection " + (err && err.stack ? err.stack : err));
});
const iconPng = "iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAABxklEQVR42u3aMU7DQBCG0ZyBwpVvQMM5OC2nySloqYMokBBCilDs2d3535O2wg07X5J1nMsFAAAAAAAAAAAAoIG3fb/ZhbCB31t2KXTwQjB8ERi+CAQgAMMXgQAEIAABCEAAhi8CERi+ABAAAiAwArsoAFIjsHvBEdi10BDsUlgQdgEA8uyvz84A3Qb6tZ5e9j/X999/r/9cb5cncdRAj7jeNAqHXjHQR643pcavdO8MXuneGSoH3ykAh8jBp/fZrjf1H4N/dMM/3q/l66hgDD88gLgIznhrHRHAGR8NPuvDA2gdwZmHq04BtIzg7NN1twBanQsqbq86BtAigqr7664BLB1B5Rcvq98Gtrs7qP7mrXsAy0UggOAARnz3nhDAEhGMeviSEsD0h0IBhAcw6jFr59vAZX5YMvI5e1IA00YgAAEIQAACEIAA8gIY/SPMpNvAaR8SCaDu/4197i8AAbheAK4XgADG2rbtZs21RGD4AhCACAxfAAIQgABEYPgCEIAIDF8AAhCAAERg+AIQgAgMXwACEIAARGD4AhCACAx/MSv8Zs+UCmOYJQDTmERFAHa5WTB2AQAAAAAAAAAAAAAAAICFfALz+NrUdqiEIwAAAABJRU5ErkJggg==";
let win;
let grokKey = "";
let claudeKey = "";
let openaiKey = "";
let provider = "grok";
let chatShown = false;
let models = { grok: "grok-4.7", claude: "claude-sonnet-5-5", openai: "gpt-5.5" };

function keyFile(name) {
  return path.join(app.getPath("userData"), `${name}-key.bin`);
}

function loadSourceKey(name) {
  if (!safeStorage.isEncryptionAvailable()) throw new Error("The keychain is not available");
  const file = keyFile(name);
  if (!fs.existsSync(file)) throw new Error("No key is stored");
  return safeStorage.decryptString(fs.readFileSync(file));
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

function forgetOne(name) {
  if (name === "claude") claudeKey = "";
  else if (name === "openai") openaiKey = "";
  else grokKey = "";
  const file = keyFile(name);
  if (fs.existsSync(file)) fs.unlinkSync(file);
  if (!activeKey()) chatShown = false;
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
  if (app.isPackaged) return path.join(process.resourcesPath, parserBin.binaryName(process.platform));
  return parserBin.devBinary(repo, process.platform);
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
    let tooBig = false;
    child.stdout.on("data", (chunk) => {
      if (tooBig) return;
      const text = chunk.toString();
      if (out.length + text.length > MAX_OUT) {
        tooBig = true;
        out = "";
        err = "Result is over " + Math.round(MAX_OUT / 1024 / 1024) + " MB and too large to display. Add a LIMIT or a WHERE clause.";
        debugLog("output exceeded " + MAX_OUT + " bytes for " + args.join(" "));
        return;
      }
      out += text;
    });
    child.stderr.on("data", (chunk) => {
      err += chunk.toString();
    });
    child.on("close", (code) => {
      if (tooBig) resolve({ code: 1, out: "", err });
      else resolve({ code, out, err });
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
    models,
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
    body: JSON.stringify({ model: models.grok, input }),
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
      model: models.claude,
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
      model: models.openai,
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

function clip(text) {
  return text.length > 4000 ? text.slice(0, 4000) : text;
}

async function caseTables(caseDir) {
  const listed = await run(["query", "--case", casePath(caseDir), "--format", "csv", "--store", bazaarStore(), ask.TABLES_SQL]);
  return listed.code === 0 ? ask.parseTables(listed.out) : new Set();
}

function bazaarStore() {
  return path.join(app.getPath("userData"), "marketplace.sqlite");
}

async function caseContext(caseDir, tables) {
  const q = async (table, sql, label) => {
    if (table && !tables.has(table)) return "";
    const args = ["query", "--case", casePath(caseDir), "--format", "csv"];
    if (table && table.startsWith("malwarebazaar")) args.push("--store", bazaarStore());
    args.push(sql);
    const out = await run(args);
    return "\n" + label + ":\n" + clip(out.code === 0 ? out.out || "no rows" : "query failed");
  };
  const hosts = await run(["hosts", "--case", casePath(caseDir)]);
  let text = "Hosts, tab separated host_id, hostname, fqdn, os, arch:\n" + clip(hosts.out || "");
  text += await q("events", "SELECT host_id, log_name, computer, count(*) AS events FROM events GROUP BY host_id, log_name, computer ORDER BY events DESC LIMIT 30", "Logs in this case, csv host_id, log_name, computer, events");
  text += await q("prefetch", "SELECT host_id, executable, run_count, last_run, path FROM prefetch ORDER BY run_count DESC LIMIT 30", "Prefetch in this case, csv host_id, executable, run_count, last_run, path");
  text += await q("userassist", "SELECT host_id, run_count, last_run, \"name\" FROM userassist WHERE \"name\" NOT LIKE 'UEME_CTL%' ORDER BY run_count DESC LIMIT 30", "UserAssist in this case, csv host_id, run_count, last_run, name");
  text += await q("amcache", "SELECT kind, \"name\", sha1, modified, path FROM amcache WHERE kind = 'file' ORDER BY modified DESC LIMIT 30", "Amcache file rows in this case, csv kind, name, sha1, modified, path");
  text += await q("events", "SELECT event_id, channel, count(*) AS events FROM events GROUP BY event_id, channel ORDER BY events DESC LIMIT 20", "Event ids in this case, csv event_id, channel, events");
  text += await q("shimcache", "SELECT position, executed, modified, path FROM shimcache WHERE lower(path) NOT LIKE '%\\\\windows\\\\%' ORDER BY position LIMIT 30", "Shimcache outside Windows, newest 30, csv position, executed, modified, path");
  text += await q("srum", "SELECT kind, timestamp, app, user_sid, bytes_sent, bytes_received, background_cycles FROM srum WHERE kind = 'network' ORDER BY bytes_sent DESC LIMIT 30", "SRUM network rows, highest bytes sent, csv kind, timestamp, app, user_sid, bytes_sent, bytes_received, background_cycles");
  text += await q("services", "SELECT name, state, start_mode, user_id, path FROM services WHERE lower(path) NOT LIKE '%\\\\windows\\\\system32\\\\%' AND lower(path) NOT LIKE '%\\\\windows\\\\syswow64\\\\%' ORDER BY name LIMIT 40", "Services outside System32, csv name, state, start_mode, user_id, path");
  text += await q("tasks", "SELECT enabled, user_id, command, arguments, path FROM tasks WHERE command <> '' AND lower(command) NOT LIKE '%\\\\windows\\\\system32\\\\%' AND lower(command) NOT LIKE '%\\\\windows\\\\syswow64\\\\%' ORDER BY command LIMIT 40", "Scheduled tasks outside System32, csv enabled, user_id, command, arguments, path");
  text += await q("malwarebazaar", "SELECT sha256, sha1, md5, signature, file_name, first_seen FROM malwarebazaar LIMIT 20", "MalwareBazaar sample, csv sha256, sha1, md5, signature, file_name, first_seen");
  const peSql = ask.peSummarySql(tables);
  if (peSql) text += await q("pe_files", peSql, "Analyzed PE files, one row each, most indicators first (hints, not verdicts; signature_present is not validation; IOC candidates are shown defanged and are not confirmed malicious)");
  return text;
}

function vendorLabel() {
  if (provider === "openai") return "OpenAI";
  if (provider === "claude") return "Claude";
  return "Grok";
}

function askProgress(label) {
  if (win) win.webContents.send("ask-progress", label);
}

async function coverage(caseDir, tables) {
  const parts = [];
  for (const [name, sql] of ask.coverageQueries(tables)) {
    askProgress("Querying " + name);
    const args = ["query", "--case", casePath(caseDir), "--format", "csv"];
    if (name === "malwarebazaar") args.push("--store", bazaarStore());
    args.push(sql);
    const queried = await run(args);
    parts.push(name + "\n" + (queried.code === 0 ? queried.out || "no rows" : "query failed: " + clip(queried.err || queried.out || "unknown")));
  }
  return parts.join("\n");
}

async function grokAsk(caseDir, question) {
  if (!activeKey()) return { error: "Configure this integration.", provider };
  try {
    const tables = await caseTables(caseDir);
    const schema = ask.buildSchema(tables);
    const context = await caseContext(caseDir, tables);
    const covered = await coverage(caseDir, tables);
    askProgress("Asking " + vendorLabel() + " for a query");
    const prompt = schema + "\n" + context + "\nCoverage already queried:\n" + covered + ask.RULES + "Question: " + question;
    let sql = "";
    let rows = "";
    let failure = "";
    for (let attempt = 0; attempt < 2 && !rows; attempt++) {
      try {
        sql = ask.readOnlySql(await askModel(prompt + failure));
        const queried = await run(["query", "--case", casePath(caseDir), "--format", "csv", "--store", bazaarStore(), sql]);
        if (queried.code === 0) rows = queried.out || "no rows";
        else failure = "\nYour last statement failed: " + clip(queried.err || queried.out || "unknown") + "\nFix it.\n";
      } catch (error) {
        failure = "\nYour last answer was rejected: " + error.message + "\n";
      }
    }
    if (!rows) sql = (sql ? sql + "\n" : "") + "-- failed, answered from coverage";
    askProgress("Asking " + vendorLabel() + " to answer");
    const answer = await askModel(
      ask.ANSWER_RULES +
      "Question: " + question +
      (rows ? "\nQuery:\n" + sql + "\nRows:\n" + clip(rows) : "") +
      "\nCase context:\n" + context +
      "\nCoverage:\n" + covered
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

// View > Mode. Fixed IPC channels, nothing loaded from the network:
// main sends THEME_SET_CHANNEL with "light" or "dark" when a radio is picked;
// the renderer reports the effective mode on THEME_STATE_CHANNEL at startup
// and on every change so the radio checks stay in sync.
const THEME_SET_CHANNEL = "set-theme-mode";
const THEME_STATE_CHANNEL = "theme-mode";
const THEME_MODES = ["light", "dark"];
let themeMode = "light";

function setThemeMode(mode) {
  if (!THEME_MODES.includes(mode)) return;
  themeMode = mode;
  if (win) win.webContents.send(THEME_SET_CHANNEL, mode);
  buildMenu();
}

function viewMenu() {
  return {
    label: "View",
    submenu: [
      {
        label: "Mode",
        submenu: [
          { label: "Light", type: "radio", checked: themeMode === "light", click: () => setThemeMode("light") },
          { label: "Dark", type: "radio", checked: themeMode === "dark", click: () => setThemeMode("dark") },
        ],
      },
    ],
  };
}

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
        { label: "Save", enabled: caseOpen, click: () => win.webContents.send("save-sql") },
        { label: "Save All", enabled: caseOpen, accelerator: "CmdOrCtrl+Shift+S", click: () => win.webContents.send("save-all-sql") },
        { type: "separator" },
        { label: "Import EVTX...", click: openEvtx },
        { label: "Import Collection...", click: () => win.webContents.send("import-collection") },
        { label: "Analyze PE File...", click: () => win.webContents.send("analyze-pe") },
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
    viewMenu(),
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
      label: "Administration",
      submenu: [
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
          label: "Marketplace",
          click: () => win.webContents.send("marketplace"),
        },
        {
          label: "IOC Management",
          submenu: [
            { label: "View", enabled: caseOpen, click: () => win.webContents.send("ioc-view") },
            { label: "Add", enabled: caseOpen, click: () => win.webContents.send("ioc-add") },
            { label: "Upload", click: () => win.webContents.send("ioc-upload") },
          ],
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
    fullscreen: true,
    title: "McParser",
    icon: icon || undefined,
    backgroundColor: "#f3f3f3",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      // Preload only uses contextBridge, ipcRenderer and process.platform,
      // all available in a sandboxed preload.
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      allowRunningInsecureContent: false,
    },
  });
  win.loadFile("index.html");
  win.webContents.once("did-finish-load", () => {
    if (chatShown) win.webContents.send("grok-chat", true);
    startupBazaarUpdate();
  });
  win.on("focus", () => buildMenu());
}

ipcMain.handle("stats", (_event, caseDir) => run(["stats", "--case", casePath(caseDir)]));
ipcMain.handle("hosts", (_event, caseDir) => run(["hosts", "--case", casePath(caseDir)]));
ipcMain.handle("pick-collection", async () => dialog.showOpenDialog(win, {
  title: "Import Velociraptor collection",
  properties: ["openFile"],
  filters: [{ name: "Collector zip", extensions: ["zip"] }],
}));
ipcMain.on(THEME_STATE_CHANNEL, (event, mode) => {
  if (!win || event.sender !== win.webContents || !THEME_MODES.includes(mode) || mode === themeMode) return;
  themeMode = mode;
  buildMenu();
});
ipcMain.handle("set-case-open", (_event, open) => { caseOpen = Boolean(open); buildMenu(); return caseOpen; });
ipcMain.handle("ioc-upload", async () => {
  const picked = await dialog.showOpenDialog(win, {
    title: "Upload IOC file",
    filters: [{ name: "CSV", extensions: ["csv", "txt"] }],
    properties: ["openFile"],
  });
  if (picked.canceled || !picked.filePaths[0]) return { canceled: true };
  const store = path.join(app.getPath("userData"), "marketplace.sqlite");
  return runIocUpload(["ioc-upload", "--file", picked.filePaths[0], "--store", store]);
});

function runIocUpload(args) {
  return new Promise((resolve) => {
    const child = spawn(parserBinary(), args, { cwd: app.isPackaged ? app.getPath("home") : repo });
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
          if (win) win.webContents.send("ioc-progress", { pct: Number(parts[1] || 0), label: parts.slice(2).join(" ") });
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
ipcMain.handle("iocs", (_event, caseDir) => run(["iocs", "--case", casePath(caseDir)]));
ipcMain.handle("ioc-add", (_event, caseDir, kind, value, note) => run(["ioc-add", "--case", casePath(caseDir), "--kind", kind, "--value", value, "--note", note || ""]));
ipcMain.handle("ioc-update", (_event, caseDir, id, kind, value, note) => run(["ioc-update", "--case", casePath(caseDir), "--id", String(id), "--kind", kind, "--value", value, "--note", note || ""]));
ipcMain.handle("ioc-remove", (_event, caseDir, id) => run(["ioc-remove", "--case", casePath(caseDir), "--id", String(id)]));
ipcMain.handle("pick-case-open", async () => {
  const picked = await dialog.showOpenDialog(win, {
    title: "Open Collection",
    properties: ["openDirectory"],
    buttonLabel: "Open",
  });
  if (!picked || picked.canceled || !picked.filePaths[0]) return picked;
  let dir = picked.filePaths[0];
  const parts = dir.split(path.sep);
  const mcp = parts.findIndex((part) => part.endsWith(".mcp"));
  if (mcp >= 0) dir = parts.slice(0, mcp + 1).join(path.sep);
  return { canceled: false, filePaths: [dir] };
});
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


function runHunt(args, channel = "hunt-progress") {
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
          if (win) win.webContents.send(channel, { pct: Number(parts[1] || 0), label: parts.slice(2).join(" ") });
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

ipcMain.handle("hunt", (_event, caseDir) => runHunt(["hunt", "--case", casePath(caseDir)]));
ipcMain.handle("marketplace", () => run(["marketplace", "--store", path.join(app.getPath("userData"), "marketplace.sqlite")]));
ipcMain.handle("store-key", (_event, name, key) => { try { storeKey(name, key); return { code: 0 }; } catch (err) { return { code: 1, err: err.message }; } });
ipcMain.handle("install-source", (_event, id, config) => run(["install-source", "--source", id, "--config", config || "{}", "--store", path.join(app.getPath("userData"), "marketplace.sqlite")]));
ipcMain.handle("uninstall-source", (_event, id) => {
  const file = keyFile(id);
  if (fs.existsSync(file)) fs.unlinkSync(file);
  return run(["uninstall-source", "--source", id, "--store", path.join(app.getPath("userData"), "marketplace.sqlite")]);
});
ipcMain.handle("test-source", async (_event, id) => {
  try {
    const key = loadSourceKey(id);
    if (id === "malwarebazaar") {
      const body = new URLSearchParams({ query: "get_info", hash: "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d" });
      const config = await bazaarConfig();
      const response = await bazaar.safeFetch(config.lookupEndpoint, { method: "POST", headers: { "Auth-Key": key }, body });
      const json = await response.json().catch(() => ({}));
      const state = json.query_status || (response.status === 401 || response.status === 403 || response.status === 429 ? bazaar.statusMessage(response.status) : response.status);
      return { code: response.ok ? 0 : 1, out: "MalwareBazaar: " + state };
    }
    return { code: 1, err: "No test for " + id };
  } catch (err) {
    return { code: 1, err: bazaar.redact(err.message) };
  }
});
ipcMain.handle("lookup-hash", async (_event, hash) => {
  try {
    const key = loadSourceKey("malwarebazaar");
    const body = new URLSearchParams({ query: "get_info", hash });
    const config = await bazaarConfig();
    const response = await bazaar.safeFetch(config.lookupEndpoint, { method: "POST", headers: { "Auth-Key": key }, body });
    const json = await response.json().catch(() => ({}));
    const state = json.query_status || (response.status === 429 ? bazaar.statusMessage(429) : response.status);
    const name = (json.data && json.data[0] && (json.data[0].signature || json.data[0].file_name)) || "";
    return { code: response.ok ? 0 : 1, out: state + (name ? ": " + name : "") };
  } catch (err) {
    return { code: 1, err: err.message };
  }
});
// MalwareBazaar full dump. Settings live in the hash_sources.config JSON of
// the malwarebazaar row: lookupEndpoint, exportUrl (a template with {key},
// never the key itself), onlineLookup (off by default) and onlineMax.
function marketStore() {
  return path.join(app.getPath("userData"), "marketplace.sqlite");
}

async function bazaarConfig() {
  const result = await run(["source-config", "--source", "malwarebazaar", "--store", marketStore()]);
  let parsed = {};
  try { parsed = JSON.parse(result.out || "{}") || {}; } catch (_) { parsed = {}; }
  return {
    lookupEndpoint: typeof parsed.lookupEndpoint === "string" && parsed.lookupEndpoint ? parsed.lookupEndpoint : bazaar.DEFAULT_LOOKUP_ENDPOINT,
    exportUrl: typeof parsed.exportUrl === "string" && parsed.exportUrl.includes("{key}") ? parsed.exportUrl : bazaar.DEFAULT_EXPORT_TEMPLATE,
    onlineLookup: parsed.onlineLookup === true,
    onlineMax: Math.max(0, Math.min(1000, Number(parsed.onlineMax) || 25)),
    autoUpdate: parsed.autoUpdate !== false,
  };
}

function bazaarProgress(pct, label) {
  if (win) win.webContents.send("bazaar-progress", { pct, label });
}

function notify(title, body) {
  try { if (Notification.isSupported()) new Notification({ title, body }).show(); } catch (_) { /* notifications are optional */ }
}

function parseTsv(out) {
  const info = {};
  for (const line of String(out || "").split(/\n/)) {
    const [k, ...rest] = line.split("\t");
    if (k) info[k] = rest.join("\t");
  }
  return info;
}

async function bazaarImportFile(file, label) {
  bazaarProgress(5, "Loading " + label);
  const result = await runHunt(["bazaar-import", "--file", file, "--store", marketStore()], "bazaar-progress");
  if (result.code !== 0) return { code: result.code, err: result.err };
  const counts = parseTsv(result.out);
  const info = parseTsv((await run(["bazaar-info", "--store", marketStore()])).out);
  bazaarProgress(100, "Loaded");
  return { code: 0, counts, info };
}

ipcMain.handle("bazaar-info", async () => {
  const result = await run(["bazaar-info", "--store", marketStore()]);
  const config = await bazaarConfig();
  return { code: result.code, info: parseTsv(result.out), config: { onlineLookup: config.onlineLookup, onlineMax: config.onlineMax, lookupEndpoint: config.lookupEndpoint, exportUrl: bazaar.redact(config.exportUrl) }, warning: bazaar.endpointWarning(config), err: result.err };
});

ipcMain.handle("bazaar-settings", async (_event, changes) => {
  const current = await bazaarConfig();
  const next = { ...current };
  if (changes && typeof changes.onlineLookup === "boolean") next.onlineLookup = changes.onlineLookup;
  if (changes && Number(changes.onlineMax) > 0) next.onlineMax = Math.min(1000, Math.floor(Number(changes.onlineMax)));
  // Endpoints are https only. On a refused value nothing is saved.
  const checked = bazaar.applyEndpointSettings(next, changes);
  if (checked.error) return { code: 1, err: checked.error };
  const result = await run(["install-source", "--source", "malwarebazaar", "--config", JSON.stringify(checked.next), "--store", marketStore()]);
  return { ...result, warning: bazaar.endpointWarning(checked.next) };
});

ipcMain.handle("bazaar-upload", async () => {
  const picked = await dialog.showOpenDialog(win, { properties: ["openFile"], filters: [{ name: "MalwareBazaar export", extensions: ["zip", "csv", "txt"] }] });
  if (picked.canceled || !picked.filePaths[0]) return { canceled: true };
  const result = await bazaarImportFile(picked.filePaths[0], path.basename(picked.filePaths[0]));
  if (result.code === 0) notify("MalwareBazaar dump loaded", `${result.counts.added || 0} added, ${result.counts.updated || 0} updated, ${result.counts.unchanged || 0} unchanged`);
  return result;
});

ipcMain.handle("bazaar-fetch", async () => {
  let key;
  try { key = loadSourceKey("malwarebazaar"); } catch (err) { return { code: 1, err: err.message }; }
  return bazaarFetchAndImport(key, await bazaarConfig());
});

// Shared by the Fetch recent button and the start-up update. The download
// goes to a temp file that is always deleted; the dump only changes when the
// import succeeds.
async function bazaarFetchAndImport(key, config) {
  let download;
  try {
    bazaarProgress(1, "Downloading the recent export from abuse.ch");
    download = await bazaar.fetchExport({
      template: config.exportUrl,
      key,
      dir: app.getPath("temp"),
      onProgress: (bytes) => bazaarProgress(2, `Downloaded ${(bytes / 1024 / 1024).toFixed(1)} MB`),
    });
  } catch (err) {
    debugLog("bazaar fetch failed: " + bazaar.redact(err.message, key));
    return { code: 1, err: bazaar.redact(err.message, key) };
  }
  try {
    const result = await bazaarImportFile(download.file, "recent export");
    if (result.code === 0) {
      result.fileDate = download.lastModified;
      notify("MalwareBazaar dump fetched", `${result.info.rows || 0} rows, ${result.counts.added || 0} added`);
    } else {
      result.err = bazaar.redact(result.err, key);
    }
    return result;
  } finally {
    try { fs.unlinkSync(download.file); } catch (_) { /* already gone */ }
  }
}

// Runs once per app start after the window has loaded. A reload does not run
// it again (the guard lives in bazaar-autoupdate.js in the main process).
function startupBazaarUpdate() {
  runStartupUpdate({
    isInstalled: async () => {
      const r = await run(["marketplace", "--store", marketStore()]);
      return r.code === 0 && String(r.out || "").split("\n").some((l) => { const [id, , state] = l.split("\t"); return id === "malwarebazaar" && state && state !== "not-installed"; });
    },
    loadKey: () => loadSourceKey("malwarebazaar"),
    loadConfig: bazaarConfig,
    fetchAndImport: bazaarFetchAndImport,
    redact: bazaar.redact,
    report: (payload) => { if (win) win.webContents.send("bazaar-auto", payload); },
  }).then((r) => { if (r && r.error) debugLog("bazaar auto-update: " + r.error); })
    .catch((err) => debugLog("bazaar auto-update: " + bazaar.redact(err && err.message)));
}

ipcMain.handle("bazaar-match", async (_event, caseDir) => {
  const dir = casePath(caseDir);
  if (!dir) return { code: 1, err: "Open a case first." };
  const result = await runHunt(["bazaar-match", "--case", dir, "--store", marketStore()], "bazaar-progress");
  if (result.code !== 0) return { code: result.code, err: result.err };
  const lines = parseTsv(result.out);
  const [checked, hits, unmatched, dumpRows] = (lines.counts || "").split("\t").map(Number);
  const [csv, md, unmatchedFile, runId] = (lines.report || "").split("\t");
  let online = { looked: 0, found: 0, note: "" };
  const config = await bazaarConfig();
  if (config.onlineLookup && unmatched > 0) {
    try {
      const key = loadSourceKey("malwarebazaar");
      const hashes = fs.readFileSync(unmatchedFile, "utf8").split(/\n/).filter(Boolean);
      const looked = await bazaar.lookupHashes({
        endpoint: config.lookupEndpoint, key, hashes, max: config.onlineMax,
        onProgress: (n, total) => bazaarProgress(90, `Online lookup ${n} of ${total}`),
      });
      const found = path.join(app.getPath("temp"), `mcparser-bazaar-online-${process.pid}-${Date.now()}.tsv`);
      fs.writeFileSync(found, looked.found.map((row) => row.join("\t")).join("\n"));
      const added = await run(["bazaar-online-hits", "--case", dir, "--file", found, "--csv", csv, "--md", md, "--looked-up", String(looked.looked)]);
      try { fs.unlinkSync(found); } catch (_) { /* gone */ }
      online = { looked: looked.looked, found: Number(parseTsv(added.out).online || 0), note: looked.note || (added.code ? added.err : "") };
    } catch (err) {
      online.note = err.message;
    }
  }
  const total = (hits || 0) + online.found;
  notify("MalwareBazaar match finished", `${total} hits in ${checked || 0} hashes`);
  return { code: 0, checked, hits, unmatched, dumpRows, csv, md, runId, online };
});

ipcMain.handle("open-report", (_event, file) => {
  const target = String(file || "");
  if (!/[\\/]reports[\\/]malwarebazaar-[0-9]+\.(md|csv)$/.test(target) || !fs.existsSync(target)) return { code: 1, err: "Report not found" };
  return shell.openPath(target).then((err) => ({ code: err ? 1 : 0, err }));
});

ipcMain.handle("hunt-matches", (_event, caseDir, runId) => run(["hunt-matches", "--case", casePath(caseDir), "--run", String(runId)]));

ipcMain.handle("ingest", (_event, caseDir, file) => run(["ingest", "--case", casePath(caseDir), file]));
ipcMain.handle("choose-case-target", async (_event, current) => dialog.showMessageBox(win, { type: "question", message: "Do you want to import this file to the existing case?", detail: current, buttons: ["Import to this case", "New case", "Cancel"], defaultId: 0, cancelId: 2 }));
ipcMain.handle("save-analyst", (_event, caseDir, name) => run(["save-analyst", "--case", casePath(caseDir), "--name", name]));
// Paged hex view: bounded reads from the last picked PE file only.
let peFile = "";
let peCaseSha = "";
ipcMain.handle("pe-read-range", (_event, offset, length) => peRange.readRange(peFile, offset, length));
// Parse-only PE analysis. The file is read by the parser, never run or loaded.
ipcMain.handle("pe-analyze", async (_event, caseDir) => {
  const picked = await dialog.showOpenDialog(win, { title: "Analyze PE file", properties: ["openFile"] });
  if (picked.canceled || !picked.filePaths.length) return { code: 0, out: "", canceled: true };
  peFile = picked.filePaths[0];
  peCaseSha = "";
  const args = ["pe", "--file", picked.filePaths[0], "--json", "--store", path.join(app.getPath("userData"), "marketplace.sqlite")];
  if (caseDir) args.push("--case", casePath(caseDir));
  return run(args);
});
// Reopen a saved PE analysis from the case tables (read-only SELECTs). The
// file is only made readable for hex after its sha256 matches the row.
ipcMain.handle("pe-case-report", async (_event, caseDir, target) => {
  let qs;
  try { qs = peCase.queries(target); } catch { return { code: 1, err: "Not a valid sha256" }; }
  const rows = { _failed: [] };
  for (const [k, q] of Object.entries(qs)) {
    const res = await run(["query", "--case", casePath(caseDir), "--format", "jsonl", q]);
    if (res.code !== 0 && k === "files") return { code: 1, err: res.err || res.out || "Query failed" };
    if (res.code !== 0) rows._failed.push(k);
    rows[k] = res.code === 0 ? peCase.parseJsonl(res.out) : [];
  }
  const report = peCase.buildReport(rows);
  if (!report) return { code: 1, err: "No saved PE analysis for this row in the case" };
  peFile = "";
  peCaseSha = target.sha256.toLowerCase();
  if (report.path && await peRange.fileMatches(report.path, peCaseSha)) peFile = report.path;
  return { code: 0, report, hexReady: Boolean(peFile) };
});
ipcMain.handle("pe-locate", async () => {
  if (!peCaseSha) return { ok: false, error: "No saved PE analysis is open" };
  const picked = await dialog.showOpenDialog(win, { title: "Locate the analysed file", properties: ["openFile"] });
  if (picked.canceled || !picked.filePaths.length) return { ok: false };
  if (!(await peRange.fileMatches(picked.filePaths[0], peCaseSha))) return { ok: false, error: "That file's SHA256 does not match this analysis." };
  peFile = picked.filePaths[0];
  return { ok: true };
});
ipcMain.handle("collections", (_event, caseDir) => run(["collections", "--case", casePath(caseDir)]));
ipcMain.handle("prefetch", (_event, caseDir) => run(["prefetch", "--case", casePath(caseDir)]));
ipcMain.handle("query", async (_event, caseDir, sql) => {
  const result = await run(["query", "--case", casePath(caseDir), "--format", "csv", "--store", path.join(app.getPath("userData"), "marketplace.sqlite"), sql]);
  if (result.code !== 0 && /malwarebazaar\b(?!_full)/i.test(sql) && /column|Binder/i.test(result.err || result.out || "")) {
    result.err = (result.err || result.out || "") + "\nmalwarebazaar has six columns: sha256, sha1, md5, signature, file_name, first_seen. Use malwarebazaar_full for more columns.";
  }
  return result;
});
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
ipcMain.handle("set-model", (_event, name, model) => {
  if (models[name] && model) models[name] = model;
  return grokStatus();
});
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
ipcMain.handle("grok-forget-one", (_event, name) => {
  if (name === "grok" || name === "claude" || name === "openai") forgetOne(name);
  buildMenu();
  return grokStatus();
});
ipcMain.handle("grok-ask", (_event, caseDir, question, name) => {
  if (name === "grok" || name === "claude" || name === "openai") provider = name;
  return grokAsk(caseDir, question);
});
ipcMain.handle("queries", (_event, caseDir) => run(["queries", "--case", casePath(caseDir)]));
ipcMain.handle("save-query", (_event, caseDir, name, sql) => run(["save-query", "--case", casePath(caseDir), "--name", name, sql]));
ipcMain.handle("save-sql-file", async (_event, caseDir, suggested, sql) => {
  const dir = casePath(caseDir);
  const name = String(suggested || "query.sql");
  const picked = await dialog.showSaveDialog(win, {
    title: "Save query",
    defaultPath: path.join(dir, name.endsWith(".sql") ? name : name + ".sql"),
    filters: [{ name: "SQL", extensions: ["sql"] }],
  });
  if (picked.canceled || !picked.filePath) return { saved: false };
  fs.writeFileSync(picked.filePath, String(sql || ""), "utf8");
  return { saved: true, path: picked.filePath };
});
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
