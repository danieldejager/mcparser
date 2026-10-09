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

async function grokAsk(caseDir, question) {
  if (!activeKey()) return { error: "Configure this integration.", provider };
  try {
    const stats = await run(["stats", "--case", casePath(caseDir)]);
    const schema = "events(source_sha256, record_id, event_id, channel, provider, computer, time_created, event_data). event_data is JSON. Filter a field with json_extract_string(event_data, '$.TargetUserName').";
    const sqlText = await askModel(
      "Return one DuckDB SELECT and no other text. " + schema +
      " Case stats:\n" + clip(stats.out || "") +
      "\nQuestion: " + question
    );
    const sql = oneSelect(sqlText);
    const queried = await run(["query", "--case", casePath(caseDir), "--format", "csv", sql]);
    if (queried.code !== 0) return { error: queried.err || queried.out || "query failed", sql, provider };
    const answer = await askModel(
      "Answer the question from these rows only. Do not invent rows.\nQuestion: " + question +
      "\nSQL: " + sql +
      "\nRows:\n" + clip(queried.out || "")
    );
    return { sql, answer, provider };
  } catch (error) {
    return { error: error.message, provider };
  }
}

async function openEvtx() {
  const picked = await dialog.showOpenDialog(win, {
    title: "Open Windows event log",
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
        { label: "New Case...", click: () => win.webContents.send("new-case") },
        { label: "Open Case...", accelerator: "CmdOrCtrl+O", click: () => win.webContents.send("open-case") },
        { label: "Delete Case...", click: () => win.webContents.send("delete-case") },
        { type: "separator" },
        { label: "Open EVTX...", click: openEvtx },
        { label: "Import Collection...", click: () => win.webContents.send("import-collection") },
        { label: "Export handoff...", click: () => win.webContents.send("export-handoff") },
        { label: "Open handoff...", click: () => win.webContents.send("open-handoff") },
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
ipcMain.handle("collect", (_event, caseDir, file, analyst) => run(["collect", "--case", casePath(caseDir), "--analyst", analyst || "", file]));
ipcMain.handle("ingest", (_event, caseDir, file) => run(["ingest", "--case", casePath(caseDir), file]));
ipcMain.handle("choose-case-target", async (_event, current) => dialog.showMessageBox(win, { type: "question", message: "Do you want to import this file to the existing case?", detail: current, buttons: ["Import to this case", "New case", "Cancel"], defaultId: 0, cancelId: 2 }));
ipcMain.handle("save-analyst", (_event, caseDir, name) => run(["save-analyst", "--case", casePath(caseDir), "--name", name]));
ipcMain.handle("collections", (_event, caseDir) => run(["collections", "--case", casePath(caseDir)]));
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
