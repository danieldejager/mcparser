const { app, BrowserWindow, ipcMain, dialog, Menu, nativeImage, shell } = require("electron");
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
let chatShown = false;

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

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(parserBinary(), args, { cwd: app.isPackaged ? app.getPath("home") : repo });
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
  return { connected: grokKey.length > 0, last4: grokKey.slice(-4) };
}

async function openEvtx() {
  const picked = await dialog.showOpenDialog(win, {
    title: "Open Windows event log",
    properties: ["openFile"],
    filters: [{ name: "Windows Event Log", extensions: ["evtx"] }],
  });
  if (picked.canceled || !picked.filePaths[0]) return;
  const file = picked.filePaths[0];
  const caseDir = file.replace(/\.evtx$/i, "") + ".mcp";
  const result = await run(["ingest", "--case", caseDir, file]);
  win.webContents.send("opened", { file, caseDir, ...result });
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
  const connected = grokKey.length > 0;
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
        { label: "Open EVTX...", accelerator: "CmdOrCtrl+O", click: openEvtx },
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
      label: "Window",
      submenu: [
        { role: "minimize" },
        { role: "zoom" },
        { type: "separator" },
        { role: "front" },
      ],
    },
    {
      label: "Grok",
      submenu: [
        {
          label: connected ? "Grok connected" : "Connect Grok...",
          click: () => win.webContents.send("grok-connect"),
        },
        {
          label: "Forget key",
          enabled: connected,
          click: () => {
            grokKey = "";
            chatShown = false;
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
}

ipcMain.handle("stats", (_event, caseDir) => run(["stats", "--case", caseDir]));
ipcMain.handle("query", (_event, caseDir, sql) => run(["query", "--case", caseDir, "--format", "csv", sql]));
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
ipcMain.handle("grok-save", (_event, key) => {
  grokKey = String(key || "").trim();
  chatShown = grokKey.length > 0;
  buildMenu();
  return grokStatus();
});
ipcMain.handle("grok-forget", () => {
  grokKey = "";
  chatShown = false;
  buildMenu();
  return grokStatus();
});

app.whenReady().then(() => {
  const icon = appIcon();
  if (icon && app.dock) app.dock.setIcon(icon);
  buildMenu();
  createWindow();
});
app.on("window-all-closed", () => app.quit());
