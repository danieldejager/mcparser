const { app, BrowserWindow, ipcMain, dialog, Menu } = require("electron");
const { spawn } = require("child_process");
const path = require("path");

const repo = path.resolve(__dirname, "..");
const binary = path.join(repo, "target/debug/mcparser");
let win;

function run(args) {
  return new Promise((resolve) => {
    const child = spawn(binary, args, { cwd: repo });
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

function buildMenu() {
  const template = [
    {
      label: "File",
      submenu: [
        { label: "Open EVTX...", accelerator: "CmdOrCtrl+O", click: openEvtx },
        { type: "separator" },
        { role: "quit" },
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
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function createWindow() {
  win = new BrowserWindow({
    width: 1200,
    height: 760,
    title: "McParser",
    backgroundColor: "#f3f3f3",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
    },
  });
  win.loadFile("index.html");
}

ipcMain.handle("stats", (_event, caseDir) => run(["stats", "--case", caseDir]));
ipcMain.handle("query", (_event, caseDir, sql) => run(["query", "--case", caseDir, "--format", "csv", sql]));

app.whenReady().then(() => {
  buildMenu();
  createWindow();
});
app.on("window-all-closed", () => app.quit());
