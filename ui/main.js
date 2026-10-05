const { app, BrowserWindow, ipcMain } = require("electron");
const { spawn } = require("child_process");
const path = require("path");

const repo = path.resolve(__dirname, "..");
const binary = path.join(repo, "target/debug/mcparser");

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

function createWindow() {
  const win = new BrowserWindow({
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

app.whenReady().then(createWindow);
app.on("window-all-closed", () => app.quit());
