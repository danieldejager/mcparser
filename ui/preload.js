const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("mcparser", {
  stats: (caseDir) => ipcRenderer.invoke("stats", caseDir),
  query: (caseDir, sql) => ipcRenderer.invoke("query", caseDir, sql),
  saveCsv: (csv) => ipcRenderer.invoke("save-csv", csv),
  onOpened: (handler) => ipcRenderer.on("opened", (_event, payload) => handler(payload)),
});
