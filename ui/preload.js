const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("mcparser", {
  stats: (caseDir) => ipcRenderer.invoke("stats", caseDir),
  query: (caseDir, sql) => ipcRenderer.invoke("query", caseDir, sql),
});
