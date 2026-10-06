const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("mcparser", {
  stats: (caseDir) => ipcRenderer.invoke("stats", caseDir),
  query: (caseDir, sql) => ipcRenderer.invoke("query", caseDir, sql),
  saveCsv: (csv) => ipcRenderer.invoke("save-csv", csv),
  queries: (caseDir) => ipcRenderer.invoke("queries", caseDir),
  saveQuery: (caseDir, name, sql) => ipcRenderer.invoke("save-query", caseDir, name, sql),
  notes: (caseDir) => ipcRenderer.invoke("notes", caseDir),
  saveNote: (caseDir, recordId, body) => ipcRenderer.invoke("save-note", caseDir, recordId, body),
  grokStatus: () => ipcRenderer.invoke("grok-status"),
  grokSave: (key) => ipcRenderer.invoke("grok-save", key),
  grokForget: () => ipcRenderer.invoke("grok-forget"),
  grokAsk: (caseDir, question) => ipcRenderer.invoke("grok-ask", caseDir, question),
  onOpened: (handler) => ipcRenderer.on("opened", (_event, payload) => handler(payload)),
  onGrokConnect: (handler) => ipcRenderer.on("grok-connect", () => handler()),
  onGrokChat: (handler) => ipcRenderer.on("grok-chat", (_event, shown) => handler(shown)),
  onGrokStatus: (handler) => ipcRenderer.on("grok-status", (_event, status) => handler(status)),
});
