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
ipcMain.handle("grok-ask", (_event, caseDir, question) => grokAsk(caseDir, question));
