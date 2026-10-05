function showSheet(grokState) {
  keyHint.textContent = grokState.connected
    ? `A key is set, ending ${grokState.last4}. Save replaces it.`
    : "The key is encrypted with the macOS keychain.";
  keyInput.value = "";
  sheet.hidden = false;
  keyInput.focus();
}

function hideSheet() {
  keyInput.value = "";
  sheet.hidden = true;
}

sql.addEventListener("input", updateLines);
sql.addEventListener("scroll", () => {
  lines.scrollTop = sql.scrollTop;
});
document.getElementById("refresh").onclick = refresh;
document.getElementById("run").onclick = run;
document.getElementById("export").onclick = exportCsv;
document.getElementById("key-cancel").onclick = hideSheet;
document.getElementById("key-form").onsubmit = async (event) => {
  event.preventDefault();
  const saved = await window.mcparser.grokSave(keyInput.value);
  hideSheet();
  if (saved.error) {
    note(saved.error);
    return;
  }
  if (saved.connected) {
    grok.hidden = false;
    note("Grok connected. Ask about this case.");
  }
};
