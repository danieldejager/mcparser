document.getElementById("key-form").onsubmit = async (event) => {
  event.preventDefault();
  const saved = await window.mcparser.grokSave(keyInput.value);
  hideSheet();
  if (saved.connected) {
    grok.hidden = false;
    note("Grok connected. Ask about this case.");
  }
};
document.getElementById("send").onclick = async () => {
  const question = ask.value.trim();
  if (!question) return;
  if (!confirmed) {
    const ok = window.confirm("Row text from this case will leave the machine. The case file stays here.");
    if (!ok) return;
    confirmed = true;
  }
  note(question);
  ask.value = "";
  const result = await window.mcparser.grokAsk(caseDir(), question);
  if (result.error) {
    note(result.error);
    return;
  }
  note(result.sql);
  const runSql = document.createElement("button");
  runSql.textContent = "Run";
  runSql.onclick = () => {
    sql.value = result.sql;
    updateLines();
    run();
  };
  transcript.append(runSql);
  note(result.answer);
};
