function parserBinary() {
  const name = process.platform === "win32" ? "mcparser.exe" : "mcparser";
  const profile = app.isPackaged ? "release" : "debug";
  if (app.isPackaged) return path.join(process.resourcesPath, name);
  return path.join(repo, "target", profile, name);
}