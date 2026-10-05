const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

if (process.platform !== "darwin") process.exit(0);

const plist = path.join(__dirname, "node_modules/electron/dist/Electron.app/Contents/Info.plist");
if (!fs.existsSync(plist)) process.exit(0);

for (const key of ["CFBundleName", "CFBundleDisplayName"]) {
  execFileSync("/usr/libexec/PlistBuddy", ["-c", `Set :${key} McParser`, plist]);
}
