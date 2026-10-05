const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

if (process.platform !== "darwin") process.exit(0);

const appPath = path.join(__dirname, "node_modules/electron/dist/Electron.app");
const plist = path.join(appPath, "Contents/Info.plist");
if (!fs.existsSync(plist)) {
  console.error("Electron.app was not found");
  process.exit(0);
}

function setKey(key) {
  try {
    execFileSync("/usr/libexec/PlistBuddy", ["-c", `Set :${key} McParser`, plist], { stdio: "ignore" });
  } catch {
    execFileSync("/usr/libexec/PlistBuddy", ["-c", `Add :${key} string McParser`, plist], { stdio: "ignore" });
  }
}

setKey("CFBundleName");
setKey("CFBundleDisplayName");
const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
execFileSync(lsregister, ["-f", appPath], { stdio: "ignore" });
console.log("bundle name set to McParser");
