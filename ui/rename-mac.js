const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");

if (process.platform !== "darwin") process.exit(0);

const NAME = "McParser";
const electronDir = path.join(__dirname, "node_modules/electron");
const appPath = path.join(electronDir, "dist/Electron.app");
const plist = path.join(appPath, "Contents/Info.plist");
const macosDir = path.join(appPath, "Contents/MacOS");
if (!fs.existsSync(plist)) {
  console.error("Electron.app was not found");
  process.exit(0);
}

function setKey(key, value = NAME) {
  try {
    execFileSync("/usr/libexec/PlistBuddy", ["-c", `Set :${key} ${value}`, plist], { stdio: "ignore" });
  } catch {
    execFileSync("/usr/libexec/PlistBuddy", ["-c", `Add :${key} string ${value}`, plist], { stdio: "ignore" });
  }
}

// The Dock label comes from the running executable's name, so renaming the
// bundle name alone is not enough: rename the executable too and point the
// plist and electron's path.txt at it. Safe to run again after `npm install`
// restores the original Electron.app.
const original = path.join(macosDir, "Electron");
const renamed = path.join(macosDir, NAME);
if (fs.existsSync(original) && !fs.existsSync(renamed)) {
  fs.renameSync(original, renamed);
}
if (fs.existsSync(renamed)) {
  setKey("CFBundleExecutable");
  fs.writeFileSync(
    path.join(electronDir, "path.txt"),
    `Electron.app/Contents/MacOS/${NAME}`
  );
}

setKey("CFBundleName");
setKey("CFBundleDisplayName");
// A distinct identifier stops the Dock reusing the label it cached for the
// stock Electron app (com.github.Electron).
setKey("CFBundleIdentifier", "com.danieldejager.mcparser.dev");

// Changing the bundle invalidates its signature; re-sign it ad hoc so macOS
// still launches it.
try {
  execFileSync("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", appPath], { stdio: "ignore" });
} catch {
  console.error("codesign failed; the app may not launch");
}

const lsregister = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
execFileSync(lsregister, ["-f", appPath], { stdio: "ignore" });
console.log("bundle name and executable set to McParser");
