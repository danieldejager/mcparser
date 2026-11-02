// Window options per platform. On macOS the app opens fullscreen and the
// menu lives in the global menu bar. On Linux and Windows fullscreen hides
// the native frame (minimise, maximise, close) and the in-window menu bar,
// so open a framed, maximised window instead.
function windowOptions(platform) {
  const mac = platform === "darwin";
  return { fullscreen: mac, frame: true, autoHideMenuBar: false, maximize: !mac };
}

module.exports = { windowOptions };
