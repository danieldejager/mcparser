// IPC sender check: only the main window's top frame may call the main
// process. Matches the theme-mode listener's event.sender check and also
// rejects calls from subframes.

function sameFrame(a, b) {
  if (!a || !b) return false;
  if (a === b) return true;
  return a.processId === b.processId && a.routingId === b.routingId;
}

// True when event came from win's webContents and its main frame.
function isTrustedSender(event, win) {
  if (!event || !win) return false;
  if (typeof win.isDestroyed === "function" && win.isDestroyed()) return false;
  const wc = win.webContents;
  if (!wc || event.sender !== wc) return false;
  return sameFrame(event.senderFrame, wc.mainFrame);
}

// Wraps an ipcMain.handle callback. getWin returns the current main window.
function guard(channel, getWin, fn) {
  return (event, ...args) => {
    if (!isTrustedSender(event, getWin())) {
      throw new Error(`IPC "${channel}" refused: caller is not the McParser main window`);
    }
    return fn(event, ...args);
  };
}

module.exports = { isTrustedSender, guard };
