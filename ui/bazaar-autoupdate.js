// Start-up refresh of the MalwareBazaar dump. Pure Node with every side
// effect injected so it can be tested without Electron. It runs at most once
// per process, does nothing (and says nothing) when the card is not installed,
// and never touches the dump unless the download and import both succeed.
let started = false;

function errorText(message) {
  const m = String(message || "");
  if (/No key is stored/i.test(m)) return "no key is stored on the MalwareBazaar card";
  if (/fetch failed|ENOTFOUND|ECONNREFUSED|EAI_AGAIN|ENETUNREACH|ETIMEDOUT/i.test(m)) return "offline or abuse.ch is unreachable";
  return m;
}

// deps: isInstalled() -> bool, loadKey() -> key (throws when none),
// loadConfig() -> { autoUpdate }, fetchAndImport(key, config) -> { code, counts, info, err },
// report({ phase, text }), redact(text, key).
async function runStartupUpdate(deps, state) {
  const guard = state || { get started() { return started; }, set started(v) { started = v; } };
  if (guard.started) return { skipped: "already-ran" };
  guard.started = true;
  let installed = false;
  try { installed = await deps.isInstalled(); } catch (_) { installed = false; }
  if (!installed) return { skipped: "not-installed" };
  const config = (await deps.loadConfig()) || {};
  if (config.autoUpdate === false) return { skipped: "disabled" };
  let key;
  try { key = await deps.loadKey(); } catch (_) { key = ""; }
  if (!key) return { skipped: "no-key" };
  const redact = deps.redact || ((t) => String(t));
  deps.report({ phase: "start", text: "Updating MalwareBazaar....." });
  let result;
  try {
    result = await deps.fetchAndImport(key, config);
  } catch (err) {
    result = { code: 1, err: err && err.message };
  }
  if (!result || result.code !== 0) {
    const text = "MalwareBazaar update failed: " + redact(errorText(result && result.err), key) + ". The existing dump was kept.";
    deps.report({ phase: "error", text });
    return { error: text };
  }
  const c = result.counts || {};
  const newest = (result.info && result.info.newest_first_seen) || "unknown";
  const text = `MalwareBazaar updated: ${c.added || 0} added, ${c.updated || 0} updated, ${c.unchanged || 0} unchanged, newest sample ${newest}`;
  deps.report({ phase: "done", text });
  return { ok: true, text };
}

module.exports = { runStartupUpdate, errorText };
