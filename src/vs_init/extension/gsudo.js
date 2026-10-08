// First-class gsudo support for the extension -- deliberately separate
// from the bootstrap tool's own winsudo.py (see PLAN.md's "Note:
// gsudo"). winsudo.py only ever makes one elevated call per run, so it
// doesn't manage gsudo's cache at all and just eats one UAC prompt per
// call. This extension is a long-running session instead, where more
// than one elevated action is plausible (e.g. repeated Request Cert
// runs), so it's worth enabling gsudo's own credentials cache once and
// reusing it instead of prompting every time.

const { execFile } = require("child_process");

// gsudo's own default idle cache window is 5 minutes; this resets on
// each use, so it's a ceiling on idle time between privileged actions
// within one VS Code session, not a hard session length.
const CACHE_DURATION = "01:00:00";

function execFileAsync(command, args) {
  return new Promise((resolve, reject) => {
    execFile(command, args, (err, stdout, stderr) => {
      if (err) {
        reject(Object.assign(err, { stdout, stderr }));
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

let cacheReady = null;

/** Enables gsudo's credentials cache, scoped to this extension host's
 * own process (process.pid) -- it's the one long-lived process for the
 * whole VS Code session, so (unlike winsudo.py's short-lived CLI
 * invocation) no ancestor-process walking is needed to find something
 * longer-lived to scope to. Idempotent: only actually invokes gsudo
 * once per extension host lifetime; concurrent callers share the same
 * in-flight promise. A failed attempt resets state so a later call can
 * retry instead of being stuck failing forever. */
function ensureCache() {
  if (!cacheReady) {
    cacheReady = execFileAsync("gsudo", [
      "--loglevel", "Error", "cache", "on",
      "-p", String(process.pid), "-d", CACHE_DURATION,
    ]).catch((err) => {
      cacheReady = null;
      throw new Error(`Enabling the gsudo cache failed: ${err.message}`);
    });
  }
  return cacheReady;
}

module.exports = { ensureCache, CACHE_DURATION };
