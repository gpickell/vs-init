const fs = require("fs");
const path = require("path");
const os = require("os");
const { spawn } = require("child_process");

// Ported from vss-prime's agolregister.py / the parked
// experiments/agol-bootstrap/ spike (see its MEMO.md for the full
// design rationale and decision log) -- this is the one piece of that
// whole effort actually confirmed working end-to-end against a real
// portal. The app-registration REST calls that consume this token are
// a separate, NOT-yet-ported, NOT-yet-verified piece (see MEMO.md:
// field names in that response were never confirmed against a real
// portal either).
//
// Launching/driving Edge goes through child_process.spawn directly,
// not TaskExecutor.executeOnSystem -- that method's contract is "run a
// command to completion and stream its output", which doesn't fit a
// browser we deliberately keep alive, talk to live over CDP, and close
// ourselves once we're done with it.

const EDGE_DEBUG_PORT = 9222;
// ~/.vs-init is now a real directory (vs_init/settings.py migrates it
// from the old flat-file layout automatically), so this no longer
// collides with the main tool's own settings.json living there too.
const EDGE_PROFILE_DIR = path.join(os.homedir(), ".vs-init", "edge");

// Home's own self-identifying call. Confirmed in vss-prime to always
// carry the signed-in user's real token in its query string,
// regardless of how they actually authenticated (built-in, SAML, OIDC,
// SSO) -- nothing has to be asked up front, the user just logs in
// wherever their portal actually sends them.
const SELF_CALL_MARKER = "/sharing/rest/portals/self";

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Pure. Extracts the token from a portals/self URL, or null if this
 * isn't that call (most network traffic isn't) or it has no token. */
function matchToken(url) {
  if (!url || !url.includes(SELF_CALL_MARKER)) {
    return null;
  }
  try {
    return new URL(url).searchParams.get("token");
  } catch {
    return null;
  }
}

function findEdge() {
  const candidates = [
    path.join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "Microsoft", "Edge", "Application", "msedge.exe"),
    path.join(process.env.ProgramFiles || "C:\\Program Files", "Microsoft", "Edge", "Application", "msedge.exe"),
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error("msedge.exe not found");
}

/** Launches Edge against our own persistent, never-cleaned-up profile
 * (EDGE_PROFILE_DIR -- reusing it lets logins/cookies carry over
 * between runs) with the CDP flags vss-prime found necessary:
 * --remote-debugging-port to expose the DevTools protocol at all, and
 * --remote-allow-origins=* specifically because Chromium 403s the
 * DevTools WebSocket without it (an Origin check with no exception for
 * a bare debugging client). */
function launchEdge(startUrl) {
  fs.mkdirSync(EDGE_PROFILE_DIR, { recursive: true });
  const edge = findEdge();
  const args = [
    `--remote-debugging-port=${EDGE_DEBUG_PORT}`,
    `--user-data-dir=${EDGE_PROFILE_DIR}`,
    "--no-first-run",
    "--no-default-browser-check",
    "--remote-allow-origins=*",
    startUrl,
  ];
  return spawn(edge, args, { stdio: "ignore" });
}

/** Connects to a CDP WebSocket URL, retrying for up to `timeoutMs` --
 * a page target can show up in /json/list slightly before its
 * WebSocket debugger actually accept()s connections. */
function connectWebSocket(wsUrl, timeoutMs) {
  return new Promise((resolve, reject) => {
    const deadline = Date.now() + timeoutMs;

    function attempt() {
      const ws = new WebSocket(wsUrl);
      const cleanup = () => {
        ws.removeEventListener("open", onOpen);
        ws.removeEventListener("error", onError);
      };
      function onOpen() {
        cleanup();
        resolve(ws);
      }
      function onError() {
        cleanup();
        if (Date.now() >= deadline) {
          reject(new Error(`Could not connect to ${wsUrl}`));
        } else {
          setTimeout(attempt, 300);
        }
      }
      ws.addEventListener("open", onOpen);
      ws.addEventListener("error", onError);
    }

    attempt();
  });
}

/** The page target matching `urlPrefix` -- matched by URL, not just
 * "the first page", so a profile dir with other tabs already open from
 * a previous run can't pick the wrong one. */
async function findPageTarget(urlPrefix, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${EDGE_DEBUG_PORT}/json/list`);
      const targets = await response.json();
      const match = targets.find((t) => t.type === "page" && typeof t.url === "string" && t.url.startsWith(urlPrefix));
      if (match) {
        return match;
      }
    } catch (err) {
      lastError = err;
    }
    await delay(200);
  }
  throw new Error(`No page target matching ${urlPrefix}: ${lastError}`);
}

/** Opens the page's DevTools WebSocket, enables Network, *then*
 * navigates to `navigateTo` ourselves via CDP's Page.navigate -- in
 * that order, deliberately. Letting the browser navigate to the portal
 * on its own (e.g. via an HTTP redirect) before we're connected and
 * watching is a real race: Home's self-identifying portals/self call
 * only fires once, on that page's initial load, and if login completes
 * fast it can happen before our WebSocket handshake + Network.enable
 * finish -- confirmed in practice (the browser can land cleanly on a
 * signed-in page while this sits waiting forever, having missed the
 * one call it was listening for). Driving the navigation from inside
 * here, after Network is already enabled, makes that ordering
 * impossible instead of merely unlikely. Rejects if `signal` aborts
 * first. */
function watchForToken(wsUrl, navigateTo, signal) {
  return new Promise((resolve, reject) => {
    let ws;
    const onAbort = () => {
      cleanup();
      reject(new Error("Cancelled"));
    };
    function cleanup() {
      signal?.removeEventListener("abort", onAbort);
      try {
        ws?.close();
      } catch {
        // already closed/closing
      }
    }

    signal?.addEventListener("abort", onAbort);

    connectWebSocket(wsUrl, 10000)
      .then((socket) => {
        ws = socket;
        // connectWebSocket already consumed this socket's one-shot "open"
        // event internally (that's precisely why its promise resolved) --
        // registering another "open" listener here would never fire, so
        // send directly instead.
        ws.send(JSON.stringify({ id: 1, method: "Network.enable" }));
        ws.send(JSON.stringify({ id: 2, method: "Page.navigate", params: { url: navigateTo } }));
        ws.addEventListener("message", (event) => {
          const message = JSON.parse(event.data);
          if (message.method !== "Network.requestWillBeSent") {
            return;
          }
          const token = matchToken(message.params?.request?.url);
          if (token) {
            cleanup();
            resolve(token);
          }
        });
        ws.addEventListener("error", () => {
          cleanup();
          reject(new Error("CDP WebSocket error"));
        });
      })
      .catch((err) => {
        cleanup();
        reject(err);
      });
  });
}

function waitForExit(childProcess, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("timed out waiting for Edge to exit")), timeoutMs);
    childProcess.once("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

/** Asks Chromium to shut down via Browser.close over the browser-level
 * WebSocket (distinct from a page's) -- the same path a user closing
 * the window triggers -- rather than a hard kill(), so it exits
 * cleanly instead of looking crashed. Known unresolved wrinkle,
 * inherited from vss-prime's own spike: Browser.close does give a
 * clean process exit, but the profile's own Preferences file still
 * records exit_type as "Crashed" afterward regardless -- never
 * actually confirmed whether that produces a visible "restore pages?"
 * prompt on the next launch. Falls back to a hard kill if the graceful
 * path fails for any reason. */
async function closeEdgeGracefully(childProcess) {
  try {
    const response = await fetch(`http://127.0.0.1:${EDGE_DEBUG_PORT}/json/version`);
    const { webSocketDebuggerUrl } = await response.json();
    const ws = await connectWebSocket(webSocketDebuggerUrl, 3000);
    ws.send(JSON.stringify({ id: 1, method: "Browser.close" }));
    ws.close();
    await waitForExit(childProcess, 5000);
    return;
  } catch {
    // fall through to a hard kill
  }
  childProcess.kill();
}

/** Captures an ArcGIS Portal token: starts a local server that just
 * serves a static "ready" page -- deliberately *not* a redirect to
 * `portalUrl` (see watchForToken's comment for why) -- whose only job
 * is to prove Edge's initial tab made a real round-trip (a far more
 * reliable readiness signal than polling /json/list or guessing the
 * WebSocket debugger is up yet). Launches Edge pointed at it, finds
 * that tab, then lets watchForToken itself drive the actual navigation
 * to the portal once it's already connected and listening. `executor`
 * supplies writeLine for progress and openServer/signal for the server
 * and cancellation. */
async function captureAgolToken(executor, portalUrl) {
  let settleReady;
  const ready = new Promise((resolve) => {
    settleReady = resolve;
  });

  const server = await executor.openServer({
    port: 0,
    host: "127.0.0.1",
    handler: (req, res) => {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end("");
      settleReady();
    },
  });

  const { port } = server.address();
  const startUrl = `http://127.0.0.1:${port}/`;

  executor.writeLine("Launching Edge...");
  const edgeProcess = launchEdge(startUrl);

  try {
    await ready;
    const page = await findPageTarget(startUrl);
    executor.writeLine(`Sign in to ${portalUrl} in the window that opens...`);
    const token = await watchForToken(page.webSocketDebuggerUrl, portalUrl, executor.signal);
    executor.writeLine("Captured token; closing the browser...");
    return token;
  } finally {
    server.close();
    await closeEdgeGracefully(edgeProcess);
  }
}

module.exports = { captureAgolToken, matchToken, EDGE_PROFILE_DIR };
