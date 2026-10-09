const vscode = require("vscode");
const { spawn } = require("child_process");
const http = require("http");

/** Pure. A pty's "\n" only moves the cursor down a row, not back to
 * column 0 -- real terminals (and VS Code's Pseudoterminal) need "\r\n"
 * for an actual line break. Normalizes any newline style to that. */
function toCrlf(text) {
  return text.replace(/\r\n|\r|\n/g, "\r\n");
}

/** Shared by executeOnSystem/captureOnSystem: spawns `command`, either
 * directly or (gsudo: true) wrapped as `gsudo <command> <args...>`,
 * streaming raw stdout/stderr into the task's terminal as it arrives
 * either way. `collect`, if passed, also accumulates the combined
 * stdout+stderr text, returned alongside the exit code -- for callers
 * that need to parse a command's own output, not just know its exit
 * code. Killed automatically on `signal` abort; rejects if the process
 * itself couldn't start. */
function spawnForExecutor({ command, args = [], cwd, env, gsudo = false, write, signal, collect = false }) {
  const launch = () =>
    new Promise((resolve, reject) => {
      const spawnCommand = gsudo ? "gsudo" : command;
      const spawnArgs = gsudo ? [command, ...args] : args;
      const child = spawn(spawnCommand, spawnArgs, {
        cwd,
        env: env ? { ...process.env, ...env } : undefined,
        signal,
      });
      let output = "";
      const onChunk = (chunk) => {
        const text = chunk.toString();
        write(toCrlf(text));
        if (collect) {
          output += text;
        }
      };
      child.stdout.on("data", onChunk);
      child.stderr.on("data", onChunk);
      child.on("error", reject);
      child.on("close", (code) => resolve(collect ? { code: code === null ? -1 : code, output } : code === null ? -1 : code));
    });

  return launch();
}

/** Passed into every task action. Extends AbortController so
 * cancellation is one standard signal instead of a different hand-
 * rolled "if the user closes this, clean up that" callback per
 * feature: executeTask() calls abort() when its terminal tab closes,
 * and every method here (and anything an action wires to `.signal`
 * itself) tears down the same way. */
class TaskExecutor extends AbortController {
  constructor(write) {
    super();
    this._write = write;
  }

  /** Appends one line (plus its own "\r\n") to the task's terminal. */
  writeLine(text) {
    this._write(toCrlf(text) + "\r\n");
  }

  /** Runs `command` locally (on this Windows machine) via
   * child_process.spawn, streaming its raw stdout/stderr into the
   * task's terminal as it arrives -- not line-buffered, so ANSI escape
   * sequences (colors, cursor moves) from a real CLI tool render
   * correctly instead of being mangled by naive line-splitting.
   * Resolves with the real exit code; rejects if the process itself
   * couldn't start. Killed automatically if the executor is aborted.
   *
   * `gsudo: true` runs it elevated instead, via gsudo -- a first-class
   * option here rather than something each action wires up by hand.
   * gsudo is left entirely at its own default (Explicit cache mode, no
   * app-managed caching -- see PLAN.md's "Note: gsudo"), so every
   * elevated call prompts independently unless the user has configured
   * gsudo's own caching for themselves outside of vs-init. */
  executeOnSystem({ command, args = [], cwd, env, gsudo = false }) {
    return spawnForExecutor({ command, args, cwd, env, gsudo, write: this._write, signal: this.signal });
  }

  /** Like executeOnSystem, but also buffers the command's combined
   * stdout+stderr and resolves with `{ code, output }` instead of just
   * the exit code -- for commands whose own output needs parsing (e.g.
   * `certutil -dump`, `certreq`), not just their exit code. Output is
   * still streamed live into the task's terminal as it arrives, same
   * as executeOnSystem; this only adds buffering on top. Never throws
   * on a nonzero exit code on its own -- certreq in particular uses
   * nonzero exits for legitimate non-error dispositions (e.g. a
   * request taken under submission on a non-synchronous CA), so the
   * caller has to interpret code and output together. */
  captureOnSystem({ command, args = [], cwd, env, gsudo = false }) {
    return spawnForExecutor({
      command,
      args,
      cwd,
      env,
      gsudo,
      write: this._write,
      signal: this.signal,
      collect: true,
    });
  }

  /** Runs `command` on the remote host: the hidden terminal's shell
   * process *is* the command (shellPath/shellArgs, not sendText into
   * an interactive shell), so it exits -- with the command's own real
   * exit code -- the moment the command finishes. Terminal creation
   * follows the connected window's remote authority (verified
   * empirically: a file written this way lands on the actual remote
   * host, not locally), so this runs remotely even though this
   * extension itself is local/ui-kind. No live output streaming here
   * (unlike executeOnSystem) -- that would need the shell-integration
   * API; this only reports the final exit code. Force-killed if the
   * executor is aborted. */
  executeOnRemote({ command }) {
    return new Promise((resolve) => {
      const terminal = vscode.window.createTerminal({
        name: "vs-init-remote-task",
        hideFromUser: true,
        shellPath: "/bin/sh",
        shellArgs: ["-c", command],
      });

      const onAbort = () => terminal.dispose();
      this.signal.addEventListener("abort", onAbort);

      const disposable = vscode.window.onDidCloseTerminal((closed) => {
        if (closed !== terminal) {
          return;
        }
        disposable.dispose();
        this.signal.removeEventListener("abort", onAbort);
        resolve(terminal.exitStatus ? (terminal.exitStatus.code ?? -1) : -1);
      });
    });
  }

  /** Starts a local HTTP server, closed automatically if the executor
   * is aborted. Resolves once it's actually listening. Port 0 lets the
   * OS pick an ephemeral port (read back via server.address().port);
   * a fixed port is needed when, like the account-id flow, some
   * external party already has that exact port registered. */
  openServer({ port = 0, host = "localhost", handler }) {
    return new Promise((resolve, reject) => {
      const server = http.createServer(handler);
      const onAbort = () => server.close();
      this.signal.addEventListener("abort", onAbort);
      server.once("error", reject);
      server.listen(port, host, () => resolve(server));
    });
  }
}

// One shared terminal slot across every feature that calls
// executeTask() -- not one-per-call. A new task terminates whatever
// task was previously running (if any) rather than piling up tabs.
let currentTerminal = null;

/** Runs one task in a single, reused "vs-init" terminal (its usual
 * panel location, not a one-off editor tab) backed by a Pseudoterminal
 * we fully control, not a real shell. Starting a new task first
 * disposes whichever task's terminal is still open -- disposing a
 * Pseudoterminal-backed Terminal invokes its pty's close(), which
 * calls that previous run's executor.abort(), so an in-flight
 * local/remote command or open server from the terminated task tears
 * down the same way it would if the user had closed the terminal by
 * hand. `title` becomes the first line written once the terminal is
 * actually open, not the terminal's own name (which stays the fixed
 * "vs-init") -- a flavor line identifying what's currently running,
 * inside a terminal the user already knows to look at. `action` gets a
 * TaskExecutor to report progress (writeLine), run local/remote
 * commands, or open a server. Doesn't await or return anything to the
 * caller -- completion is reported into the terminal itself, not back
 * through a call stack, the same way a button click triggering a
 * background action already works everywhere else in this extension. */
function executeTask(title, action) {
  if (currentTerminal) {
    currentTerminal.dispose();
    currentTerminal = null;
  }

  const writeEmitter = new vscode.EventEmitter();
  const closeEmitter = new vscode.EventEmitter();
  const executor = new TaskExecutor((text) => writeEmitter.fire(text));

  async function runAction() {
    let code = 0;
    try {
      const result = await action(executor);
      code = typeof result === "number" ? result : 0;
    } catch (err) {
      executor.writeLine(`Failed: ${err.message}`);
      code = 1;
    }
    executor.writeLine(`[done, exit code ${code}]`);
  }

  const pty = {
    onDidWrite: writeEmitter.event,
    onDidClose: closeEmitter.event,
    // onDidWrite events fired before open() is called are ignored, so
    // the flavor line (and everything the action writes) has to wait
    // for this, not just for createTerminal() to return.
    open: () => {
      executor.writeLine(title);
      runAction();
    },
    close: () => {
      executor.abort();
      if (currentTerminal === terminal) {
        currentTerminal = null;
      }
    },
  };

  const terminal = vscode.window.createTerminal({ name: "vs-init", pty });
  currentTerminal = terminal;
  terminal.show();
}

module.exports = { executeTask, TaskExecutor };
