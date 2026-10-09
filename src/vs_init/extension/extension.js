const vscode = require("vscode");
const fs = require("fs");
const os = require("os");
const path = require("path");
const dns = require("dns");
const tls = require("tls");
const crypto = require("crypto");
const { executeTask } = require("./taskExecutor");
const { captureAgolToken } = require("./agolToken");
const { resolveUsername, addApplicationItem, registerOAuthApp, updateOAuthApp, extractAppId } = require("./portalRegister");

// Must match the host path on the left of the bind mount this cue looks
// for in compose.yml: "- /opt/vertigis-studio/certs/root:/etc/ssl/certs:ro".
const TRUST_PATH_SEGMENTS = ["certs", "root"];
const TRUST_BUNDLE_NAME = "ca-certificates.crt";

const STUDIO_PATH = "/opt/vertigis-studio";

// Ported from vss-prime's certenroll.py.
const CERT_TEMPLATE = "WebServerV3";

// Same client_id/redirect_uri/port as vss-prime's accountid.py -- these
// are registered verbatim with VertiGIS's identity service, not ours to
// change. http.createServer here is the Node port of that same local
// callback-server flow.
const ACCOUNT_ID_PORT = 7780;
const ACCOUNT_ID_AUTH_URL =
  "https://identity.vertigisstudio.com/authorize" +
  "?client_id=pTmBlZldlUaNrhFn" +
  "&redirect_uri=http%3A%2F%2Flocalhost%3A7780%2Fa5510196-002b-4e2e-ba4e-8fdb91ee5287%2Fonline-activate" +
  "&response_mode=form_post" +
  "&activate=no_grant";

/** Pure (no vscode API) so it's testable directly. True only for a
 * Remote-SSH window (not WSL/Dev Containers/local) whose workspace
 * folder is specifically our provisioned folder, not just any remote
 * folder. */
function computeLooksLikeOurs(remoteName, folderPaths) {
  if (remoteName !== "ssh-remote") {
    return false;
  }
  return folderPaths.some((p) => p.replace(/\/+$/, "") === STUDIO_PATH);
}

/** Pure. "something.foo.bar.etc -> something._folder_name_.int": keeps
 * the target value's first label, replaces everything else with the
 * owning project's own folder name plus ".int" -- the internal network
 * alias every project's compose template already declares for itself
 * (e.g. studio-2's own "studio.studio-2.int"). A port, if present
 * (host:port), survives unchanged. */
function rewriteTarget(target, projectName) {
  const [hostPart, ...portParts] = target.split(":");
  const port = portParts.join(":");
  const firstLabel = hostPart.split(".")[0] || hostPart;
  const rewritten = `${firstLabel}.${projectName}.int`;
  return port ? `${rewritten}:${port}` : rewritten;
}

/** Pure. Appends a "# caddy route target:<port>" comment hint's port to
 * a rewritten target, for the generated Caddyfile route only -- never
 * written back to the alias value itself, which can't carry a port at
 * all (it's a real Docker network alias, not just a Caddyfile field;
 * e.g. studio's own template listens on 8080, but a network alias is
 * just a hostname). Only applies the hint if the rewrite doesn't
 * already carry a port of its own (defensive -- in practice a network
 * alias value never does). */
function applyPortHint(target, portHint) {
  return portHint && !target.includes(":") ? `${target}:${portHint}` : target;
}

/** Pure. "remove trailing slash, make sure host part is lowercase" --
 * lowercases just the scheme://host authority portion of a URL, not
 * the whole string (paths can be case-sensitive), and strips exactly
 * one trailing slash. String manipulation, not a full URL parse:
 * JavaScript's URL class normalizes a bare origin back to having a
 * trailing "/" on .toString(), which would undo the trim this is
 * explicitly asked to do. */
function normalizeRouteUrl(url) {
  const noTrailingSlash = url.replace(/\/+$/, "");
  return noTrailingSlash.replace(/^([a-z][a-z0-9+.-]*:\/\/)([^/]+)/i, (_m, scheme, host) => scheme + host.toLowerCase());
}

/** Pure. Splits a normalized route URL into its origin
 * (scheme://host) and path, so multiple routes sharing a host can be
 * grouped under one Caddy site block and differentiated by path. */
function splitRouteUrl(url) {
  const match = url.match(/^([a-z][a-z0-9+.-]*:\/\/[^/]+)(\/.*)?$/i);
  return match ? { origin: match[1], path: match[2] || "" } : { origin: url, path: "" };
}

/** Pure. Strips the scheme off a route's origin, leaving just the host
 * -- the thing both a Caddy site block's own label and Request Cert's
 * certs/live/<host> are keyed on. */
function hostFromOrigin(origin) {
  return origin.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");
}

/** Pure. Absolute remote paths to a host's live cert material -- the
 * same certs/live/<host>/{fullchain.pem,privkey.pem} Request Cert's
 * triage step (certTriageScript()) writes. */
function liveCertPaths(host) {
  const dir = `${STUDIO_PATH}/certs/live/${host}`;
  return { fullchain: `${dir}/fullchain.pem`, privkey: `${dir}/privkey.pem` };
}

/** Pure. Builds Caddyfile text from {url, target} route pairs,
 * grouped by host: a host with exactly one (pathless) route gets a
 * plain reverse_proxy block, a host with multiple routes (necessarily
 * distinguished by path) gets handle_path blocks instead -- "mind the
 * trailing slashes in rewrites": handle_path strips its matched prefix
 * before proxying, so the glob is normalized to "<path>/*" regardless
 * of whether the route's own path already ended in a slash. Two routes
 * sharing both host AND path is a genuine conflict with no good
 * automatic resolution ("some intelligence is required", per the
 * plan) -- first one found wins, the rest are left as a comment rather
 * than silently dropped.
 *
 * `hasLiveCert(host)` decides whether that host's block gets an
 * explicit `tls <fullchain> <privkey>` line pointing at
 * certs/live/<host> -- if a host doesn't have one yet (or ever), its
 * block is left with no tls directive at all, so Caddy falls back to
 * its own automatic HTTPS (ACME) for it rather than this generator
 * needing to know anything about that config. Defaults to "no host has
 * one" so existing callers/tests that don't care about certs still get
 * the old plain output. */
function buildCaddyfileText(routes, hasLiveCert = () => false) {
  const byOrigin = new Map();
  for (const { url, target } of routes) {
    const { origin, path } = splitRouteUrl(url);
    if (!byOrigin.has(origin)) {
      byOrigin.set(origin, []);
    }
    byOrigin.get(origin).push({ path, target });
  }

  const blocks = [];
  for (const [origin, entries] of byOrigin) {
    const host = hostFromOrigin(origin);
    const lines = [`${host} {`];
    if (hasLiveCert(host)) {
      const { fullchain, privkey } = liveCertPaths(host);
      lines.push(`    tls ${fullchain} ${privkey}`);
    }

    if (entries.length === 1 && !entries[0].path) {
      lines.push(`    reverse_proxy ${entries[0].target}`);
      lines.push("}");
      blocks.push(lines.join("\n"));
      continue;
    }

    const seenPaths = new Set();
    for (const { path, target } of entries) {
      const prefix = path || "/";
      if (seenPaths.has(prefix)) {
        lines.push(`    # conflict: another route already claims ${prefix}, skipped ${target}`);
        continue;
      }
      seenPaths.add(prefix);
      const pattern = prefix.endsWith("/") ? `${prefix}*` : `${prefix}/*`;
      lines.push(`    handle_path ${pattern} {`);
      lines.push(`        reverse_proxy ${target}`);
      lines.push(`    }`);
    }
    lines.push("}");
    blocks.push(lines.join("\n"));
  }

  return blocks.join("\n\n") + "\n";
}

// The bind mount a caddy project's own compose.yml uses to expose its
// sibling Caddyfile to the container -- shared with
// looksLikeCaddyProjectFile() below, which uses the same marker to
// recognize a caddy project's own compose.yml.
const OWN_CADDYFILE_MOUNT = /^\s*-\s*\.:\/etc\/caddy:ro\s*$/;

/** Pure. Does this compose.yml look like a caddy project's own file --
 * the one Build Caddyfile writes its generated Caddyfile NEXT TO, not
 * one of the project files it reads caddy route cues FROM? Two
 * structural signals, both required: a caddy image on some service,
 * and the self-mount (`.:/etc/caddy:ro`) that exposes this project's
 * own folder -- Caddyfile included -- to the container. Needed because
 * a caddy project's own compose.yml has no "# caddy route ..." comments
 * of its own -- without this, opening it directly would never trigger
 * the lens at all. */
function looksLikeCaddyProjectFile(lines) {
  const hasCaddyImage = lines.some((line) => /^\s*image:\s*["']?caddy:/i.test(line));
  const hasOwnCaddyfileMount = lines.some((line) => OWN_CADDYFILE_MOUNT.test(line));
  return hasCaddyImage && hasOwnCaddyfileMount;
}

/** Returns the first existing caddy-* project's folder name, or
 * creates one ("caddy-1") if none exist yet -- "if none present, we
 * add a project", per the plan. */
async function findOrCreateCaddyProject(studioFolderUri) {
  const names = await listDirectories(studioFolderUri);
  const caddyNames = names.filter((name) => /^caddy(-\d+)?$/.test(name)).sort();
  if (caddyNames.length > 0) {
    return caddyNames[0];
  }
  const { name } = await addProject(studioFolderUri, "caddy");
  return name;
}

/** Scans every project's compose.yml (depth 1) for the two caddy-route
 * cues, updates each in place (quote-preserving, per
 * replaceLineValue()), collects the resulting {url, target} pairs, and
 * writes the generated Caddyfile to the caddy project's own Caddyfile
 * (bind-mounted into the container via that project's `.:/etc/caddy:ro`
 * compose.yml entry). Triggered from either cue's CodeLens -- both do
 * the same whole-workspace scan, not just the clicked line/file. */
function buildCaddyfile() {
  const folders = vscode.workspace.workspaceFolders;
  const studioFolderUri = folders && folders[0] && folders[0].uri;
  if (!studioFolderUri) {
    return;
  }

  executeTask("Build Caddyfile", async (executor) => {
    const projectNames = await listProjects(studioFolderUri);
    executor.writeLine(`Scanning ${projectNames.length} project(s) for caddy route cues...`);

    const routes = [];
    for (const name of projectNames) {
      const composeUri = await findComposeUri(studioFolderUri, name);
      if (!composeUri) {
        continue;
      }

      // Multiple pairs per file are paired up by order of appearance --
      // 1st url with 1st target, 2nd with 2nd, etc. That only matches
      // the right url to the right target if whoever edits the file
      // keeps the cues in matching order; nothing enforces that, but a
      // mis-paired route is easy to spot (wrong target in the
      // generated Caddyfile) and easy to fix (reorder the cues), so a
      // warning on count mismatch is enough -- no need for a more
      // explicit correlation scheme.
      const urls = [];
      const targets = [];

      const changed = await applyTextEdit(composeUri, (text) => {
        const lines = text.split("\n");
        let didChange = false;

        for (let i = 0; i < lines.length; i++) {
          if (/#\s*caddy route url\s*$/.test(lines[i])) {
            const raw = extractLineValue(lines[i]);
            if (!raw) {
              continue;
            }
            const url = normalizeRouteUrl(raw);
            urls.push(url);
            const updatedLine = replaceLineValue(lines[i], url);
            if (updatedLine !== null && updatedLine !== lines[i]) {
              lines[i] = updatedLine;
              didChange = true;
            }
          } else {
            const targetMatch = lines[i].match(/#\s*caddy route target(?::(\d+))?\s*$/);
            if (!targetMatch) {
              continue;
            }
            const raw = extractLineValue(lines[i]);
            if (!raw) {
              continue;
            }
            // The alias itself (what's written back to the file) never
            // carries a port -- it's a real Docker network alias, not
            // just a Caddyfile field, and a port suffix there would be
            // invalid. The port hint only ever affects the route
            // collected below for the generated Caddyfile.
            const rewrittenHost = rewriteTarget(raw, name);
            targets.push(applyPortHint(rewrittenHost, targetMatch[1]));
            const updatedLine = replaceLineValue(lines[i], rewrittenHost);
            if (updatedLine !== null && updatedLine !== lines[i]) {
              lines[i] = updatedLine;
              didChange = true;
            }
          }
        }

        return didChange ? lines.join("\n") : null;
      });

      if (changed) {
        executor.writeLine(`Updated ${name}/compose.yml.`);
      }

      const pairCount = Math.min(urls.length, targets.length);
      if (urls.length !== targets.length) {
        executor.writeLine(
          `${name}/compose.yml has ${urls.length} caddy route url cue(s) but ${targets.length} target cue(s) -- pairing the first ${pairCount} by order found; the rest are ignored.`
        );
      }
      for (let i = 0; i < pairCount; i++) {
        routes.push({ url: urls[i], target: targets[i] });
      }
    }

    executor.writeLine(`${routes.length} route(s) found.`);
    if (routes.length === 0) {
      return 0;
    }

    const hosts = new Set(routes.map((route) => hostFromOrigin(splitRouteUrl(route.url).origin)));
    const liveCertHosts = new Set();
    for (const host of hosts) {
      try {
        await vscode.workspace.fs.stat(vscode.Uri.joinPath(studioFolderUri, "certs", "live", host, "fullchain.pem"));
        liveCertHosts.add(host);
      } catch {
        // No live cert for this host (yet, or ever) -- its block gets
        // no tls directive, so Caddy falls back to automatic HTTPS.
      }
    }
    if (liveCertHosts.size > 0) {
      executor.writeLine(`${liveCertHosts.size} of ${hosts.size} host(s) have a live cert; wiring tls for those.`);
    }

    const caddyName = await findOrCreateCaddyProject(studioFolderUri);
    const caddyfileUri = vscode.Uri.joinPath(studioFolderUri, caddyName, "Caddyfile");
    executor.writeLine(`Writing ${caddyName}/Caddyfile...`);

    const caddyfileText = buildCaddyfileText(routes, (host) => liveCertHosts.has(host));
    // Wholly regenerated every run -- unlike compose.yml's surgical
    // cue-line edits, there's no hand-editing of this file to preserve.
    // Still routed through applyTextEdit (not a raw workspace.fs write)
    // so an already-open editor updates in place instead of racing
    // VS Code's own file-watcher-driven revert on the immediate reopen
    // below -- addProject() guarantees every caddy project has this
    // file from creation, so it's always there to open.
    await applyTextEdit(caddyfileUri, () => caddyfileText);

    const doc = await vscode.workspace.openTextDocument(caddyfileUri);
    await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
    await vscode.commands.executeCommand("revealInExplorer", caddyfileUri);

    return 0;
  });
}

function pemToDer(pem) {
  const base64 = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
  return Buffer.from(base64, "base64");
}

function splitPemCertificates(text) {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
}

/** Pure. Same collapse vss-prime's _kebab() does: any run of non-
 * alphanumeric characters becomes a single '-', uppercased, trimmed.
 * Not meant to round-trip back to the real subject -- just a
 * human-scannable filename component. */
function kebabSubject(subject) {
  return subject.replace(/[^A-Za-z0-9]+/g, "-").toUpperCase().replace(/^-+|-+$/g, "");
}

/** Pure. <8-hex-sha256-prefix, uppercase>-<KEBAB-SUBJECT>.pem, same
 * shape as vss-prime's _filename() -- the hash prefix is what actually
 * guarantees uniqueness (CA rollovers share a subject across distinct
 * certs), the kebab subject is just for readability. */
function pemFilename(der, subject) {
  const digest = crypto.createHash("sha256").update(der).digest("hex").slice(0, 8).toUpperCase();
  return `${digest}-${kebabSubject(subject)}.pem`;
}

/** Adds `patterns` to the workspace's files.exclude (settings.json, same
 * file provision.sh's own Abyss-theme write already lands in) -- there's
 * no reason for the admin to browse generated key/cert material in the
 * Explorer. Idempotent: skips patterns already present, and is a no-op
 * entirely if every pattern is already there. Shared by both the trust-
 * anchors and cert-request flows rather than each reimplementing the
 * same read-merge-write dance. */
async function addFilesExcludePatterns(patterns) {
  const config = vscode.workspace.getConfiguration("files");
  const exclude = config.get("exclude") || {};
  const missing = patterns.filter((pattern) => !exclude[pattern]);
  if (missing.length === 0) {
    return;
  }

  const updated = { ...exclude };
  for (const pattern of missing) {
    updated[pattern] = true;
  }
  await config.update("exclude", updated, vscode.ConfigurationTarget.Workspace);
}

/** Hides the generated .pem files and openssl-rehash symlinks from the
 * Explorer. No globstar prefix: the trust folder is always directly at
 * the workspace root, never nested. *.? covers the common single-digit
 * cert-hash symlinks (.0, .1, ...); *.?? covers the rarer two-character
 * ones (.r0/.r1 CRL-hash symlinks, or a 10+-way collision counter) --
 * glob `?` matches exactly one character, so both are needed, neither
 * subsumes the other. */
async function hideTrustPemFiles() {
  const base = TRUST_PATH_SEGMENTS.join("/");
  await addFilesExcludePatterns([`${base}/*.pem`, `${base}/*.?`, `${base}/*.??`]);
}

/** Ported from vss-prime's trustscrape.py. The one piece that's
 * genuinely simpler here: Electron's Node ships
 * tls.getCACertificates("system"), which reads the same Windows trust
 * store vss-prime had to reconstruct by hand (PowerShell metadata +
 * Python's ssl.enum_certificates, merged and filtered for store-level
 * server-auth trust) -- verified empirically against that exact proven
 * output: every one of vss-prime's 38 correctly-filtered anchors on
 * this machine also appears in tls.getCACertificates's list, as part
 * of a larger, unfiltered superset. A few extra non-server-auth-
 * purpose certs riding along is harmless; missing a real enterprise
 * anchor would not be. */
function transferTrustAnchors() {
  const folders = vscode.workspace.workspaceFolders;
  const studioFolderUri = folders && folders[0] && folders[0].uri;
  if (!studioFolderUri) {
    return;
  }

  executeTask("Transfer Enterprise Trust Anchors", async (executor) => {
    executor.writeLine("Reading this machine's trusted system CAs...");
    const windowsPems = tls.getCACertificates("system");
    executor.writeLine(`${windowsPems.length} CA(s) from Windows.`);

    executor.writeLine("Reading the remote host's own /etc/ssl/certs/ca-certificates.crt...");
    const remoteCertsUri = vscode.Uri.from({
      scheme: studioFolderUri.scheme,
      authority: studioFolderUri.authority,
      path: "/etc/ssl/certs/ca-certificates.crt",
    });
    let linuxPems = [];
    try {
      const data = await vscode.workspace.fs.readFile(remoteCertsUri);
      linuxPems = splitPemCertificates(Buffer.from(data).toString("utf8"));
    } catch (err) {
      executor.writeLine(`(couldn't read the remote bundle: ${err.message}; continuing with Windows-only anchors)`);
    }
    executor.writeLine(`${linuxPems.length} CA(s) already on the remote host.`);

    const merged = new Map();
    for (const pem of [...windowsPems, ...linuxPems]) {
      const der = pemToDer(pem);
      const fingerprint = crypto.createHash("sha256").update(der).digest("hex");
      if (!merged.has(fingerprint)) {
        merged.set(fingerprint, { pem: pem.trim(), der });
      }
    }
    executor.writeLine(`${merged.size} unique trust anchor(s) after merge.`);

    const trustDirUri = vscode.Uri.joinPath(studioFolderUri, ...TRUST_PATH_SEGMENTS);
    executor.writeLine(`Writing individual cert files to ${trustDirUri.toString()}...`);
    for (const { pem, der } of merged.values()) {
      const subject = new crypto.X509Certificate(pem).subject || "UNKNOWN";
      const filename = pemFilename(der, subject);
      await vscode.workspace.fs.writeFile(vscode.Uri.joinPath(trustDirUri, filename), Buffer.from(pem + "\n", "utf8"));
    }

    const bundle = Array.from(merged.values(), ({ pem }) => pem).join("\n") + "\n";
    const bundleUri = vscode.Uri.joinPath(trustDirUri, TRUST_BUNDLE_NAME);
    await vscode.workspace.fs.writeFile(bundleUri, Buffer.from(bundle, "utf8"));
    executor.writeLine(`Wrote ${merged.size} cert file(s) and ${TRUST_BUNDLE_NAME}.`);

    executor.writeLine("Dispatching `openssl rehash` on the remote...");
    const rehashCode = await executor.executeOnRemote({ command: `openssl rehash ${trustDirUri.path}` });
    executor.writeLine(
      rehashCode === 0
        ? "openssl rehash completed successfully."
        : `openssl rehash exited with code ${rehashCode}.`
    );

    await hideTrustPemFiles();
    return 0;
  });
}

/** Pure. Given compose.yml lines and the index of an "environment:" key
 * line, returns the {KEY: value} map of entries in its indented block
 * -- anything more indented than the environment: line itself, stopping
 * at the first non-blank line back at or above that indentation. These
 * are the "nearby ARCGIS_APP_ID, ARCGIS_PORTAL_URL, FRONTEND_URL" keys
 * the plan's cue condition means by "nearby". */
function environmentBlockValues(lines, envIndex) {
  const baseIndent = lines[envIndex].match(/^(\s*)/)[1].length;
  const values = {};
  for (let i = envIndex + 1; i < lines.length; i++) {
    const text = lines[i];
    if (text.trim() === "") {
      continue;
    }
    const indent = text.match(/^(\s*)/)[1].length;
    if (indent <= baseIndent) {
      break;
    }
    const { payload } = splitComment(text);
    const keyMatch = payload.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:/);
    if (keyMatch) {
      values[keyMatch[1]] = extractLineValue(text);
    }
  }
  return values;
}

/** Pure. Finds the CodeLens cues this extension currently understands
 * in a compose.yml's lines.
 *
 * Build Caddyfile and Transfer Enterprise Trust Anchors are file-wide
 * actions (Build Caddyfile scans every project's compose.yml, Transfer
 * Enterprise Trust Anchors doesn't care which line triggered it either),
 * so their lenses are pinned to line 0 -- the top of the file -- rather
 * than wherever their cue happens to sit. Each still only appears when
 * its cue is actually present somewhere in the file (Build Caddyfile's
 * trigger is deliberately loose: any "# caddy" comment at all, not
 * anchored to a specific "route url"/"route target" suffix, so the
 * action surfaces readily; the actual url/target extraction in
 * buildCaddyfile() still only acts on those two specific markers, so
 * loosening the trigger can't misfire on an unrelated "# caddy ..."
 * comment) -- and a cue matching multiple lines (e.g. both a url and a
 * target comment) still produces exactly one lens, not one per match.
 * Build Caddyfile also shows up on a caddy project's OWN compose.yml --
 * which has no "# caddy route ..." comments of its own to match -- via
 * a second, structural cue (looksLikeCaddyProjectFile): a caddy image
 * plus the `.:/etc/caddy:ro` self-mount, the shape the caddy template
 * itself has.
 *
 * Everything else -- Get Account ID, Register App, Update App, Request
 * Cert, Retrieve Cert, Register CNAME -- is decided together off a
 * single "is this our environment block" check, all anchored at that
 * one environment: line rather than scattered across their own
 * individual key lines. "Ours" requires VERTIGIS_ACCOUNT_ID,
 * FRONTEND_URL, and ARCGIS_PORTAL_URL all present -- deliberately not
 * ARCGIS_APP_ID too, since that one's expected to be blank until
 * Register App has actually run. Register App, Request Cert, Retrieve
 * Cert, and Register CNAME always show once a block qualifies -- none
 * of the four are gated on any prior state (see each action's own
 * comment for why); Update App is the one exception, showing
 * additionally only once ARCGIS_APP_ID has a value.
 *
 * Pick Version is simpler still: any "image:" mapping with a value at
 * all gets its own lens, right on that line (not top-pinned -- it's
 * genuinely per-image, and a file could have more than one service each
 * with its own image: line). No further condition -- every image
 * reference is a valid candidate to look up tags for. */
function findLensSpecs(lines) {
  const specs = [];
  let hasCaddyCue = false;
  let hasTrustAnchorsCue = false;

  lines.forEach((text, line) => {
    if (/#\s*caddy/.test(text)) {
      hasCaddyCue = true;
    } else if (/^\s*-\s*\/opt\/vertigis-studio\/certs\/root:\/etc\/ssl\/certs:ro\s*$/.test(text)) {
      hasTrustAnchorsCue = true;
    } else if (/^\s*image\s*:\s*\S/.test(text)) {
      specs.push({ line, title: "Pick Version", kind: "pickVersion" });
    } else if (/^\s*environment\s*:\s*$/.test(text)) {
      const values = environmentBlockValues(lines, line);
      const isOurs = "VERTIGIS_ACCOUNT_ID" in values && "FRONTEND_URL" in values && "ARCGIS_PORTAL_URL" in values;
      if (!isOurs) {
        return;
      }
      specs.push({ line, title: "Get Account ID", kind: "accountId" });
      specs.push({ line, title: "Register App", kind: "registerApp" });
      if (values.ARCGIS_APP_ID) {
        specs.push({ line, title: "Update App", kind: "updateApp" });
      }
      // Always shown, even with a live cert already in place --
      // resubmitting is never gated (see requestCert's own comment).
      // Retrieve Cert is just as unconditional -- deliberately not
      // gated on any check of certs/requests' state; it just tries,
      // and certreq's own output says why if there's nothing to
      // retrieve (see retrieveCert's own comment).
      specs.push({ line, title: "Request Cert", kind: "requestCert" });
      specs.push({ line, title: "Retrieve Cert", kind: "retrieveCert" });
      // Also unconditional -- "very optimistic" by design, re-derives
      // and upserts from scratch every run (see registerCname's own
      // comment), nothing here to gate on.
      specs.push({ line, title: "Register CNAME", kind: "registerCname" });
    }
  });

  const topSpecs = [];
  if (hasCaddyCue || looksLikeCaddyProjectFile(lines)) {
    topSpecs.push({ line: 0, title: "Build Caddyfile", kind: "caddyfile" });
  }
  if (hasTrustAnchorsCue) {
    topSpecs.push({ line: 0, title: "Transfer Enterprise Trust Anchors", kind: "trustAnchors" });
  }
  return [...topSpecs, ...specs];
}

/** Pure. Splits a line's trailing "# ..." comment off, if any.
 * Requires a space before the "#" specifically so a "#" inside a
 * quoted value (e.g. a URL fragment, "https://host/#section") isn't
 * mistaken for one. */
function splitComment(line) {
  const match = line.match(/^(.*?)(\s+#.*)?$/);
  return { payload: match[1], comment: match[2] || "" };
}

/** Pure. The trailing "# ..." comment's own text, with the leading "#"
 * and surrounding whitespace stripped -- e.g. " # VertiGIS Studio" ->
 * "VertiGIS Studio". Null if there's no comment, or it's empty once
 * stripped. */
function lineCommentText(line) {
  const { comment } = splitComment(line);
  const text = comment.replace(/^\s*#\s*/, "").trim();
  return text || null;
}

/** Pure. Splits a (comment-stripped) line into its structural prefix
 * -- a YAML mapping's "key:" or a list item's "-", normalized to
 * exactly one trailing space regardless of how much (or how little --
 * including none, for a not-yet-filled-in "KEY:" with nothing after
 * it) whitespace the original had -- and everything after it (the
 * value). Anchored on the START of the line specifically (the first
 * unquoted ":" for a mapping, the leading "-" for a list item) -- not
 * "the last colon or dash anywhere in the line" -- so a value that
 * itself contains a dash (e.g. "studio-1") or a colon (a host:port)
 * isn't mistaken for the line's own structure. Returns null if the
 * line isn't a mapping or list-item line at all. */
function splitLinePrefix(payload) {
  const listMatch = payload.match(/^(\s*-)\s*([\s\S]*)$/);
  if (listMatch) {
    return { prefix: `${listMatch[1]} `, rest: listMatch[2] };
  }
  const keyMatch = payload.match(/^(\s*[^\s:][^:]*:)\s*([\s\S]*)$/);
  if (keyMatch) {
    return { prefix: `${keyMatch[1]} `, rest: keyMatch[2] };
  }
  return null;
}

/** Pure. Extracts the current value of a compose.yml line -- the text
 * after its "key:"/"- " prefix, unquoted if it was quoted (empty
 * string for a blank, not-yet-filled-in field like "KEY: "). Returns
 * null if the line doesn't look like key/value or list-item shape. */
function extractLineValue(line) {
  const { payload } = splitComment(line);
  const split = splitLinePrefix(payload);
  if (!split) {
    return null;
  }
  const quoted = split.rest.match(/^(["'])((?:(?!\1)[\s\S])*)\1\s*$/);
  return quoted ? quoted[2] : split.rest.trim();
}

/** Pure. Replaces the value field of a single line with `newValue` --
 * "touches the last field of the line", per the plan -- preserving
 * whatever quoting (' or ", or none at all) wrapped the old value, and
 * preserving any trailing "# ..." comment unchanged. Not a YAML
 * parser: handles the shapes this extension actually generates/edits
 * (a "key:" mapping or a "- " list item, optionally quoted, optionally
 * followed by a comment), not arbitrary YAML. Returns null if the line
 * doesn't look like key/value or list-item shape at all. */
function replaceLineValue(line, newValue) {
  const { payload, comment } = splitComment(line);
  const split = splitLinePrefix(payload);
  if (!split) {
    return null;
  }
  const quoted = split.rest.match(/^(["'])(?:(?!\1)[\s\S])*\1\s*$/);
  if (quoted) {
    const quoteChar = quoted[1];
    return `${split.prefix}${quoteChar}${newValue}${quoteChar}${comment}`;
  }
  return `${split.prefix}${newValue}${comment}`;
}

/** Pure. Finds the "key: ..." line in a compose.yml's raw text and
 * replaces its value via replaceLineValue(), preserving quoting and
 * any trailing comment. Returns null if the key isn't present. */
function updateComposeEnvValue(text, key, value) {
  const lines = text.split("\n");
  const index = lines.findIndex((line) => new RegExp(`^\\s*${key}\\s*:`).test(line));
  if (index === -1) {
    return null;
  }
  const updated = replaceLineValue(lines[index], value);
  if (updated === null) {
    return null;
  }
  lines[index] = updated;
  return lines.join("\n");
}

// Kept as real .yml files under templates/ (not inline template
// literals) so they're easy to read/edit on their own -- proper YAML
// syntax highlighting, no JS-string escaping to fight with -- and
// shipped as-is, no placeholder expansion.
function composeStubFor(kind) {
  return fs.readFileSync(path.join(__dirname, "templates", kind, "compose.yml"), "utf8");
}

function caddyfileStub() {
  return fs.readFileSync(path.join(__dirname, "templates", "caddy", "Caddyfile"), "utf8");
}

async function listDirectories(studioFolderUri) {
  let entries;
  try {
    entries = await vscode.workspace.fs.readDirectory(studioFolderUri);
  } catch {
    return [];
  }
  return entries.filter(([, type]) => type === vscode.FileType.Directory).map(([name]) => name);
}

/** Returns the project's compose file's Uri (compose.yml or
 * compose.yaml, whichever exists), or null if neither does. */
async function findComposeUri(studioFolderUri, name) {
  for (const filename of ["compose.yml", "compose.yaml"]) {
    const uri = vscode.Uri.joinPath(studioFolderUri, name, filename);
    try {
      await vscode.workspace.fs.stat(uri);
      return uri;
    } catch {
      // try the next candidate filename
    }
  }
  return null;
}

/** Fast-links list: only folders that actually contain a compose file
 * count as a "project" -- a bare subfolder (mid-creation, unrelated,
 * whatever) shouldn't show up as a clickable project. */
async function listProjects(studioFolderUri) {
  const names = await listDirectories(studioFolderUri);
  const withCompose = await Promise.all(
    names.map(async (name) => ((await findComposeUri(studioFolderUri, name)) ? name : null))
  );
  return withCompose.filter((name) => name !== null).sort();
}

/** Naming/collision check: considers every existing subfolder, not
 * just ones with a compose file yet -- so a half-created "caddy-1"
 * folder still reserves that number instead of being silently reused. */
async function nextProjectName(studioFolderUri, prefix) {
  const names = await listDirectories(studioFolderUri);
  let n = 1;
  while (names.includes(`${prefix}-${n}`)) {
    n++;
  }
  return `${prefix}-${n}`;
}

async function addProject(studioFolderUri, kind) {
  const name = await nextProjectName(studioFolderUri, kind);
  const composeUri = vscode.Uri.joinPath(studioFolderUri, name, "compose.yml");
  await vscode.workspace.fs.writeFile(composeUri, Buffer.from(composeStubFor(kind), "utf8"));
  if (kind === "caddy") {
    // compose.yml's `command` points caddy at /etc/caddy/Caddyfile (bind
    // -mounted from this same folder) from the moment the container
    // first starts -- without this, a freshly added caddy project would
    // fail to start at all until Build Caddyfile happened to run once.
    const caddyfileUri = vscode.Uri.joinPath(studioFolderUri, name, "Caddyfile");
    await vscode.workspace.fs.writeFile(caddyfileUri, Buffer.from(caddyfileStub(), "utf8"));
  }
  return { name, composeUri };
}

/** Reads, transforms, and writes back a text file through VS Code's
 * own document model (TextDocument + WorkspaceEdit + save()) instead
 * of a raw vscode.workspace.fs write -- so if the file is already open
 * in an editor, that editor's buffer updates immediately and in place
 * ("inflight", per the plan), with no race against VS Code's own
 * file-watcher-driven revert. That race was a real bug: writing via
 * workspace.fs and then immediately re-opening the same file (as
 * buildCaddyfile does) could happen faster than the revert caught up,
 * so the freshly-reopened editor still showed stale content even
 * though disk was already correct. `transform(text)` returns the new
 * text, or null (or the unchanged text) to skip -- nothing is written
 * either way. Returns whether a write happened. */
async function applyTextEdit(uri, transform) {
  const doc = await vscode.workspace.openTextDocument(uri);
  const text = doc.getText();
  const updated = transform(text);
  if (updated === null || updated === text) {
    return false;
  }
  const fullRange = new vscode.Range(doc.positionAt(0), doc.positionAt(text.length));
  const edit = new vscode.WorkspaceEdit();
  edit.replace(uri, fullRange, updated);
  await vscode.workspace.applyEdit(edit);
  await doc.save();
  return true;
}

async function updateComposeFile(folderUri, key, value) {
  const uri = vscode.Uri.joinPath(folderUri, "compose.yml");
  try {
    return await applyTextEdit(uri, (text) => updateComposeEnvValue(text, key, value));
  } catch {
    return false;
  }
}

async function resolveAccountId(idValue, idUrl) {
  const response = await fetch(`${idUrl}?id=${encodeURIComponent(idValue)}`);
  if (!response.ok) {
    return null;
  }
  const data = await response.json();
  return data.accountId || null;
}

function findMyAccountId(folderUri) {
  executeTask("Get Account ID", async (executor) => {
    let settleAccountId;
    const accountIdFound = new Promise((resolve) => {
      settleAccountId = resolve;
    });

    executor.writeLine(`Starting local callback server on port ${ACCOUNT_ID_PORT}...`);
    const server = await executor.openServer({
      port: ACCOUNT_ID_PORT,
      host: "localhost",
      handler: (req, res) => {
        if (req.method === "GET") {
          res.writeHead(302, { Location: ACCOUNT_ID_AUTH_URL });
          res.end();
          return;
        }
        if (req.method !== "POST") {
          res.writeHead(404);
          res.end();
          return;
        }

        const chunks = [];
        req.on("data", (chunk) => chunks.push(chunk));
        req.on("end", async () => {
          const body = Buffer.concat(chunks).toString("utf8");
          const params = new URLSearchParams(body);
          const idValue = params.get("id");
          const idUrl = params.get("idUrl");
          const accountId = idValue && idUrl ? await resolveAccountId(idValue, idUrl) : null;

          res.writeHead(accountId ? 200 : 404);
          res.end();

          if (accountId) {
            settleAccountId(accountId);
          } else {
            executor.writeLine("Callback didn't resolve to an Account ID; still waiting...");
          }
        });
      },
    });

    const url = `http://localhost:${ACCOUNT_ID_PORT}/`;
    executor.writeLine(`Opening ${url} in your browser...`);
    vscode.env.openExternal(vscode.Uri.parse(url));

    const aborted = new Promise((resolve) => {
      executor.signal.addEventListener("abort", () => resolve(null));
    });
    const accountId = await Promise.race([accountIdFound, aborted]);
    server.close();
    if (accountId === null) {
      return 1;
    }

    executor.writeLine(`Resolved Account ID: ${accountId}`);
    const wrote = await updateComposeFile(folderUri, "VERTIGIS_ACCOUNT_ID", accountId);
    executor.writeLine(
      wrote
        ? "Wrote VERTIGIS_ACCOUNT_ID into compose.yml."
        : "compose.yml has no VERTIGIS_ACCOUNT_ID line to update (or it's already set to this value)."
    );
    return 0;
  });
}

/** Dual-purpose: registers a brand-new Application item + OAuth client
 * against the portal, or refreshes the redirect URI on an existing one
 * -- same arc split as vss-prime's register_app(). Which arc runs is
 * driven by `kind` (which lens was actually clicked), not by whether
 * ARCGIS_APP_ID happens to have a value -- Register App stays available
 * even once an app id already exists (re-registering mints a fresh,
 * separate client; nothing stops a user from wanting that), so the arc
 * can't be inferred from compose.yml's state alone. ARCGIS_PORTAL_URL
 * and FRONTEND_URL are read straight out of the compose.yml's
 * environment: block (the cue condition already guarantees both are
 * present); there's nothing left to prompt for, so this runs start-to-
 * finish unattended except for the portal sign-in itself. `folderUri`
 * is the project's own folder (the compose.yml's parent), and also
 * doubles as the Application item's title when registering -- a
 * placeholder, same "best guess for now" spirit as the project-naming
 * elsewhere in this extension. */
function registerOrUpdateApp(folderUri, kind) {
  executeTask(kind === "updateApp" ? "Update App" : "Register App", async (executor) => {
    const composeUri = vscode.Uri.joinPath(folderUri, "compose.yml");
    const doc = await vscode.workspace.openTextDocument(composeUri);
    const lines = doc.getText().split("\n");
    const envIndex = lines.findIndex((text) => /^\s*environment\s*:\s*$/.test(text));
    if (envIndex === -1) {
      executor.writeLine("No environment: block found in compose.yml.");
      return 1;
    }

    const values = environmentBlockValues(lines, envIndex);
    const portalUrl = values.ARCGIS_PORTAL_URL;
    const frontendUrl = values.FRONTEND_URL;
    const existingAppId = values.ARCGIS_APP_ID;
    if (!portalUrl || !frontendUrl) {
      executor.writeLine("compose.yml is missing a value for ARCGIS_PORTAL_URL or FRONTEND_URL -- fill those in first.");
      return 1;
    }
    if (kind === "updateApp" && !existingAppId) {
      executor.writeLine("No existing ARCGIS_APP_ID to update -- use Register App instead.");
      return 1;
    }

    const token = await captureAgolToken(executor, portalUrl);
    const username = await resolveUsername(portalUrl, token);
    executor.writeLine(`Signed in to ${portalUrl} as ${username}.`);

    let appId;
    if (kind === "updateApp") {
      executor.writeLine(`Updating existing registration (app id ${existingAppId})...`);
      await updateOAuthApp(portalUrl, token, existingAppId, [frontendUrl]);
      appId = existingAppId;
    } else {
      // The template's own "# VertiGIS Studio"-style comment on
      // ARCGIS_APP_ID is what a user actually sees on the portal's
      // OAuth consent screen, so it's a much better title than the
      // project folder name -- falls back to the folder name only if
      // that comment is missing or empty.
      const appIdLineIndex = lines.findIndex((line) => /^\s*ARCGIS_APP_ID\s*:/.test(line));
      const title =
        (appIdLineIndex !== -1 && lineCommentText(lines[appIdLineIndex])) ||
        folderUri.path.split("/").filter(Boolean).pop() ||
        "VertiGIS Studio";
      const itemId = await addApplicationItem(portalUrl, token, username, title);
      executor.writeLine(`Created Application item ${itemId}; registering OAuth info...`);
      const info = await registerOAuthApp(portalUrl, token, itemId, [frontendUrl]);
      appId = extractAppId(info);
      if (!appId) {
        executor.writeLine(`registerApp did not return a recognizable app id: ${JSON.stringify(info)}`);
        return 1;
      }
    }

    executor.writeLine(`App id: ${appId}`);
    if (kind === "updateApp") {
      // appId is unchanged here -- updating only refreshes the redirect
      // URI on the portal side, ARCGIS_APP_ID itself doesn't move. A
      // write attempt would be a no-op (identical value in, identical
      // text out), which updateComposeFile can't tell apart from "key
      // not found" -- so skip it and just confirm directly rather than
      // reporting that indistinguishable no-op as a failure.
      executor.writeLine("ARCGIS_APP_ID already matches; nothing to write.");
    } else {
      const wrote = await updateComposeFile(folderUri, "ARCGIS_APP_ID", appId);
      executor.writeLine(
        wrote ? "Wrote ARCGIS_APP_ID into compose.yml." : "Could not write ARCGIS_APP_ID into compose.yml."
      );
    }
    return 0;
  });
}

/** Pure. The host certreq submits for is just FRONTEND_URL's hostname,
 * lowercased -- scheme/port/path don't matter for a certificate's
 * subject. Returns null for a value that doesn't parse as a URL at all
 * (e.g. still blank/placeholder). */
function hostFromFrontendUrl(url) {
  try {
    const hostname = new URL(url).hostname;
    return hostname ? hostname.toLowerCase() : null;
  } catch {
    return null;
  }
}

/** Pure. Ported from vss-prime's _dump_value(): the quoted value after
 * the first ":" in a certutil -dump field line, e.g.
 * '  Config:   "server\\ca"' -> 'server\\ca'. */
function dumpValue(line) {
  const index = line.indexOf(":");
  if (index === -1) {
    return "";
  }
  let rest = line.slice(index + 1).trim();
  if (rest.length >= 2 && rest.startsWith('"') && rest.endsWith('"')) {
    rest = rest.slice(1, -1);
  }
  return rest;
}

/** Pure. Ported from vss-prime's list_cas(): {name, config} for every
 * CA certutil -dump prints -- a "Name:" line sets the pending name, the
 * very next "Config:" line pairs with it and resets. `config` (not
 * `name`) is what actually gets passed to certreq -config. */
function parseCertutilDump(output) {
  const cas = [];
  let name = null;
  for (const raw of output.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("Name:")) {
      name = dumpValue(line);
    } else if (line.startsWith("Config:") && name !== null) {
      cas.push({ name, config: dumpValue(line) });
      name = null;
    }
  }
  return cas;
}

/** Pure. Ported from vss-prime's _is_valid_cert_file(): a cheap, local-
 * only sniff for "does this file actually hold a staged cert", not a
 * real parse. Windows labels PKCS7 bundles (.p7b) with the same generic
 * "BEGIN CERTIFICATE" PEM header a plain cert uses (confirmed in
 * vss-prime against a real .p7b), so one check covers both. */
function looksLikeCertFile(text) {
  return text.includes("BEGIN CERTIFICATE");
}

const REQUEST_ID_PATTERN = /RequestId:\s*"?(\d+)"?/i;

/** Pure. Ported from vss-prime's own regex: pulls the numeric Request
 * ID out of certreq -submit's own console output, e.g. a line like
 * `RequestId: "42"`. Returns null if there isn't one -- e.g. the CA
 * issued synchronously, so there never was a pending request id to
 * retrieve later. */
function findRequestId(submitOutputText) {
  const match = submitOutputText.match(REQUEST_ID_PATTERN);
  return match ? match[1] : null;
}

function certTriageScript() {
  return fs.readFileSync(path.join(__dirname, "templates", "certTriage.sh"), "utf8");
}

/** Enumerates CAs visible to certutil -dump and resolves to the Config
 * string certreq -config needs. Skips the picker entirely when there's
 * only one CA ("Skip if only one", per the plan); throws if there are
 * none at all or the user cancels a multi-CA picker.
 *
 * `gsudo` defaults to true for Request Cert's sake, which needs a
 * -submit -adminforcemachine right after -- but elevation doesn't
 * change *which* account gets presented to the CA (UAC just raises the
 * current account's local privilege token; -adminforcemachine is the
 * one thing that actually swaps the identity to the computer account,
 * and it's submit-only), so there's no real reason to force it here on
 * Retrieve Cert's behalf, which passes gsudo: false. */
async function pickCaConfig(executor, { gsudo = true } = {}) {
  executor.writeLine("Enumerating certificate authorities (certutil -dump)...");
  const { output } = await executor.captureOnSystem({ gsudo, command: "certutil", args: ["-dump"] });
  const cas = parseCertutilDump(output);
  if (cas.length === 0) {
    throw new Error("No certificate authorities visible to certutil -dump.");
  }
  if (cas.length === 1) {
    executor.writeLine(`Using the only CA found: ${cas[0].name}`);
    return cas[0].config;
  }

  const choice = await vscode.window.showQuickPick(
    cas.map((ca) => ca.name),
    { placeHolder: "Pick a certificate authority" }
  );
  if (!choice) {
    throw new Error("Cancelled.");
  }
  return cas.find((ca) => ca.name === choice).config;
}

/** Resolves a project's compose.yml FRONTEND_URL into a host, or throws
 * a descriptive error -- shared by Request Cert and Retrieve Cert,
 * since both key everything off the same host. */
async function hostForProject(folderUri) {
  const composeUri = vscode.Uri.joinPath(folderUri, "compose.yml");
  const doc = await vscode.workspace.openTextDocument(composeUri);
  const lines = doc.getText().split("\n");
  const envIndex = lines.findIndex((text) => /^\s*environment\s*:\s*$/.test(text));
  const values = envIndex === -1 ? {} : environmentBlockValues(lines, envIndex);
  const frontendUrl = values.FRONTEND_URL;
  if (!frontendUrl) {
    throw new Error("compose.yml has no FRONTEND_URL value to derive a host from.");
  }
  const host = hostFromFrontendUrl(frontendUrl);
  if (!host) {
    throw new Error(`Could not determine a host from FRONTEND_URL (${frontendUrl}).`);
  }
  return host;
}

/** Copies whichever of these local certreq output files actually exist
 * back to certs/requests/<host>/<subdir> on the remote host, exactly
 * as-is -- an audit trail of the raw attempt, written regardless of
 * whether the chain ends up looking like a real cert. Shared by Request
 * Cert ("submitted") and Retrieve Cert ("retrieved") -- kept in
 * separate subdirs so neither arc's raw output clobbers the other's. */
async function copyRawCertOutput(requestDirUri, subdir, localPaths) {
  for (const [name, localPath] of localPaths) {
    if (!fs.existsSync(localPath)) {
      continue;
    }
    await vscode.workspace.fs.writeFile(
      vscode.Uri.joinPath(requestDirUri, subdir, name),
      fs.readFileSync(localPath)
    );
  }
}

/** "Smells good"-checks a just-copied-back chain.p7b and, if it looks
 * like a real cert, uploads and runs certTriageScript() to promote it
 * to certs/live/<host>. Returns false (not an error -- callers report
 * that themselves with arc-specific wording) if it still doesn't look
 * ready; throws only if the triage script itself fails after a chain
 * that did look good. Shared by Request Cert and Retrieve Cert. */
async function triageAndPromote(executor, { remoteDir, requestDirUri, host, subdir, chainPath }) {
  const chainText = fs.existsSync(chainPath) ? fs.readFileSync(chainPath, "utf8") : "";
  if (!looksLikeCertFile(chainText)) {
    return false;
  }

  executor.writeLine("Chain looks good -- promoting to certs/live...");
  await vscode.workspace.fs.writeFile(
    vscode.Uri.joinPath(requestDirUri, ".triage.sh"),
    Buffer.from(certTriageScript(), "utf8")
  );
  const triageCode = await executor.executeOnRemote({ command: `sh '${remoteDir}/.triage.sh' '${host}' '${subdir}'` });
  if (triageCode !== 0) {
    throw new Error(`Promoting to certs/live failed with exit code ${triageCode}.`);
  }
  executor.writeLine(`certs/live/${host} updated (cert.pem, chain.pem, fullchain.pem, privkey.pem).`);
  return true;
}

/** Requests (or re-requests -- resubmitting is always allowed, not
 * gated, per vss-prime's design: it just orphans whatever request
 * preceded it, modeling the real process rather than hand-holding) a
 * certificate for the project's FRONTEND_URL host, via the Windows
 * machine's own internal CA through certreq. Ported from vss-prime's
 * certenroll.py, collapsed from its multi-session 4-loop wizard (add
 * CN/SAN, enroll, check pending, promote) into one pass, since here the
 * host comes straight from FRONTEND_URL instead of being collected
 * interactively across runs, and this is a single CodeLens click, not a
 * standing CLI session -- if a CA doesn't issue synchronously, Retrieve
 * Cert is the follow-up, not a "check back later" step of this same
 * action.
 *
 * The private key never leaves the remote host -- only the CSR (public)
 * travels here for certreq to submit, and only the issued chain travels
 * back. certreq's own raw output (files and all) is copied back to
 * certs/requests/<host>/submitted on the remote host exactly as-is
 * regardless of outcome, as an audit trail, before any triaging happens
 * -- "do not rely on exit code too much": certreq uses nonzero exits
 * for legitimate non-error dispositions too (e.g. a request taken under
 * submission on a non-synchronous CA), so whether chain.p7b actually
 * looks like a cert is the real signal, not the exit code. */
function requestCert(folderUri) {
  executeTask("Request Cert", async (executor) => {
    const folders = vscode.workspace.workspaceFolders;
    const studioFolderUri = folders && folders[0] && folders[0].uri;
    if (!studioFolderUri) {
      executor.writeLine("No workspace folder open.");
      return 1;
    }

    const host = await hostForProject(folderUri);
    executor.writeLine(`Requesting a certificate for ${host}...`);

    await addFilesExcludePatterns([`certs/requests/${host}/privkey.pem`, `certs/live/${host}/privkey.pem`]);

    const remoteDir = `${STUDIO_PATH}/certs/requests/${host}`;
    const requestDirUri = vscode.Uri.joinPath(studioFolderUri, "certs", "requests", host);

    executor.writeLine("Generating a CSR and private key on the remote host...");
    const genCode = await executor.executeOnRemote({
      command:
        `mkdir -p '${remoteDir}' && openssl req -new -newkey rsa:4096 -nodes ` +
        `-keyout '${remoteDir}/privkey.pem' -out '${remoteDir}/cert.csr' ` +
        `-subj '/CN=${host}' -addext 'subjectAltName=DNS:${host}'`,
    });
    if (genCode !== 0) {
      executor.writeLine(`CSR generation failed with exit code ${genCode}.`);
      return 1;
    }

    // Stage locally: certreq is a Windows-only tool and needs the CSR
    // on local disk to read. A genuinely ephemeral OS temp dir is fine
    // here -- the remote host (certs/requests/<host>/submitted, written
    // below regardless of outcome) is the durable record, not this.
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `vs-init-cert-${host}-`));
    const submittedDir = path.join(tempDir, "submitted");
    fs.mkdirSync(submittedDir, { recursive: true });

    const csrLocalPath = path.join(tempDir, "request.csr");
    const csrData = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(requestDirUri, "cert.csr"));
    fs.writeFileSync(csrLocalPath, Buffer.from(csrData));

    const caConfig = await pickCaConfig(executor);

    const cerPath = path.join(submittedDir, "cert.pem");
    const chainPath = path.join(submittedDir, "chain.p7b");
    const responsePath = path.join(submittedDir, "response.resp");
    const outTxtPath = path.join(submittedDir, "out.txt");

    executor.writeLine(`Submitting the request to ${caConfig}...`);
    const { code: submitCode, output: submitOutput } = await executor.captureOnSystem({
      gsudo: true,
      command: "certreq",
      args: [
        "-submit", "-f", "-q", "-adminforcemachine",
        "-config", caConfig,
        "-attrib", `CertificateTemplate:${CERT_TEMPLATE}`,
        csrLocalPath, cerPath, chainPath, responsePath,
      ],
    });
    fs.writeFileSync(outTxtPath, submitOutput);
    executor.writeLine(`certreq exited with code ${submitCode} (not necessarily a failure -- see below).`);

    executor.writeLine(`Copying raw certreq output back to ${host}/submitted on the remote host...`);
    await copyRawCertOutput(requestDirUri, "submitted", [
      ["out.txt", outTxtPath],
      ["cert.pem", cerPath],
      ["chain.p7b", chainPath],
      ["response.resp", responsePath],
    ]);

    const promoted = await triageAndPromote(executor, {
      remoteDir,
      requestDirUri,
      host,
      subdir: "submitted",
      chainPath,
    });
    if (!promoted) {
      executor.writeLine(
        `No usable certificate chain yet -- the request may still be pending at the CA. Check ` +
          `${host}/submitted/out.txt and ${host}/submitted/response.resp on the remote host, then ` +
          `use Retrieve Cert once it's issued (the Request ID is in submitted/out.txt).`
      );
      return 1;
    }
    return 0;
  });
}

/** The deferred half of Request Cert, for a CA that didn't issue
 * synchronously: re-reads the Request ID straight out of whatever
 * Request Cert last wrote to certs/requests/<host>/submitted/out.txt on
 * the remote host -- no separate local bookkeeping of pending requests,
 * the remote host's own audit trail IS the state -- picks a CA the same
 * way Request Cert does (nothing persists which one was used before),
 * and runs certreq -retrieve. Deliberately dumb: doesn't check whether
 * a live cert already exists or whether a request actually looks
 * pending first -- it just tries, and certreq's own output says why if
 * there's nothing to retrieve. Raw output goes to
 * certs/requests/<host>/retrieved (not submitted/, so this doesn't
 * clobber the original submission's own audit trail), then triages the
 * same way Request Cert does. */
function retrieveCert(folderUri) {
  executeTask("Retrieve Cert", async (executor) => {
    const folders = vscode.workspace.workspaceFolders;
    const studioFolderUri = folders && folders[0] && folders[0].uri;
    if (!studioFolderUri) {
      executor.writeLine("No workspace folder open.");
      return 1;
    }

    const host = await hostForProject(folderUri);
    const remoteDir = `${STUDIO_PATH}/certs/requests/${host}`;
    const requestDirUri = vscode.Uri.joinPath(studioFolderUri, "certs", "requests", host);

    let submittedOutput;
    try {
      const data = await vscode.workspace.fs.readFile(vscode.Uri.joinPath(requestDirUri, "submitted", "out.txt"));
      submittedOutput = Buffer.from(data).toString("utf8");
    } catch {
      executor.writeLine(`No submitted request found for ${host} -- run Request Cert first.`);
      return 1;
    }

    const requestId = findRequestId(submittedOutput);
    if (!requestId) {
      executor.writeLine(`No Request ID found in ${host}/submitted/out.txt.`);
      return 1;
    }
    executor.writeLine(`Retrieving Request ID ${requestId} for ${host}...`);

    const caConfig = await pickCaConfig(executor, { gsudo: false });

    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), `vs-init-cert-${host}-`));
    const retrievedDir = path.join(tempDir, "retrieved");
    fs.mkdirSync(retrievedDir, { recursive: true });

    const cerPath = path.join(retrievedDir, "cert.pem");
    const chainPath = path.join(retrievedDir, "chain.p7b");
    const responsePath = path.join(retrievedDir, "response.resp");
    const outTxtPath = path.join(retrievedDir, "out.txt");

    // Not run elevated: -adminforcemachine (the thing that actually
    // requires admin rights, by swapping the CA-facing identity to the
    // computer account) is a -submit-only flag, not accepted here at
    // all, and this doesn't use -accept to install into a local store
    // either -- so there's no local-store or -adminforcemachine reason
    // for -retrieve to need elevation. Unverified against a real CA
    // yet, same caveat as the rest of this feature.
    const { code: retrieveCode, output: retrieveOutput } = await executor.captureOnSystem({
      command: "certreq",
      args: ["-retrieve", "-f", "-q", "-config", caConfig, requestId, cerPath, chainPath, responsePath],
    });
    fs.writeFileSync(outTxtPath, retrieveOutput);
    executor.writeLine(`certreq exited with code ${retrieveCode} (not necessarily a failure -- see below).`);

    executor.writeLine(`Copying raw certreq output back to ${host}/retrieved on the remote host...`);
    await copyRawCertOutput(requestDirUri, "retrieved", [
      ["out.txt", outTxtPath],
      ["cert.pem", cerPath],
      ["chain.p7b", chainPath],
      ["response.resp", responsePath],
    ]);

    const promoted = await triageAndPromote(executor, {
      remoteDir,
      requestDirUri,
      host,
      subdir: "retrieved",
      chainPath,
    });
    if (!promoted) {
      executor.writeLine(
        `Still no usable certificate chain -- the request may still be pending. Check ` +
          `${host}/retrieved/out.txt and ${host}/retrieved/response.resp on the remote host, then ` +
          `re-run this action later.`
      );
      return 1;
    }
    return 0;
  });
}

/** Pure. Candidate zones for `host`, most-specific first: for
 * studio.dept.corp.example.com that's [dept.corp.example.com,
 * corp.example.com, example.com] -- every suffix of host with at least
 * two labels left in it (a bare TLD like "com" is never offered).
 * What's registered with the HOST'S OWN zone is the thing deriving the
 * zone, deliberately NOT the remote Linux host's own domain -- a
 * CNAME's target doesn't need to share a zone with its own name at all
 * (that's not a DNS requirement anywhere), so comparing them was never
 * actually load-bearing. Doesn't try to guess the "real" registrable
 * domain via a public-suffix list either -- just offers every
 * structurally possible split and lets the caller (or, for more than
 * one candidate, the user via a picker) decide which one is actually
 * the AD zone. Empty for a two-label-or-shorter host (e.g.
 * "example.com" itself) -- nothing to strip at all. */
function zoneCandidates(host) {
  const labels = host.split(".");
  const candidates = [];
  for (let i = 1; i < labels.length - 1; i++) {
    candidates.push(labels.slice(i).join("."));
  }
  return candidates;
}

/** Pure. The record name to pass to -Name (relative to the zone, not
 * the full FQDN), or null if `host` IS the zone -- a CNAME can't live
 * at a zone's own apex (that node has to carry SOA/NS records, which
 * can't coexist with a CNAME). */
function relativeRecordName(host, zone) {
  return host === zone ? null : host.slice(0, host.length - zone.length - 1);
}

/** Pure. Escapes a value for embedding as a PowerShell single-quoted
 * string literal (doubling any embedded "'"). */
function psQuote(value) {
  return `'${value.replace(/'/g, "''")}'`;
}

/** Pure. Pulls the message back out of buildCnameUpsertScript's own
 * "VS_INIT_CNAME_ERROR: ..." marker, or null if that marker isn't
 * present. That script routes every failure through this plain-text
 * marker specifically so a caught exception never has to reach
 * PowerShell's native Error stream. */
function findCnameScriptError(output) {
  const match = output.match(/VS_INIT_CNAME_ERROR:\s*(.+)/);
  return match ? match[1].trim() : null;
}

/** Pure. The upsert script itself: Get, then no-op if already correct,
 * remove+recreate if it exists pointing somewhere else, or just create
 * if absent -- three explicit, unambiguous branches, rather than
 * trusting that re-running Add-DnsServerResourceRecordCName silently
 * overwrites (plausible, but not something to bet correctness on
 * without having run it against a real DC). Each branch prints its own
 * marker line so the caller can tell which happened from the captured
 * output without parsing structured PowerShell objects over a plain
 * text pipe.
 *
 * Everything that can fail is wrapped in try/catch with
 * $ErrorActionPreference = 'Stop' (overridden back to SilentlyContinue
 * just for the Get -- "not found yet" there is an expected outcome, not
 * a failure), and any caught exception is reported via its own
 * Write-Output marker rather than being allowed to actually reach
 * PowerShell's native Error stream. That's not just tidiness: when
 * PowerShell's host isn't attached to a real console -- exactly the
 * case every time this runs, spawned and piped -- anything that lands
 * on the Error/Warning/Verbose/Debug streams gets serialized as CLIXML
 * instead of plain text (confirmed as the source of "weird" captured
 * output). Write-Output (the success/pipeline stream) never gets that
 * treatment, so routing every failure through it instead is what
 * actually avoids CLIXML, not any PowerShell flag -- there isn't one. */
function buildCnameUpsertScript({ zone, name, target, computerName }) {
  const zoneQ = psQuote(zone);
  const nameQ = psQuote(name);
  const targetQ = psQuote(target);
  const computerQ = psQuote(computerName);
  return [
    `$ErrorActionPreference = 'Stop'`,
    `$zone = ${zoneQ}`,
    `$name = ${nameQ}`,
    `$target = ${targetQ}`,
    `$dc = ${computerQ}`,
    `try {`,
    `  $existing = Get-DnsServerResourceRecord -ZoneName $zone -Name $name -RRType CName -ComputerName $dc -ErrorAction SilentlyContinue`,
    `  if ($existing) {`,
    `    if ($existing.RecordData.HostNameAlias -ne $target) {`,
    `      $existing | Remove-DnsServerResourceRecord -ZoneName $zone -ComputerName $dc -Force`,
    `      Add-DnsServerResourceRecordCName -ZoneName $zone -Name $name -HostNameAlias $target -ComputerName $dc`,
    `      Write-Output 'VS_INIT_CNAME_UPDATED'`,
    `    } else {`,
    `      Write-Output 'VS_INIT_CNAME_ALREADY_CORRECT'`,
    `    }`,
    `  } else {`,
    `    Add-DnsServerResourceRecordCName -ZoneName $zone -Name $name -HostNameAlias $target -ComputerName $dc`,
    `    Write-Output 'VS_INIT_CNAME_CREATED'`,
    `  }`,
    `} catch {`,
    `  Write-Output "VS_INIT_CNAME_ERROR: $($_.Exception.Message)"`,
    `}`,
  ].join("\n");
}

/** Pure. Encodes `script` for PowerShell's -EncodedCommand parameter --
 * base64 of the UTF-16LE bytes (.NET's "Unicode" encoding), exactly
 * what PowerShell itself documents -EncodedCommand as expecting.
 *
 * Needed in place of -Command <script> because a multi-line,
 * quote-heavy script string has to survive being re-quoted at every
 * layer between here and powershell.exe actually parsing it: Node's own
 * Windows argv-to-command-line quoting, then gsudo relaying that command
 * line to its elevated broker. Any one of those re-quoting/re-escaping
 * passes can corrupt or truncate it -- confirmed in practice: the exact
 * same script text runs fine pasted into an interactive PowerShell
 * session (elevated or not), but silently failed through this spawn
 * chain. Base64 has no characters that need escaping at all, so there's
 * nothing left for any layer to get wrong. */
function encodePowerShellCommand(script) {
  return Buffer.from(script, "utf16le").toString("base64");
}

/** Runs a PowerShell script via captureOnSystem, wrapped so its output
 * never reaches PowerShell's CLIXML serialization path. Confirmed
 * empirically (reproduced through the exact real spawn chain: gsudo +
 * -EncodedCommand + piped, console-less stdio) that the trigger is
 * specifically -EncodedCommand -- a direct spawn and a gsudo-wrapped
 * spawn both stayed perfectly clean using -File; switching only the
 * invocation mode to -EncodedCommand reproduced the "#< CLIXML" blob
 * immediately. Two things fix it, both needed:
 *   - `& { <script> } *>&1 | Out-String` -- *>&1 redirects every
 *     numbered stream (Success/Error/Warning/Verbose/Debug/Information)
 *     into the success stream, and Out-String forces it all through
 *     PowerShell's own formatting *inside the process* before anything
 *     crosses the OS pipe boundary -- so there's nothing left for the
 *     non-interactive host to serialize. -Width is pinned high as a
 *     defensive measure against Out-String wrapping a long single-line
 *     message (confirmed NOT to happen by default in this exact
 *     console-less invocation shape, even at 2000 characters -- but
 *     cheap enough to guard explicitly rather than rely on an
 *     undocumented default).
 *   - $ProgressPreference = 'SilentlyContinue' -- Progress is NOT one
 *     of the numbered streams *>&1 covers (it has no redirect number at
 *     all; it's a separate host callback), so without this, a one-time
 *     "Preparing modules for first use" progress message (first module
 *     auto-load in a session) still shows up as its own separate
 *     "#< CLIXML" blob even with the *>&1 | Out-String wrap in place --
 *     confirmed by reproducing it, then confirming this line removes it.
 *
 * This is the one place any future PowerShell-based action should run
 * its script through, rather than reinventing this wrapping per
 * script -- certutil/certreq calls elsewhere don't go through here at
 * all (they're not PowerShell), so this only ever affects actual
 * PowerShell invocations. */
function runPowerShellScript(executor, script, { gsudo = false } = {}) {
  const wrapped = [`$ProgressPreference = 'SilentlyContinue'`, `& {`, script, `} *>&1 | Out-String -Width 4096`].join(
    "\n"
  );
  return executor.captureOnSystem({
    gsudo,
    command: "powershell.exe",
    args: ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(wrapped)],
  });
}

/** "Pings" a candidate name server by asking it directly (not the
 * system's default resolver) to resolve the zone's own NS records again
 * -- Node's dns.Resolver can direct a query at a specific server rather
 * than whatever the OS has configured, via setServers(); that takes an
 * IP, not a hostname, hence the lookup() first. A successful answer
 * confirms the server is both reachable and actually serving the zone,
 * which a bare connectivity probe wouldn't -- the real later work goes
 * over WinRM/DCOM (a different port entirely), but this reuses the one
 * protocol a name server is guaranteed to speak by definition. Never
 * throws -- resolves false on any failure (lookup failure, query
 * failure, or timeout) so callers can just try the next candidate. */
async function pingNameServer(nsHost, zone, timeoutMs = 3000) {
  try {
    const { address } = await dns.promises.lookup(nsHost);
    const resolver = new dns.promises.Resolver();
    resolver.setServers([address]);
    const query = resolver.resolveNs(zone);
    const timeout = new Promise((_resolve, reject) => setTimeout(() => reject(new Error("timed out")), timeoutMs));
    await Promise.race([query, timeout]);
    return true;
  } catch {
    return false;
  }
}

/** "Very optimistic": point the project's FRONTEND_URL hostname at the
 * remote host via a CNAME, using Windows' own DnsServer PowerShell
 * module against whichever DNS server actually answers for the zone.
 * No state is persisted or checked beforehand (same "fairly dumb"
 * spirit as Request/Retrieve Cert) -- every run re-derives everything
 * from scratch and upserts, so resubmitting is always safe.
 *
 * The zone is derived from FRONTEND_URL's own host, NOT compared
 * against the remote Linux host's domain -- a CNAME's target doesn't
 * need to share a zone with its own name (nothing in DNS requires
 * that), so that comparison was never actually load-bearing; it just
 * made the action refuse to run for perfectly valid setups where the
 * two domains happen to differ. The Linux host's FQDN is still what
 * the record points AT, just not what decides which zone to register
 * it in.
 *
 * Zone and name server are both found authoritatively, not guessed at
 * or asked about: deep, actually-delegated DNS zones (a real separate
 * zone cut at every naming level) are rare in practice -- most
 * environments have one zone (often the AD domain itself, which can
 * still be multi-label) and everything else is just a multi-label
 * record name living inside it, not a chain of nested zones. So rather
 * than presenting zoneCandidates(host) as an ambiguous choice, each
 * candidate (most-specific first, the host itself excluded, a bare TLD
 * excluded) is probed with a real NS lookup -- the first one that
 * actually has NS records IS the zone, by definition (that's what makes
 * something a zone). Likewise for picking which of that zone's name
 * servers to actually talk to: each is "pinged" by querying it directly
 * for the zone's own NS records (pingNameServer) rather than asked
 * about via a picker -- the first one that actually answers is used.
 * Both loops fail closed (clear message, stop) rather than falling back
 * to an unverified guess if nothing answers.
 *
 * The one thing genuinely worth a human checkpoint is the CNAME's
 * target: the remote host's own `hostname -f` is read and used as the
 * default, but shown back via an input box for confirmation (or
 * editing) before anything is written, rather than trusted blindly.
 *
 * Assumes the DnsServer module's cmdlets already exist -- deliberately
 * doesn't check for or install RSAT: DNS Server Tools itself at runtime
 * (Get-WindowsCapability needs elevation too, confirmed, so there's no
 * free unelevated check to skip asking with; an install dialog on every
 * use for what's meant to be a quick CodeLens click was also just
 * annoying). That's a bootstrap-time decision instead (dnstools.py,
 * asked about once during setup, same as SSH auto-logon). If the
 * module genuinely isn't installed, the PowerShell call below just
 * fails and says so.
 *
 * Deliberately NOT WMI (the classic root\MicrosoftDNS provider is
 * decades-old and, since DCOM hardening fully landed in March 2023 with
 * no opt-out, often can't even connect without extra auth-level
 * configuration) and NOT raw dnsapi.dll calls (those are MS-RPC methods
 * with a type-tagged-union wire format -- real engineering risk to
 * hand-rebuild via ctypes, where a wrong struct layout crashes natively
 * instead of raising a catchable error). The actively-maintained
 * equivalent is the CIM-based DnsServer module, reached the same way
 * certreq/certutil already are: a plain elevated PowerShell call. */
function registerCname(folderUri) {
  executeTask("Register CNAME", async (executor) => {
    const folders = vscode.workspace.workspaceFolders;
    const studioFolderUri = folders && folders[0] && folders[0].uri;
    if (!studioFolderUri) {
      executor.writeLine("No workspace folder open.");
      return 1;
    }

    const host = await hostForProject(folderUri);

    const candidates = zoneCandidates(host);
    if (candidates.length === 0) {
      executor.writeLine(`${host} has no parent domain to register a CNAME zone under.`);
      return 1;
    }

    executor.writeLine(`Looking for the real zone among: ${candidates.join(", ")}...`);
    let zone, nsHosts;
    for (const candidate of candidates) {
      try {
        const records = await dns.promises.resolveNs(candidate);
        if (records.length > 0) {
          zone = candidate;
          nsHosts = records;
          break;
        }
      } catch {
        // No NS records at this level -- it's not a real zone cut, just
        // part of a multi-label record name inside a shallower zone.
        // Try the next, shallower candidate.
      }
    }
    if (!zone) {
      executor.writeLine(`Could not find a DNS zone for ${host} (tried: ${candidates.join(", ")}).`);
      return 1;
    }
    const name = relativeRecordName(host, zone);
    executor.writeLine(`Zone: ${zone}   Record: ${name}`);

    executor.writeLine(`Checking which of ${zone}'s name servers actually answers (${nsHosts.join(", ")})...`);
    let dcHost = null;
    for (const candidateNs of nsHosts) {
      if (await pingNameServer(candidateNs, zone)) {
        dcHost = candidateNs;
        break;
      }
    }
    if (!dcHost) {
      executor.writeLine(`None of ${zone}'s name servers answered a direct query (tried: ${nsHosts.join(", ")}).`);
      return 1;
    }
    executor.writeLine(`Using ${dcHost} as the DNS server.`);

    executor.writeLine("Reading the remote host's own FQDN...");
    const fqdnMarker = `/tmp/vs-init-cname-fqdn-${Date.now()}.txt`;
    const fqdnCode = await executor.executeOnRemote({ command: `hostname -f > '${fqdnMarker}'` });
    if (fqdnCode !== 0) {
      executor.writeLine(`Could not read the remote host's FQDN (hostname -f exited with code ${fqdnCode}).`);
      return 1;
    }
    const fqdnUri = vscode.Uri.from({ scheme: studioFolderUri.scheme, authority: studioFolderUri.authority, path: fqdnMarker });
    const fqdnData = await vscode.workspace.fs.readFile(fqdnUri);
    const linuxFqdn = Buffer.from(fqdnData).toString("utf8").trim();

    const confirmedTarget = await vscode.window.showInputBox({
      prompt: `CNAME target for ${name}.${zone}`,
      value: linuxFqdn,
    });
    if (!confirmedTarget) {
      executor.writeLine("Cancelled.");
      return 1;
    }

    const target = confirmedTarget.endsWith(".") ? confirmedTarget : `${confirmedTarget}.`;
    const script = buildCnameUpsertScript({ zone, name, target, computerName: dcHost });
    executor.writeLine("Running the following PowerShell script (elevated):");
    executor.writeLine(script);
    const { code, output } = await runPowerShellScript(executor, script, { gsudo: true });

    const scriptError = findCnameScriptError(output);
    if (output.includes("VS_INIT_CNAME_CREATED")) {
      executor.writeLine(`Created ${name}.${zone} -> ${confirmedTarget}.`);
    } else if (output.includes("VS_INIT_CNAME_UPDATED")) {
      executor.writeLine(`Updated ${name}.${zone} -> ${confirmedTarget} (it pointed somewhere else before).`);
    } else if (output.includes("VS_INIT_CNAME_ALREADY_CORRECT")) {
      executor.writeLine(`${name}.${zone} already points at ${confirmedTarget}; nothing to do.`);
    } else if (scriptError) {
      executor.writeLine(
        `DNS update failed: ${scriptError}` +
          (scriptError.includes("is not recognized")
            ? " -- the DnsServer PowerShell module (RSAT: DNS Server Tools) isn't installed; the bootstrap tool offers to install it during setup."
            : "")
      );
      return 1;
    } else {
      executor.writeLine(`Unexpected output (exit code ${code}):\n${output}`);
      return 1;
    }
    return 0;
  });
}

/** Pure. Splits a tag into alternating digit/non-digit runs, e.g.
 * "v1.1.1184.377622" -> ["v","1",".","1",".","1184",".","377622"].
 * Empty array for an empty tag. */
function tokenizeTag(tag) {
  return tag.match(/\d+|\D+/g) || [];
}

/** Pure. Is `tag` a "flavor" variant rather than a real, pickable
 * version -- confirmed against two real registries' actual tag lists
 * (ghcr.io/vertigis/studio/base, docker.io/library/caddy). Every
 * non-digit run has to be "trivial" to NOT count as flavor text: after
 * stripping any leading punctuation, at most one letter can remain.
 * That covers a bare separator like "." or "-" (nothing left after
 * stripping), a leading version-prefix letter like the "v" in
 * "v1.1.1184.377622" (nothing to strip, already just one letter), AND
 * -- the case real data actually exposed -- a single-letter marker
 * elsewhere in the tag, like the "-r" in GHCR's own
 * "v1.1.598.224400-r13470513045" build-id suffix (strip the "-",
 * one letter remains). A naive "only the very first character is
 * exempt" version of this rule wrongly flagged that real GHCR tag
 * shape as flavored -- caught by testing against the actual tag list,
 * not just hand-picked examples. Genuine flavor text ("-alpine",
 * "-builder-windowsservercore-ltsc", leading "nanoserver-ltsc") is
 * always more than one letter after stripping, so it's still caught
 * the same way regardless of whether it sits before, between, or after
 * the tag's numeric runs -- no separate leading/internal/trailing
 * cases needed. A tag with no digits at all (e.g. "latest",
 * "nanoserver") is also considered flavored here -- it's not a
 * comparable version either way. */
function isFlavoredTag(tag) {
  return tokenizeTag(tag).some((token) => {
    if (/^\d+$/.test(token)) {
      return false;
    }
    const stripped = token.replace(/^[^a-zA-Z0-9]+/, "");
    return !/^[a-zA-Z]?$/.test(stripped);
  });
}

/** Pure. The tag's numeric runs, parsed as BigInt (cheap correctness
 * insurance against a pathological huge build number -- not that
 * that's likely, Number would almost certainly be fine too, but this
 * costs nothing). Empty array for a tag with no digits at all. */
function tagVersionKey(tag) {
  return tokenizeTag(tag)
    .filter((token) => /^\d+$/.test(token))
    .map((token) => BigInt(token));
}

/** Pure. Compares two tags by their numeric runs, component by
 * component, as actual numbers -- not strings. This is the whole point:
 * confirmed empirically that Docker Hub's own tag list is plain lexical
 * string order, which gets "2.10.0" sorting before "2.2.0" (wrong --
 * 2.10.0 is newer). A missing trailing component compares as 0, so "2"
 * sorts as equivalent to "2.0.0" relative to "2.11.7". Standard
 * comparator convention: negative if a < b, positive if a > b, 0 if
 * equal (by every compared component). */
function compareTagVersions(a, b) {
  const keyA = tagVersionKey(a);
  const keyB = tagVersionKey(b);
  const length = Math.max(keyA.length, keyB.length);
  for (let i = 0; i < length; i++) {
    const diff = (keyA[i] ?? 0n) - (keyB[i] ?? 0n);
    if (diff !== 0n) {
      return diff < 0n ? -1 : 1;
    }
  }
  return 0;
}

/** Pure. The real, pickable versions out of a raw tags list -- no
 * flavor variants, no non-version tags (latest and friends), sorted
 * ascending (oldest first; callers wanting newest-first just reverse
 * it). "latest" is deliberately excluded here even though it'd fail
 * the flavor check anyway (no digits) -- it's handled as a separately
 * hard-pinned choice by the caller instead of flowing through version
 * comparison at all. */
function cleanVersionTags(tags) {
  return tags
    .filter((tag) => tag !== "latest" && !isFlavoredTag(tag) && tagVersionKey(tag).length > 0)
    .sort(compareTagVersions);
}

/** Pure. Parses `realm="...",service="...",scope="..."` (plus the
 * leading "Bearer " this is always found after) out of a 401 response's
 * WWW-Authenticate header -- the standard OCI Distribution Spec
 * anonymous-auth challenge. Confirmed against two real registries'
 * actual headers (ghcr.io and Docker Hub both use this exact shape,
 * just with different realm/service values). Returns {} for a header
 * that doesn't match at all (e.g. a non-Bearer challenge). */
function parseWwwAuthenticate(header) {
  const result = {};
  const pattern = /(\w+)="([^"]*)"/g;
  let match;
  while ((match = pattern.exec(header || "")) !== null) {
    result[match[1]] = match[2];
  }
  return result;
}

/** Pure. Splits a compose.yml image reference into its registry,
 * repository, and tag -- e.g. "ghcr.io/vertigis/studio/base:latest" ->
 * {registry: "ghcr.io", repository: "vertigis/studio/base", tag:
 * "latest"}, "caddy:2" -> {registry: "docker.io", repository:
 * "library/caddy", tag: "2"} (Docker Hub's implicit "library/" namespace
 * for an unqualified official image name). `name` is the exact
 * substring before the tag (or the whole reference, if there's no tag)
 * -- kept verbatim, not reconstructed from registry+repository, so
 * writing a new tag back never changes how the image was originally
 * written (never turns "caddy:2" into "docker.io/library/caddy:2" just
 * because that's technically what it resolves to). A colon is only
 * treated as the tag separator if it comes after the first "/" (so a
 * registry's own :port, e.g. "myregistry.example.com:5000/image:1.0",
 * isn't mistaken for one). */
function parseImageRef(image) {
  const slashIndex = image.indexOf("/");
  const tagIndex = image.lastIndexOf(":");
  const hasTag = tagIndex !== -1 && (slashIndex === -1 || tagIndex > slashIndex);
  const name = hasTag ? image.slice(0, tagIndex) : image;
  const tag = hasTag ? image.slice(tagIndex + 1) : null;

  const firstSegment = name.split("/")[0];
  const looksLikeRegistry = firstSegment.includes(".") || firstSegment.includes(":") || firstSegment === "localhost";
  const registry = looksLikeRegistry ? firstSegment : "docker.io";
  const repository = looksLikeRegistry
    ? name.slice(firstSegment.length + 1)
    : name.includes("/")
      ? name
      : `library/${name}`;

  return { registry, repository, name, tag };
}

/** Pure. "docker.io" (the conventional registry identifier used in
 * image references, and what's shown to the user) isn't actually the
 * host that serves the registry API -- that's registry-1.docker.io.
 * docker.io itself serves Docker Hub's web UI; hitting
 * https://docker.io/v2/... returns an HTML page (confirmed -- the
 * actual bug this was written to fix: "<!DOCTYPE ..." where JSON was
 * expected), not a JSON 401 challenge. Every other registry (ghcr.io
 * included) uses the same host for both purposes, so this is a
 * one-off translation, not a general pattern. */
function registryApiHost(registry) {
  return registry === "docker.io" ? "registry-1.docker.io" : registry;
}

/** Fetches every tag for `registry`/`repository` via the plain OCI
 * Distribution Spec anonymous-pull flow: an unauthenticated request,
 * a 401 with a WWW-Authenticate challenge, an anonymous token from
 * whatever realm/service/scope that challenge names (reused verbatim,
 * not guessed at), then the real request again with that bearer token.
 * No credentials needed for a public image -- confirmed working this
 * way against both ghcr.io and Docker Hub. Aborts along with the
 * executor's own signal, same as every other network call in this
 * extension. */
async function fetchTags(registry, repository, signal) {
  const url = `https://${registryApiHost(registry)}/v2/${repository}/tags/list`;
  const first = await fetch(url, { signal });
  if (first.status === 401) {
    const { realm, service, scope } = parseWwwAuthenticate(first.headers.get("www-authenticate"));
    if (!realm) {
      throw new Error(`${registry} asked for auth but didn't say how (no usable WWW-Authenticate header).`);
    }
    const tokenUrl = new URL(realm);
    if (service) {
      tokenUrl.searchParams.set("service", service);
    }
    if (scope) {
      tokenUrl.searchParams.set("scope", scope);
    }
    const tokenResponse = await fetch(tokenUrl.toString(), { signal });
    const { token } = await tokenResponse.json();
    const authed = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal });
    if (!authed.ok) {
      throw new Error(`${registry} rejected the authenticated tags request (HTTP ${authed.status}).`);
    }
    const data = await authed.json();
    return data.tags || [];
  }
  if (!first.ok) {
    throw new Error(`${registry} returned HTTP ${first.status} for ${repository}.`);
  }
  const data = await first.json();
  return data.tags || [];
}

/** Lets the user pick a new tag for the image on this specific
 * compose.yml line, straight from the real registry's own tag list --
 * no local guessing about what versions exist. "latest" is always
 * offered first regardless of what cleanVersionTags finds (hard-pinned,
 * since it's always a valid choice for any image whether or not the
 * registry's tag list happens to include it in a form that'd survive
 * the flavor filter), followed by every real version, newest first. */
function pickVersion(documentUri, line) {
  executeTask("Pick Version", async (executor) => {
    const doc = await vscode.workspace.openTextDocument(documentUri);
    const lineText = doc.lineAt(line).text;
    const currentValue = extractLineValue(lineText);
    if (!currentValue) {
      executor.writeLine("Could not read an image reference on this line.");
      return 1;
    }

    const { registry, repository, name } = parseImageRef(currentValue);
    executor.writeLine(`Looking up tags for ${registry}/${repository}...`);
    let tags;
    try {
      tags = await fetchTags(registry, repository, executor.signal);
    } catch (err) {
      executor.writeLine(`Could not fetch tags: ${err.message}`);
      return 1;
    }

    const versions = cleanVersionTags(tags).reverse();
    executor.writeLine(`${versions.length} real version(s) found (plus latest).`);
    const choices = ["latest", ...versions];
    const picked = await vscode.window.showQuickPick(choices, { placeHolder: `Pick a version for ${repository}` });
    if (!picked) {
      executor.writeLine("Cancelled.");
      return 1;
    }

    const newValue = `${name}:${picked}`;
    const changed = await applyTextEdit(documentUri, (text) => {
      const lines = text.split("\n");
      const updated = replaceLineValue(lines[line], newValue);
      if (updated === null || updated === lines[line]) {
        return null;
      }
      lines[line] = updated;
      return lines.join("\n");
    });
    executor.writeLine(changed ? `Updated to ${newValue}.` : `${repository} is already pinned to ${picked}.`);
    return 0;
  });
}

function buildCodeLenses(document) {
  const lines = [];
  for (let i = 0; i < document.lineCount; i++) {
    lines.push(document.lineAt(i).text);
  }

  const folderUri = vscode.Uri.joinPath(document.uri, "..");
  const commandFor = {
    accountId: "vsInit.findAccountId",
    trustAnchors: "vsInit.transferTrustAnchors",
    caddyfile: "vsInit.buildCaddyfile",
    registerApp: "vsInit.registerOrUpdateApp",
    updateApp: "vsInit.registerOrUpdateApp",
    requestCert: "vsInit.requestCert",
    retrieveCert: "vsInit.retrieveCert",
    registerCname: "vsInit.registerCname",
    pickVersion: "vsInit.pickVersion",
  };
  // Build Caddyfile scans every project's compose.yml, not just the
  // clicked one, so it doesn't need (and isn't passed) a folderUri.
  // registerApp/updateApp also pass their own kind through, since
  // registerOrUpdateApp picks its arc from whichever lens was actually
  // clicked, not from compose.yml's current state. pickVersion needs
  // the document itself (and which line) rather than the folder -- it
  // edits one specific image: line, not something folder-scoped.
  return findLensSpecs(lines).map(({ line, title, kind }) => {
    const range = new vscode.Range(line, 0, line, 0);
    const args =
      kind === "caddyfile"
        ? []
        : kind === "registerApp" || kind === "updateApp"
          ? [folderUri, kind]
          : kind === "pickVersion"
            ? [document.uri, line]
            : [folderUri];
    return new vscode.CodeLens(range, { title, command: commandFor[kind], arguments: args });
  });
}

/** @param {vscode.ExtensionContext} context */
function activate(context) {
  function looksLikeOurs() {
    const folderPaths = (vscode.workspace.workspaceFolders || []).map((f) => f.uri.path);
    return computeLooksLikeOurs(vscode.env.remoteName, folderPaths);
  }

  const codeLensChangeEmitter = new vscode.EventEmitter();

  function refreshGating() {
    vscode.commands.executeCommand("setContext", "vsInit.looksLikeOurs", looksLikeOurs());
    codeLensChangeEmitter.fire();
  }

  refreshGating();
  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(refreshGating));

  const findAccountId = vscode.commands.registerCommand("vsInit.findAccountId", (folderUri) => {
    findMyAccountId(folderUri);
  });

  const transferTrustAnchorsCommand = vscode.commands.registerCommand("vsInit.transferTrustAnchors", () => {
    transferTrustAnchors();
  });

  const buildCaddyfileCommand = vscode.commands.registerCommand("vsInit.buildCaddyfile", () => {
    buildCaddyfile();
  });

  const registerOrUpdateAppCommand = vscode.commands.registerCommand(
    "vsInit.registerOrUpdateApp",
    (folderUri, kind) => {
      registerOrUpdateApp(folderUri, kind);
    }
  );

  const requestCertCommand = vscode.commands.registerCommand("vsInit.requestCert", (folderUri) => {
    requestCert(folderUri);
  });

  const retrieveCertCommand = vscode.commands.registerCommand("vsInit.retrieveCert", (folderUri) => {
    retrieveCert(folderUri);
  });

  const registerCnameCommand = vscode.commands.registerCommand("vsInit.registerCname", (folderUri) => {
    registerCname(folderUri);
  });

  const pickVersionCommand = vscode.commands.registerCommand("vsInit.pickVersion", (documentUri, line) => {
    pickVersion(documentUri, line);
  });

  // Gated the same way the side panel is -- without this, the lens
  // fires on any compose.yml anywhere, not just ours.
  const codeLensProvider = vscode.languages.registerCodeLensProvider(
    { pattern: "**/compose.yml" },
    {
      onDidChangeCodeLenses: codeLensChangeEmitter.event,
      provideCodeLenses: (document) => (looksLikeOurs() ? buildCodeLenses(document) : []),
    }
  );

  // Singleton like currentView/currentTerminal elsewhere in this file --
  // clicking Guidance again reveals the same panel instead of piling up
  // tabs.
  let currentGuidancePanel;

  function showGuidance() {
    const hideWelcome = vscode.workspace.getConfiguration("vsInit").get("hideWelcome", false);
    if (currentGuidancePanel) {
      currentGuidancePanel.webview.html = getGuidanceHtml(currentGuidancePanel.webview, context.extensionUri, hideWelcome);
      currentGuidancePanel.reveal();
      return;
    }

    // One, not Beside -- takes the full editor area as its own tab
    // rather than forcing a 50/50 split with whatever compose.yml is
    // already open there (also column One). Opens as a separate tab in
    // that same column, not a replacement of what's already open.
    const panel = vscode.window.createWebviewPanel(
      "vsInitGuidance",
      "VertiGIS Studio Guidance",
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "media")],
      }
    );
    panel.webview.html = getGuidanceHtml(panel.webview, context.extensionUri, hideWelcome);
    panel.webview.onDidReceiveMessage((message) => {
      if (message.type === "setHideWelcome") {
        vscode.workspace
          .getConfiguration("vsInit")
          .update("hideWelcome", message.value, vscode.ConfigurationTarget.Workspace);
      }
    });
    panel.onDidDispose(() => {
      if (currentGuidancePanel === panel) {
        currentGuidancePanel = undefined;
      }
    });
    currentGuidancePanel = panel;
  }

  // Shown once per window, the first time this folder is recognized --
  // not re-shown just because the CodeLens/gating re-runs (e.g. on an
  // unrelated workspace-folder change), and never at all once the
  // workspace's own vsInit.hideWelcome setting says not to (provision.sh
  // writes that setting -- defaulted to false, i.e. "show it" -- into
  // every freshly-provisioned workspace's own settings.json).
  if (looksLikeOurs() && !vscode.workspace.getConfiguration("vsInit").get("hideWelcome", false)) {
    showGuidance();
  }

  // Separate from Guidance and not gated on hideWelcome -- the side
  // panel's activity bar icon has no other way to catch a first-time
  // user's eye (see PLAN.md's note on this), so it forces itself open
  // whenever this window looks like it just started fresh in this
  // workspace: no editors open yet is the best available proxy for that
  // (VS Code normally restores a workspace's previous tabs on reopen, so
  // their absence suggests nothing carried over from a prior session).
  // Same one-time-at-activation timing as the Guidance check above, not
  // re-run from refreshGating().
  const hasAnyEditors = vscode.window.tabGroups.all.some((group) => group.tabs.length > 0);
  if (looksLikeOurs() && !hasAnyEditors) {
    vscode.commands.executeCommand("workbench.view.extension.vsInit");
  }

  let currentView;

  async function refreshMainView() {
    if (!currentView) {
      return;
    }
    const folders = vscode.workspace.workspaceFolders;
    const studioFolderUri = folders && folders[0] && folders[0].uri;
    const projects = studioFolderUri ? await listProjects(studioFolderUri) : [];
    currentView.webview.html = getMainViewHtml(currentView.webview, context.extensionUri, projects);
  }

  const mainView = vscode.window.registerWebviewViewProvider("vsInit.mainView", {
    async resolveWebviewView(webviewView) {
      currentView = webviewView;
      webviewView.webview.options = {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(context.extensionUri, "media")],
      };
      webviewView.onDidDispose(() => {
        if (currentView === webviewView) {
          currentView = undefined;
        }
      });
      webviewView.webview.onDidReceiveMessage(async (message) => {
        if (message.type === "openGuidance") {
          showGuidance();
          return;
        }
        const folders = vscode.workspace.workspaceFolders;
        const studioFolderUri = folders && folders[0] && folders[0].uri;
        if (!studioFolderUri) {
          return;
        }
        if (message.type === "addProject") {
          const { composeUri } = await addProject(studioFolderUri, message.kind);
          const doc = await vscode.workspace.openTextDocument(composeUri);
          await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
          await vscode.commands.executeCommand("revealInExplorer", composeUri);
          await refreshMainView();
        } else if (message.type === "openProject") {
          const uri = await findComposeUri(studioFolderUri, message.name);
          if (uri) {
            const doc = await vscode.workspace.openTextDocument(uri);
            await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
            await vscode.commands.executeCommand("revealInExplorer", uri);
          }
        }
      });
      await refreshMainView();
    },
  });

  context.subscriptions.push(
    findAccountId,
    transferTrustAnchorsCommand,
    buildCaddyfileCommand,
    registerOrUpdateAppCommand,
    requestCertCommand,
    retrieveCertCommand,
    registerCnameCommand,
    pickVersionCommand,
    codeLensProvider,
    codeLensChangeEmitter,
    mainView
  );
}

/** The "Getting Started"/walkthrough content. Written for the audience
 * PLAN.md itself describes: Windows Enterprise admins, not Linux
 * people -- every concept this extension assumes (Remote-SSH, compose
 * projects, what a CodeLens action actually does and why) gets spelled
 * out here in plain language, not just linked to elsewhere. Placed in
 * the editor (a WebviewPanel), not the sidebar -- there's enough
 * content here that it needs real width, and it's the kind of thing a
 * user reads once up front then occasionally refers back to, not
 * something that should compete for space with the side panel's own
 * project list. */
function getGuidanceHtml(webview, extensionUri, hideWelcome) {
  const bannerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "banner.svg"));

  return `<!DOCTYPE html>
<html>
<head>
<style>
  body {
    margin: 0;
    padding: 1.5rem 2rem 3rem;
    max-width: 50rem;
    background: var(--vscode-editor-background);
    color: var(--vscode-editor-foreground);
    font-family: var(--vscode-font-family);
    line-height: 1.5;
  }
  img.banner {
    width: 100%;
    max-width: 28rem;
    height: auto;
    margin-bottom: 0.5rem;
  }
  h1 { font-size: 1.4em; margin: 1.5rem 0 0.5rem; }
  h2 {
    font-size: 1.15em;
    margin: 2rem 0 0.5rem;
    padding-bottom: 0.25rem;
    border-bottom: 1px solid var(--vscode-widget-border, var(--vscode-panel-border));
  }
  h3 { font-size: 1em; margin: 1.25rem 0 0.4rem; }
  p { margin: 0.5rem 0; }
  code {
    background: var(--vscode-textCodeBlock-background);
    padding: 0.1rem 0.3rem;
    border-radius: 3px;
    font-family: var(--vscode-editor-font-family, monospace);
  }
  ol, ul { padding-left: 1.4rem; }
  li { margin-bottom: 0.4rem; }
  .cue {
    border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border));
    border-radius: 6px;
    padding: 0.75rem 1rem;
    margin: 0.75rem 0;
  }
  .cue h3 { margin-top: 0; }
  .cue .where {
    display: inline-block;
    font-size: 0.85em;
    opacity: 0.75;
    margin-bottom: 0.35rem;
  }
  .footer {
    margin-top: 2.5rem;
    padding-top: 1rem;
    border-top: 1px solid var(--vscode-widget-border, var(--vscode-panel-border));
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.9em;
    opacity: 0.85;
  }
</style>
</head>
<body>
  <img class="banner" src="${bannerUri}" alt="VertiGIS Studio" />

  <p>This Windows machine is set up to manage a <strong>VertiGIS Studio</strong> deployment that
  actually <em>runs</em> somewhere else: a separate Linux server, using Docker. You don't need to
  become a Linux person to use it -- this page explains the handful of concepts that matter and
  what each button in this extension actually does.</p>

  <h2>What you're looking at</h2>
  <p>This VS Code window is connected directly to that Linux server over SSH (that's what "Remote
  (SSH)" in the bottom-left corner means). When you open or edit a file here, you're editing the
  real file <em>on the server</em>, immediately -- there's no separate upload step, no syncing.
  Closing this window doesn't undo anything you've already saved.</p>
  <p>Everything lives under one folder on that server: <code>/opt/vertigis-studio</code>. That's
  the folder this window has open.</p>

  <h2>Projects and compose.yml</h2>
  <p>Inside <code>/opt/vertigis-studio</code>, each subfolder is a <strong>project</strong> --
  one self-contained thing that Docker runs. You'll typically have:</p>
  <ul>
    <li><strong>A caddy project</strong> (named <code>caddy</code> or <code>caddy-1</code>) -- the
    "front door." It's what actually receives web traffic from the internet/your network and
    forwards it to the right place, and it's what handles HTTPS.</li>
    <li><strong>One or more studio projects</strong> (<code>studio-1</code>, <code>studio-2</code>,
    ...) -- each one is a running copy of VertiGIS Studio itself.</li>
  </ul>
  <p>Every project has a <code>compose.yml</code> file -- that's the file that tells Docker what to
  run and how to configure it. You don't need to understand Docker Compose as a format to use this
  extension; just know that:</p>
  <ul>
    <li>A line like <code>environment:</code> introduces a list of settings, one per line below it,
    each shaped like <code>SETTING_NAME: value</code>. Changing the deployment's behavior almost
    always just means changing the text after one of these colons.</li>
    <li>A line starting with <code>#</code> is a comment -- a note for humans, Docker ignores it.
    Some of those comments are what make the buttons described below show up.</li>
  </ul>

  <h2>The side panel</h2>
  <p>Open it from the VertiGIS Studio icon in the Activity Bar (the strip of icons on the far
  left). It has:</p>
  <ul>
    <li><strong>Add Caddy</strong> / <strong>Add Studio</strong> -- create a new project folder
    with a ready-to-edit <code>compose.yml</code> already in it.</li>
    <li><strong>Compose Projects</strong> -- every existing project, as a clickable list that jumps
    straight to its <code>compose.yml</code>.</li>
    <li><strong>Guidance</strong> -- brings you back to this page any time.</li>
  </ul>

  <h2>The buttons that appear inside compose.yml</h2>
  <p>Open any project's <code>compose.yml</code> and you'll see small clickable links (VS Code
  calls these "CodeLens") floating just above certain lines. Each one runs a real action -- most of
  them open a terminal-like panel at the bottom (named <strong>vs-init</strong>) so you can watch
  what's happening; that panel is reused for whatever you click most recently, not one per action.</p>

  <div class="cue">
    <span class="where">Appears above: the <code>environment:</code> line, for a studio project</span>
    <h3>Get Account ID</h3>
    <p>Opens your web browser so you can sign in and confirm which VertiGIS Studio account this
    deployment belongs to. Fills in <code>VERTIGIS_ACCOUNT_ID</code> for you -- you never have to
    go look that value up yourself.</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: the <code>environment:</code> line, for a studio project</span>
    <h3>Register App / Update App</h3>
    <p>Your organization's ArcGIS/Portal sign-in needs to know about this specific deployment
    before users can log into it. Clicking this opens a browser window for you to sign in to your
    portal, then registers (or updates) an application entry there automatically and fills in
    <code>ARCGIS_APP_ID</code>. <strong>Register App</strong> always stays available even after
    you've already registered once -- clicking it again just creates a fresh registration, which is
    sometimes exactly what you want (e.g. starting over cleanly); <strong>Update App</strong> only
    appears once there's already an app id, and just refreshes its settings instead of creating a
    new one.</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: the <code>environment:</code> line, for a studio project</span>
    <h3>Request Cert / Retrieve Cert</h3>
    <p>If your organization has its own internal certificate authority (common for anything not
    meant to be public on the internet), this requests a real HTTPS certificate for this
    deployment's web address from it, using your Windows machine's own certificate tools -- you may
    see an administrator-approval prompt, since issuing a certificate needs that. Some certificate
    authorities issue immediately; others take a moment to approve the request first. If
    <strong>Request Cert</strong> reports the certificate isn't ready yet, run <strong>Retrieve
    Cert</strong> afterward (any time) to pick it up once it is -- re-running either one is always
    safe.</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: the <code>environment:</code> line, for a studio project</span>
    <h3>Register CNAME</h3>
    <p>Tries to automatically point your organization's internal DNS at this server, so people can
    actually reach this deployment by name. This is best-effort by design: it only works if your
    network's DNS is set up in a fairly standard way, and it will clearly tell you if it couldn't
    figure out where to make the change rather than guessing. If it doesn't work, that's expected
    for some networks -- ask whoever manages DNS at your organization to point the name at this
    server manually instead.</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: the top of the file, for a studio project (it's file-wide,
    like Build Caddyfile, not tied to one specific line)</span>
    <h3>Transfer Enterprise Trust Anchors</h3>
    <p>If your organization uses its own internal certificate authority (see Request Cert above),
    the Linux server also needs to be told to trust it -- otherwise it won't trust its own
    certificate, or anything else signed by your organization. This copies your Windows machine's
    own list of trusted certificates to the server. Safe to re-run any time (e.g. after your IT
    department rolls out a new certificate authority).</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: the top of the file, for any project with "# caddy" cues
    (including the caddy project's own compose.yml)</span>
    <h3>Build Caddyfile</h3>
    <p>Looks across <em>every</em> project for two specific comments -- <code># caddy route
    url</code> and <code># caddy route target</code> -- and wires them all together into the caddy
    project's own configuration, so the front door actually knows how to reach each studio
    deployment. Run this again any time you add a new studio project or change a web address. It
    also automatically picks up a real certificate for a deployment (see Request Cert above) if one
    exists -- nothing to configure separately for that.</p>
  </div>

  <div class="cue">
    <span class="where">Appears above: any <code>image:</code> line</span>
    <h3>Pick Version</h3>
    <p>Shows every real released version of that image (VertiGIS Studio, or Caddy) actually
    available right now, newest first, and lets you pin this project to a specific one instead of
    always using <code>latest</code>. Useful when you want this deployment to stop moving until you
    deliberately decide to upgrade it.</p>
  </div>

  <h2>The certs folder</h2>
  <p>The <code>certs</code> folder visible in the Explorer (alongside your project folders) is
  normally managed for you by the buttons above. If you already have certificate material from
  somewhere else -- an existing enterprise certificate, or a CA your organization manages outside
  this tool -- you can put it in place yourself instead of using Request Cert or Transfer Enterprise
  Trust Anchors:</p>
  <ul>
    <li><code>certs/root/</code> -- trusted root/intermediate CA certificates, one <code>.pem</code>
    file each. This whole folder becomes every container's trusted certificate list. Adding a
    <code>.pem</code> file here yourself isn't enough on its own -- run <strong>Transfer Enterprise
    Trust Anchors</strong> again afterward (it re-indexes the whole folder, including anything you
    added by hand) so it actually gets trusted.</li>
    <li><code>certs/live/&lt;host&gt;/</code> -- one folder per web address, containing
    <code>fullchain.pem</code> and <code>privkey.pem</code> for that host's real serving
    certificate (exact filenames matter). If you already have a certificate for a host, create this
    folder and these two files yourself -- <strong>Build Caddyfile</strong> picks it up
    automatically next time it runs, no need to involve Request Cert at all.</li>
    <li><code>certs/requests/&lt;host&gt;/</code> -- working files for Request Cert/Retrieve Cert's
    own process. Not meant to be populated by hand.</li>
  </ul>

  <h2>Setting up a new deployment, roughly in order</h2>
  <ol>
    <li>If there's no caddy project yet, click <strong>Add Caddy</strong>.</li>
    <li>Click <strong>Add Studio</strong> to create a new studio project.</li>
    <li>Open its <code>compose.yml</code> and fill in <code>ARCGIS_PORTAL_URL</code> and the
    <code># caddy route url</code>/<code>FRONTEND_URL</code> value (the web address people will
    actually use to reach it).</li>
    <li>Click <strong>Get Account ID</strong>, then <strong>Register App</strong>.</li>
    <li>If your organization uses an internal certificate authority: click <strong>Transfer
    Enterprise Trust Anchors</strong> once per server, then <strong>Request Cert</strong> for this
    deployment (and <strong>Retrieve Cert</strong> later if needed).</li>
    <li>Click <strong>Build Caddyfile</strong> to wire the front door up to this deployment.</li>
    <li>Optionally, click <strong>Register CNAME</strong> to try to point DNS here automatically.</li>
    <li>Start the containers: the Docker/Container Tools extensions already installed in this
    window can do this from their own panel, or run <code>docker compose up -d</code> in a terminal
    opened in the project's own folder.</li>
  </ol>

  <div class="footer">
    <label>
      <input type="checkbox" id="hide-welcome" ${hideWelcome ? "checked" : ""} />
      Don't open this automatically when a VertiGIS Studio folder is opened
    </label>
  </div>

  <script>
    const vscode = acquireVsCodeApi();
    document.getElementById("hide-welcome").addEventListener("change", (event) => {
      vscode.postMessage({ type: "setHideWelcome", value: event.target.checked });
    });
  </script>
</body>
</html>`;
}

function getMainViewHtml(webview, extensionUri, projects) {
  const bannerUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "banner.svg"));
  const projectItems = projects.length
    ? projects.map((name) => `<li><a href="#" class="project-link" data-name="${name}">${name}</a></li>`).join("")
    : `<li class="empty">No projects yet.</li>`;

  return `<!DOCTYPE html>
<html>
<head>
<style>
  body {
    margin: 0;
    padding: 0.75rem;
    background: var(--vscode-sideBar-background);
    color: var(--vscode-foreground);
    font-family: var(--vscode-font-family);
  }
  img.banner {
    width: 100%;
    height: auto;
    margin-bottom: 0.5rem;
  }
  p.explainer {
    margin: 0 0 1rem;
    opacity: 0.85;
    font-size: 0.9em;
  }
  h3 {
    font-size: 0.85em;
    text-transform: uppercase;
    opacity: 0.7;
    margin: 1rem 0 0.4rem;
  }
  button {
    display: block;
    width: 100%;
    box-sizing: border-box;
    background: var(--vscode-button-background);
    color: var(--vscode-button-foreground);
    border: none;
    padding: 0.5rem;
    margin-bottom: 0.4rem;
    cursor: pointer;
  }
  button:hover { background: var(--vscode-button-hoverBackground); }
  ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  li { margin-bottom: 0.3rem; }
  li.empty { opacity: 0.6; font-size: 0.9em; }
  a.project-link {
    color: var(--vscode-textLink-foreground);
    cursor: pointer;
    text-decoration: none;
  }
  a.project-link:hover { text-decoration: underline; }
</style>
</head>
<body>
  <img class="banner" src="${bannerUri}" alt="VertiGIS Studio" />
  <p class="explainer">Manage this Docker deployment's projects without leaving VS Code.</p>

  <h3>Actions</h3>
  <button id="add-caddy">Add Caddy</button>
  <button id="add-studio">Add Studio</button>
  <button id="guidance">Guidance</button>

  <h3>Compose Projects</h3>
  <ul id="projects">${projectItems}</ul>

  <script>
    const vscode = acquireVsCodeApi();
    document.getElementById("add-caddy").addEventListener("click", () => {
      vscode.postMessage({ type: "addProject", kind: "caddy" });
    });
    document.getElementById("add-studio").addEventListener("click", () => {
      vscode.postMessage({ type: "addProject", kind: "studio" });
    });
    document.getElementById("guidance").addEventListener("click", () => {
      vscode.postMessage({ type: "openGuidance" });
    });
    document.getElementById("projects").addEventListener("click", (event) => {
      const link = event.target.closest(".project-link");
      if (link) {
        event.preventDefault();
        vscode.postMessage({ type: "openProject", name: link.dataset.name });
      }
    });
  </script>
</body>
</html>`;
}

function deactivate() {}

module.exports = {
  activate,
  deactivate,
  computeLooksLikeOurs,
  findLensSpecs,
  environmentBlockValues,
  extractLineValue,
  replaceLineValue,
  updateComposeEnvValue,
  kebabSubject,
  pemFilename,
  rewriteTarget,
  normalizeRouteUrl,
  splitRouteUrl,
  hostFromOrigin,
  liveCertPaths,
  buildCaddyfileText,
  hostFromFrontendUrl,
  dumpValue,
  parseCertutilDump,
  looksLikeCertFile,
  findRequestId,
  zoneCandidates,
  relativeRecordName,
  psQuote,
  buildCnameUpsertScript,
  encodePowerShellCommand,
  applyPortHint,
  findCnameScriptError,
  looksLikeCaddyProjectFile,
  tokenizeTag,
  isFlavoredTag,
  tagVersionKey,
  compareTagVersions,
  cleanVersionTags,
  parseWwwAuthenticate,
  parseImageRef,
  registryApiHost,
  lineCommentText,
};
