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

// The YAML literal block scalar header replaceInlineConfigContent()
// rewrites -- shared with looksLikeCaddyProjectFile() below, which uses
// the same marker to recognize a caddy project's own compose.yml.
const INLINE_CONFIG_CONTENT_HEADER = /^(\s*)content:\s*\|\s*$/;

/** Pure. Replaces the indented text under a YAML literal block
 * scalar's header line (e.g. "    content: |") with `newContent`,
 * re-indented to match. Targeted content replacement, not a full
 * regeneration of the file -- any other hand-editing of the caddy
 * project's compose.yml survives a rebuild. Returns null if no such
 * block header is found. */
function replaceInlineConfigContent(text, newContent) {
  const lines = text.split("\n");
  const headerIndex = lines.findIndex((line) => INLINE_CONFIG_CONTENT_HEADER.test(line));
  if (headerIndex === -1) {
    return null;
  }

  const baseIndent = lines[headerIndex].match(/^(\s*)/)[1];
  const contentIndent = `${baseIndent}  `;

  let end = headerIndex + 1;
  while (end < lines.length && (lines[end].startsWith(contentIndent) || lines[end].trim() === "")) {
    end++;
  }
  while (end > headerIndex + 1 && lines[end - 1].trim() === "") {
    end--;
  }

  const newLines = newContent
    .replace(/\n$/, "")
    .split("\n")
    .map((line) => (line ? contentIndent + line : line));

  return [...lines.slice(0, headerIndex + 1), ...newLines, ...lines.slice(end)].join("\n");
}

/** Pure. Does this compose.yml look like a caddy project's own file --
 * the thing Build Caddyfile writes its generated Caddyfile INTO, not
 * one of the project files it reads caddy route cues FROM? Two
 * structural signals, both required: a caddy image on some service,
 * and an inline "content: |" config block (the exact marker
 * replaceInlineConfigContent() rewrites). Needed because a caddy
 * project's own compose.yml has no "# caddy route ..." comments of its
 * own -- without this, opening it directly would never trigger the
 * lens at all. */
function looksLikeCaddyProjectFile(lines) {
  const hasCaddyImage = lines.some((line) => /^\s*image:\s*["']?caddy:/i.test(line));
  const hasInlineContentBlock = lines.some((line) => INLINE_CONFIG_CONTENT_HEADER.test(line));
  return hasCaddyImage && hasInlineContentBlock;
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
 * writes the generated Caddyfile into the caddy project's inline
 * compose config. Triggered from either cue's CodeLens -- both do the
 * same whole-workspace scan, not just the clicked line/file. */
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
    const caddyComposeUri = vscode.Uri.joinPath(studioFolderUri, caddyName, "compose.yml");
    executor.writeLine(`Writing Caddyfile config into ${caddyName}/compose.yml...`);

    const caddyfileText = buildCaddyfileText(routes, (host) => liveCertHosts.has(host));
    let noConfigBlock = false;
    await applyTextEdit(caddyComposeUri, (text) => {
      const updated = replaceInlineConfigContent(text, caddyfileText);
      noConfigBlock = updated === null;
      return updated;
    });
    if (noConfigBlock) {
      executor.writeLine(`${caddyName}/compose.yml has no inline "content: |" config block to update.`);
      return 1;
    }

    const doc = await vscode.workspace.openTextDocument(caddyComposeUri);
    await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
    await vscode.commands.executeCommand("revealInExplorer", caddyComposeUri);

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
 * plus an inline "content: |" config block, the shape the caddy
 * template itself has.
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
 * additionally only once ARCGIS_APP_ID has a value. */
function findLensSpecs(lines) {
  const specs = [];
  let hasCaddyCue = false;
  let hasTrustAnchorsCue = false;

  lines.forEach((text, line) => {
    if (/#\s*caddy/.test(text)) {
      hasCaddyCue = true;
    } else if (/^\s*-\s*\/opt\/vertigis-studio\/certs\/root:\/etc\/ssl\/certs:ro\s*$/.test(text)) {
      hasTrustAnchorsCue = true;
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
      const title = folderUri.path.split("/").filter(Boolean).pop() || "VertiGIS Studio";
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
    const { code, output } = await executor.captureOnSystem({
      gsudo: true,
      command: "powershell.exe",
      args: ["-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShellCommand(script)],
    });

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
  };
  // Build Caddyfile scans every project's compose.yml, not just the
  // clicked one, so it doesn't need (and isn't passed) a folderUri.
  // registerApp/updateApp also pass their own kind through, since
  // registerOrUpdateApp picks its arc from whichever lens was actually
  // clicked, not from compose.yml's current state.
  return findLensSpecs(lines).map(({ line, title, kind }) => {
    const range = new vscode.Range(line, 0, line, 0);
    const args =
      kind === "caddyfile" ? [] : kind === "registerApp" || kind === "updateApp" ? [folderUri, kind] : [folderUri];
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

  // Gated the same way the side panel is -- without this, the lens
  // fires on any compose.yml anywhere, not just ours.
  const codeLensProvider = vscode.languages.registerCodeLensProvider(
    { pattern: "**/compose.yml" },
    {
      onDidChangeCodeLenses: codeLensChangeEmitter.event,
      provideCodeLenses: (document) => (looksLikeOurs() ? buildCodeLenses(document) : []),
    }
  );

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
    codeLensProvider,
    codeLensChangeEmitter,
    mainView
  );
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

  <h3>Create Projects</h3>
  <button id="add-caddy">Add Caddy</button>
  <button id="add-studio">Add Studio</button>

  <h3>Projects</h3>
  <ul id="projects">${projectItems}</ul>

  <script>
    const vscode = acquireVsCodeApi();
    document.getElementById("add-caddy").addEventListener("click", () => {
      vscode.postMessage({ type: "addProject", kind: "caddy" });
    });
    document.getElementById("add-studio").addEventListener("click", () => {
      vscode.postMessage({ type: "addProject", kind: "studio" });
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
  replaceInlineConfigContent,
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
};
