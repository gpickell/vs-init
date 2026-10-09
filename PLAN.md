# Bootstrap Tool

## Motivation and Overall Goal

We have Windows Enterprise customers. These customers are not Linux heads but we want to
migrate to a Docker centric deployment for VertiGIS Studio

Standard Problems:
- Certificate Enrollment (can be done but is hard from Linux)
- DNS Updates (can be done but is hard from Linux)
- Docker Materials (users need somewhere to start)

Inspiration/Experiments: c:\code\gpickell\vss-prime (pure console incarnation)

## Shape

This is primarily a Python project. The central system is uv and the
tools will be called vs-init(-*)

## Tool: vs-init (main tool)

GOAL: Provision the Windows system to do remote Linux admin work.

Project:
- Typical UV based project structure.
- Pin the python version.
- Libs: questionary and sshconf

Flow:
- Banner
  - Keep up to date as we add stuff
  - Tells the user what this is going to do concretely
  - Ask:
    - Proceed
    - Proceed, and skip this prompt next time
      - Flag saved in ~/.vs-init
    - Exit (default)
- Get gsudo (sniff first then install using winget) -- the very first thing after the banner
- If gsudo is available, show a blurb (same style as the banner) explaining what it is/for and
  what to expect (a Windows UAC-style prompt), then ask the user to pick its consent mode:
  - Convenience (fewer UAC prompts) -- sets gsudo's own CacheMode to Auto
  - Explicit (safest, default) -- sets gsudo's own CacheMode to Explicit (gsudo's shipped default)
  Only asked once -- remembered in ~/.vs-init (gsudo_cache_mode_asked) regardless of which mode was
  picked, so later runs don't ask again. winsudo.set_cache_mode() runs `gsudo config CacheMode
  <mode>` directly (gsudo itself, not wrapped by run()/capture()) -- CacheMode is a global-only
  setting, so gsudo handles the elevation this needs internally (its own UAC prompt).
- Get ssh (sniff first then install using gsudo/powershell)
- Get RSAT: DNS Server Tools (dnstools.py) -- optional, enables the Register CNAME action in the
  editor extension later. Sniffs first via `shutil.which("dnscmd")` (Get-WindowsCapability itself
  needs elevation just to query, so dnscmd.exe's presence on PATH is the free unelevated stand-in);
  if already present, skips asking entirely. Otherwise asks (y/n, default no) before installing
  (elevated) -- a decline is remembered (~/.vs-init) so it isn't asked again on a later run.
- Get vscode (sniff first then install using winget)
- Get vscode extensions
  - Remote Development
  - Container Tools
  - Docker DX (for compose file lens)
  - Inject our extension
- SSH Profile Management
  - Generate id_ed25519(.pub)
  - If profiles present:
    - Pick: (choice saved in ~/.vs-init)
      - Profile1
      - Profile2
      - Add New Profile
  - If adding new:
    - Ask:
      - Profile: name
      - Host: name
      - User: name
- SSH Credential Management
  - Detect if we can auto-logon (not interactive)
  - If not:
    - Ask: 
      - Transfer keys for auto login: Y/n
- Provisioning:
  - Run local provided provision.sh script on remote via SSH:
    - Install dependences: curl and setaclf
      - Detect apt or dnf
    - Install docker via curl + sh method
    - Add user to docker group
    - Apply "sharing permissions" to /opt/vertigis-studio
      - GID and g+w should be sticky
      - chown to docker
      - Write .vscode/settings.json
        - Use Abyss theme
      - Create certs/root and certs/live (group docker, group-writable) -- both are Docker bind-mount
        sources (caddy and studio compose.yml both mount certs/root as /etc/ssl/certs; caddy also
        mounts certs/live), so they must exist with the right group/permissions before `docker
        compose up` ever runs, or Docker auto-creates them as plain root-owned dirs instead
- Launch code but target remote system at the correct folder.
- Right after launching, create a per-profile launcher (shortcut.py, DONE) so this deployment can
  be reopened later without rerunning vs-init -- see "Note: Per-profile launcher shortcut" below.

## Extension: VertiGIS Studio

Condition:
- All functionality is gated through this check: remote=true + folder=/opt/vertigis-studio

UI:
- Main Side Panel
  - Lift icon from apps.vertigisstudio.com
    - SVGify it
  - Top is splash text + explainer
  - Section: Create Projects
  - Button: Add Caddy (caddy-1, ...)
    - best guess place holder for now
    - pin network name so we can talk to counterparts
  - Button: Add Studio (studio-1, studio-2, ...)
    - best guess place holder for now
  - Button: Guidance (DONE) -- opens the Guidance screen (below), or re-reveals it if already open
  - Section: Projects
    - click fast links (folder name -> open compose.yml fie)
- Guidance screen (DONE): a WebviewPanel (opens in the editor, not the sidebar -- there's enough
  content here to need real width, and it's read once up front then occasionally referred back to,
  not something that should compete with the side panel's own project list). Written for the
  audience the Motivation section itself names -- Windows Enterprise admins, not Linux people --
  spelling out in plain language what Remote-SSH/projects/compose.yml actually are, then walking
  through every CodeLens action (what it's for, what to expect when you click it, e.g. "may prompt
  for administrator approval," "may need Retrieve Cert run afterward"), a section on the certs
  folder's structure (certs/root/<hash>-<subject>.pem + ca-certificates.crt; certs/live/<host>/
  {fullchain,privkey}.pem; certs/requests/<host>/, internal-only) for anyone who needs to drop in
  certificate material they already have instead of using Request Cert/Transfer Enterprise Trust
  Anchors, then a roughly-ordered checklist for setting up a brand new deployment. Auto-opens once
  per window the first time the
  folder is recognized (vsInit.looksLikeOurs), unless the workspace's own vsInit.hideWelcome
  setting says not to -- a checkbox at the bottom of the screen itself sets that (at Workspace
  scope, via vscode.workspace.getConfiguration("vsInit").update(..., ConfigurationTarget.Workspace)
  -- so it's persisted into that workspace's own settings.json, not global VS Code settings). The
  Guidance button always reopens it regardless of that setting. provision.sh's own
  .vscode/settings.json write (previously just the Abyss theme) now includes
  "vsInit.hideWelcome": false by default, so the setting already exists (defaulted to "show it")
  from the moment a workspace is first provisioned, declared as a real contributed setting in
  package.json rather than just an ad hoc read/write.
- Side panel auto-reveal (DONE): the activity bar icon itself has no supported way to draw
  attention to itself before it's been opened at least once -- WebviewView.badge exists, but can
  only be set after the user has already opened the view, so it can't help a first-time user notice
  a brand new icon. Settled on forcing the view open directly instead:
  `vscode.commands.executeCommand("workbench.view.extension.vsInit")`, whenever the workspace looks
  like ours (vsInit.looksLikeOurs) AND no editors are open in any tab group
  (vscode.window.tabGroups.all) -- "no editors" is the best available proxy for "this window just
  started fresh in this workspace" (VS Code normally restores a workspace's previous tabs on
  reopen, so their absence suggests nothing carried over from a prior session). Deliberately NOT
  gated on vsInit.hideWelcome -- unlike Guidance, there's no other affordance that ever points the
  user at the side panel, so it doesn't share Guidance's opt-out.
- compose.yml Code Lens
  - Cue: any "# caddy" comment, anywhere in the file -- OR the file structurally looks like a
    caddy project's own compose.yml (a caddy image, plus an inline "content: |" config block --
    the shape the caddy template itself has), so the lens also shows up on that file directly even
    though it has no "# caddy route ..." comments of its own
    Action: Build Caddyfile
    - Lens is pinned to the top of the file (line 1), not next to whichever line matched -- the
      action scans every project's compose.yml anyway, not just the clicked one. One lens per
      file even when multiple caddy cues (or both triggers) match.
  - Cue: - /opt/vertigis-studio/certs/root:/etc/ssl/certs:ro
    Action: Transfer Enterprise Trust Anchors
    - Lens also pinned to the top of the file, same reasoning (the action doesn't care which
      line triggered it).
  - Cue: environment: block containing VERTIGIS_ACCOUNT_ID, FRONTEND_URL, and ARCGIS_PORTAL_URL
    (all three present is what "is this our environment block" means)
    Action: Get Account ID
    Action: Register App -- always shown once the block qualifies, even once ARCGIS_APP_ID is
      already set (re-registering mints a fresh, separate client; the option staying visible
      reads as "nothing is locked in")
    Action: Update App -- additionally shown once ARCGIS_APP_ID has a value
    - All three lenses stack on the environment: line. Which arc Register/Update App actually
      runs is driven by which lens was clicked, not by compose.yml's current state.
- Feedback: a single shared "vs-init" terminal (not one per action, not dynamically named).
  Starting a new action disposes and aborts whatever task was already running. The action's
  title is written as the first line of output, not used as the terminal's name. Closing the
  terminal aborts the running task. Built on a central TaskExecutor (extends AbortController)
  with executeOnSystem (local spawn), executeOnRemote (remote terminal dispatch), openServer
  (local HTTP server, closed on abort), and writeLine -- one cancellation signal threads through
  all three.

### Action: Get Account ID (DONE)

Flow:
- Perform dance with system browser to capture Account ID
- Update file inflight:
  - keep quotes if present
  - touches the last field of the line

### Action: Transfer Enterprise Trust Anchors (DONE)

Flow: Update certs/root
- Considers root certs from system
- Considers root certs from remote
- Merges into new list
- Generate singular .pem files
- Transfer to certs/root
- Run openssl rehash on remote

### Action: Build Caddyfile (DONE)

Flow:
- Considers all compose.yml files in workspace/folder (depth 1 compose.yml files)
- Looks for the last field of a containing:
  - # caddy route url
  - # caddy route target
- For the target, update the file inflight:
  - adjust value: something.foo.bar.etc -> something._folder_name_.int
  - keep quotes if present
  - touches the last field of the line
  - optional port hint in the comment itself: "# caddy route target:8080" -- the alias VALUE
    written back to the file never carries a port (it's a real Docker network alias used for
    container DNS, not just a Caddyfile field, so a port suffix there would be invalid/meaningless
    to Docker); the hinted port only ever applies to the route collected for the generated
    Caddyfile. studio's own template uses this (its container listens on 8080, not Caddy's default
    of 80) -- "# caddy route target:8080" on its alias line.
- For the url, update the file inflight:
  - remove trailing slash
  - make sure host part is lowercase
  - keep quotes if present
  - touches the last field of the line
- Written to caddy(-1)'s own Caddyfile, a real file sibling to that project's compose.yml (not
  inline config in compose.yml itself -- an earlier version used a Docker `configs:` block with an
  inline `content: |` block for this; replaced with a plain file bind-mounted into the container via
  `.:/etc/caddy:ro`, with `command: ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--watch"]`
  pointing at it. Wholly regenerated each run (applyTextEdit(caddyfileUri, () => caddyfileText)),
  same as the old inline block was -- no hand-editing of this file survives a rebuild).
  - looksLikeCaddyProjectFile()'s structural signal (for showing the lens on a caddy project's own
    compose.yml, which has no "# caddy route ..." comments of its own) changed to match: a caddy
    image plus that same `.:/etc/caddy:ro` self-mount line, instead of the old inline "content: |"
    block header.
  - addProject() copies a placeholder Caddyfile alongside compose.yml when creating a new caddy
    project -- without it, compose.yml's `--config /etc/caddy/Caddyfile` would have nothing to
    point at until Build Caddyfile happened to run once.
  - If no caddy project is present, we add one.
  - Mind the trailing slashes in rewrites
  - Multiple routes may occur on one host, so some intelligence is required.
- For each distinct host, checks whether certs/live/<host>/fullchain.pem exists on the remote
  host. If it does, that host's block gets an explicit `tls <fullchain> <privkey>` line pointing
  at certs/live/<host> (the same material Request Cert/Retrieve Cert's triage step produces). If
  it doesn't (Request Cert never run yet, or still pending), the block is left with no tls
  directive at all -- Caddy just falls back to its own automatic HTTPS (ACME) for that host, so
  this generator never needs to know anything about that config, and it naturally "catches up" the
  next time Build Caddyfile runs after a cert lands.
- caddy's own compose.yml template bind-mounts `/opt/vertigis-studio/certs/live` at the SAME path
  inside the container (`:ro`), not translated to some other internal path -- keeps the paths
  Caddy actually sees identical to the host filesystem, easy to grok.
- Focuses the user on the this compose.yaml

### Action: Register App (Update App) (DONE)

This action is dual purpose and has two arcs (register or update), driven by which lens was
clicked -- not inferred from compose.yml's state, since Register App stays available even after
ARCGIS_APP_ID is already set. The general goal is to get the app registered with the right URL.
ARCGIS_PORTAL_URL and FRONTEND_URL are read straight out of the environment: block; nothing is
prompted for.

Flow:
- Use Edge on system to collect a token. Launched via spawn() directly, not through the generic
  task executor -- a browser we keep alive and talk to live over CDP doesn't fit "run a command,
  stream its output to completion":
  - Start a local server that serves a static, blank ready page -- deliberately not a redirect to
    the portal. A redirect lets the browser navigate on its own before our CDP listener is set up,
    racing against the portal's one-shot portals/self call; serving a plain ready page and driving
    the real navigation ourselves (below) makes that race impossible instead of just unlikely.
  - Start Edge with:
    - Initially navigates to the local ready page
    - Separate, persistent user-data-dir (~/.vs-init/edge) -- no need to clean up; logins/cookies
      carry over between runs
    - CLI: --remote-debugging-port (enables CDP), --remote-allow-origins=* (Chromium 403s the
      DevTools WebSocket without it)
  - Once the ready page's tab shows up in /json/list, connect its DevTools WebSocket, enable
    Network, and only then send Page.navigate to the real portal ourselves -- guarantees we're
    already listening before the portal can load
  - Direct the user to log in to their portal
  - Observe the request to portals/self?...token=
  - Pick up the token
  - Shut down Edge gracefully (Browser.close over the browser-level WebSocket; falls back to a
    hard kill if that fails) -- we do not want crash prompts
- Use the token:
  - Register arc: resolve the signed-in username (community/self), create an Application item
    (content/users/<user>/addItem, title = the ARCGIS_APP_ID line's own trailing comment, e.g.
    "# VertiGIS Studio" -- that's what a user actually sees on the portal's OAuth consent screen,
    so it's a better title than an internal folder name; falls back to the project folder name only
    if that comment is missing or empty), then
    oauth2/registerApp with the front end URL as the sole redirect_uri
  - Update arc: oauth2/apps/<id>/update, refreshing the redirect_uri to the current FRONTEND_URL
  - Portal REST call shapes ported from vss-prime's agolregister.py; confirmed working against a
    real portal for both arcs
- Update ARCGIS_APP_ID (register arc only -- the update arc doesn't change it, so there's nothing
  to write back)

### Action: Request Cert (DONE)

Cue: same consolidated environment: block check as Get Account ID/Register App/Update App
(VERTIGIS_ACCOUNT_ID + FRONTEND_URL + ARCGIS_PORTAL_URL all present). Always shown once a block
qualifies, even with a live cert already in place -- resubmitting is never gated, same as
Register App; it just orphans whatever request preceded it.

Ported from vss-prime's certenroll.py, collapsed from its multi-session 4-loop wizard (add
CN/SAN, enroll, check pending, promote) into one pass: the host comes straight from FRONTEND_URL
instead of being collected interactively, and this is a single CodeLens click, not a standing CLI
session. There's no separate "check back later" step on this action itself -- if a CA doesn't
issue synchronously, Retrieve Cert (below) is the follow-up.

Flow:
- host = lowercased hostname of FRONTEND_URL (scheme/port/path don't matter for a cert subject)
- Add certs/requests/<host>/privkey.pem and certs/live/<host>/privkey.pem to files.exclude
- Generate the CSR and private key on the REMOTE host (private key never leaves it -- only the
  CSR, which is public, ever travels to Windows):
  - openssl req -new -newkey rsa:4096 -nodes -keyout <dir>/privkey.pem -out <dir>/cert.csr
    -subj /CN=<host> -addext subjectAltName=DNS:<host>
  - dir = /opt/vertigis-studio/certs/requests/<host>
- Enumerate CAs via `certutil -dump` (elevated -- same gsudo context the actual submission runs
  in), parsing Name:/Config: line pairs. Zero CAs is a hard error. Exactly one: used automatically,
  no prompt. More than one: vscode.window.showQuickPick by Name; the paired Config string is what
  actually goes to certreq -config.
- Copy the CSR to a local OS temp dir (certreq is Windows-only and needs a local file to read),
  then:
  certreq -submit -f -q -adminforcemachine -config <config>
    -attrib "CertificateTemplate:WebServerV3"
    <csr> <temp>/submitted/cert.pem <temp>/submitted/chain.p7b <temp>/submitted/response.resp
  (elevated via gsudo; `-f -q` forces past certreq's own interactive overwrite-confirmation
  dialog -- this runs fully non-interactively, nothing reads stdin to answer it). Combined
  stdout+stderr is captured and written to <temp>/submitted/out.txt (not something certreq itself
  writes) -- this is also where Retrieve Cert later reads the Request ID back out of.
- Do not rely on exit code too much: certreq uses nonzero exits for legitimate non-error
  dispositions too (e.g. a request taken under submission on a non-synchronous CA) -- a nonzero
  exit here is not treated as failure on its own.
- Copy everything in <temp>/submitted back to certs/requests/<host>/submitted on the remote host
  EXACTLY AS IS, regardless of outcome -- an audit trail of the raw attempt, written before any
  triaging.
- Triage (shared with Retrieve Cert, see below): read the local chain.p7b. "Smells good" = exists
  and contains "BEGIN CERTIFICATE" (a cheap substring sniff, same one vss-prime uses -- Windows
  labels PKCS7 bundles with the same generic PEM header a plain cert uses, confirmed against a
  real .p7b). If it doesn't smell good, report that the request may still be pending (and that the
  Request ID is sitting in submitted/out.txt for Retrieve Cert to use) and stop.
- If it does: upload a small triage script (templates/certTriage.sh) and run it remotely. It
  prefers the real chain.p7b (openssl pkcs7 -print_certs), falls back to treating cert.pem itself
  as a possible PKCS7 bundle, falls back further to a raw copy if that also fails -- then splits
  the resulting bundle into certs/live/<host>/cert.pem (leaf), chain.pem (intermediates only),
  fullchain.pem (leaf + intermediates), paired with the already-remote privkey.pem.
  - Real bug, caught by inspecting an actual live chain via SSH rather than trusting the script's
    own logic on paper: a Windows CA's chain.p7b response includes the root CA certificate itself,
    not just the leaf and intermediate(s) (confirmed against a real 3-cert chain). The original
    script treated "everything after the leaf" as chain.pem and "the whole bundle" as fullchain.pem
    -- so chain.pem was actually intermediates+root (missing the leaf entirely -- useless for a TLS
    server to present on its own) and fullchain.pem was leaf+intermediates+root (the root has no
    business being there; any real client already has it in its own trust store, and RFC 8446 says
    not to send it). Fixed by identifying the root via self-signedness (issuer == subject) and
    excluding it from both files. Caught a second bug fixing the first: `openssl x509 -noout
    -issuer`/`-subject` print "issuer=..."/"subject=..." -- comparing those raw strings never
    matches even for a genuinely self-signed cert because of the differing labels; the label has to
    be stripped first. Both the original bug and this one were confirmed live via SSH against a
    real chain before and after the fix, not just reasoned about from the script's source.
  - Caddy's own `tls fullchain.pem privkey.pem` reference (liveCertPaths(), buildCaddyfileText())
    didn't need to change -- fullchain.pem was always the right file to point Caddy at
    conceptually, it was just built wrong.
  - This fix only affects certs triaged after it landed; any host's live/ directory populated by a
    Request Cert/Retrieve Cert run before this fix still has the old (root-included) fullchain.pem
    and (leaf-missing) chain.pem on disk until that host's cert is re-triaged.

### Action: Retrieve Cert (DONE)

Cue: same consolidated environment: block check as the others above -- always shown,
unconditionally. Deliberately doesn't check the state of certs/requests or certs/live first; it
just tries certreq -retrieve, and certreq's own output says why if there's nothing to retrieve.

The deferred half of Request Cert, for a CA that doesn't issue synchronously. Deliberately dumb:
no local settings/state tracking of pending requests (unlike vss-prime's own settings.json-backed
Loop 3) -- the Request ID is re-read straight out of certs/requests/<host>/submitted/out.txt on
the remote host each time, which is already the durable audit trail Request Cert wrote. Which CA
config to use is re-picked the same way Request Cert does (nothing persists which one was used
before, either).

Flow:
- host, same as Request Cert
- Read certs/requests/<host>/submitted/out.txt from the remote host; if it's missing, report that
  Request Cert needs to run first and stop
- Pull the numeric Request ID out of it via regex (RequestId:\s*"?(\d+)"?, same pattern vss-prime
  uses); if there isn't one (e.g. the CA actually issued synchronously last time), report that and
  stop
- Pick a CA config (same picker as Request Cert, but NOT elevated -- see below)
- certreq -retrieve -f -q -config <config> <request id>
    <temp>/retrieved/cert.pem <temp>/retrieved/chain.p7b <temp>/retrieved/response.resp
  (NOT run elevated, unlike Request Cert's -submit: -adminforcemachine -- the thing that actually
  requires admin rights, by swapping the CA-facing identity to the computer account -- is a
  -submit-only flag, not accepted on -retrieve at all, and this doesn't use -accept to install
  into a local store either. Elevation only raises the current account's local privilege token; it
  doesn't change which identity gets presented to the CA, so there's no reason to force it here.
  certutil -dump for the CA picker is likewise called unelevated in this arc. Unverified against a
  real CA yet, same caveat as the rest of this feature.)
- Copy everything in <temp>/retrieved back to certs/requests/<host>/retrieved on the remote host
  EXACTLY AS IS, regardless of outcome -- kept separate from submitted/ so this never clobbers the
  original submission's own audit trail
- Triage exactly like Request Cert (shared code, shared certTriage.sh, just pointed at
  retrieved/ instead of submitted/) -- if chain.p7b still doesn't smell good, report that it may
  still be pending and to re-run later; resubmitting/re-retrieving is never gated.

### Action: Register CNAME (DONE)

Cue: same consolidated environment: block check as the others above -- always shown,
unconditionally. "Very optimistic" by design, per the original ask: no state is persisted or
checked beforehand, every run re-derives everything from scratch and upserts, so re-running it is
always safe.

Researched and deliberately rejected two other approaches before landing here:
- WMI (the classic root\MicrosoftDNS provider) -- genuinely on its way out: WMIC itself is removed
  from recent Windows 11 builds, the WMI v1 PowerShell cmdlets were dropped entirely starting at
  PowerShell 6, and DCOM hardening (KB5004442, fully enforced since March 2023 with no opt-out)
  means the classic DCOM moniker pattern often can't even connect without extra auth-level
  configuration most old tutorials don't show. The actively-maintained equivalent isn't WMI at
  all -- it's a separate CIM provider (root\Microsoft\Windows\Dns) that the modern DnsServer
  PowerShell module is built on.
- Raw dnsapi.dll calls via ctypes -- the actual record-management functions
  (DnssrvUpdateRecord2/DnssrvComplexOperation2) are MS-RPC methods (documented at the wire level in
  the MS-DNSP protocol spec) with a type-tagged-union record payload that varies by record type --
  real engineering risk to hand-rebuild the exact struct layout via ctypes, where getting it wrong
  means a native crash inside dnsapi.dll, not a catchable exception.
Landed on: the DnsServer PowerShell module (Add-DnsServerResourceRecordCName /
Get-DnsServerResourceRecord / Remove-DnsServerResourceRecord), invoked the same way
certreq/certutil already are -- a plain elevated PowerShell call via captureOnSystem. No Python
helper needed after all; the module itself is the whole interface.

Flow:
- host = FRONTEND_URL's hostname, same as Request Cert
- Zone derivation is keyed off FRONTEND_URL's own host, NOT the remote Linux host's domain --
  deliberately reworked away from an earlier version that derived the zone from the remote host's
  FQDN and gated on FRONTEND_URL's host being under it. That comparison was never actually
  load-bearing: nothing in DNS requires a CNAME's target to share a zone with its own name, so it
  just refused to run for perfectly valid setups where the two domains happen to differ. The Linux
  host's FQDN is still what the record points AT, just not what decides which zone to register it
  in anymore.
- zoneCandidates(host): every structurally possible zone split of the host, most-specific first
  (studio.dept.corp.example.com -> [dept.corp.example.com, corp.example.com, example.com]; the host
  itself and a bare TLD are both excluded). Deeply nested, actually-delegated DNS zones (a real
  separate zone cut at every naming level) are rare in practice -- most environments have one zone
  (often the AD domain itself, which can still be multi-label) and everything else is just a
  multi-label record name living inside it. So rather than asking the user to pick among
  zoneCandidates like an ambiguous guess, each candidate is probed with a real NS lookup
  (dns.promises.resolveNs) -- the first one that actually has NS records IS the zone, by
  definition. No picker: this is authoritative, not a guess. Stops with a clear message if none of
  the candidates have NS records, or if the host has too few labels to produce any candidates at
  all (e.g. a bare two-label host).
- The record name passed to -Name is relative to whichever zone was found (e.g. "studio" for
  studio.example.com in zone example.com)
- Picking which of that zone's name servers to actually talk to is likewise not a picker: each is
  "pinged" (pingNameServer) by querying it directly -- via a dedicated dns.Resolver pointed at its
  own IP (resolved first via dns.promises.lookup, since setServers() needs an IP, not a hostname)
  -- asking it to resolve the zone's own NS records again. A real answer confirms that server is
  both reachable and actually serving the zone; a bare port/ping check wouldn't prove the latter.
  The first name server that answers is used; stops with a clear message if none do, rather than
  falling back to an unverified guess.
- Read the remote host's own FQDN (hostname -f, written to a throwaway /tmp marker file and read
  back via vscode.workspace.fs.readFile over the remote authority) -- used only as the DEFAULT
  value for an input box (vscode.window.showInputBox) the user confirms or edits before anything is
  written. This is the one place a human checkpoint actually belongs: the zone and name server are
  both derived authoritatively above, but the target is the one genuinely uncertain value in the
  whole flow.
- Assumes the DnsServer module's cmdlets already exist -- does NOT check for or install RSAT: DNS
  Server Tools (Rsat.Dns.Tools~~~~0.0.1.0) itself at runtime (Get-WindowsCapability -Online needs
  elevation too, confirmed -- non-elevated callers get Access Denied, so there was no free
  unelevated check to skip an install dialog with anyway, and asking every time was just annoying
  for what's meant to be a quick CodeLens click). That decision moved to the bootstrap tool
  instead (dnstools.py) -- see its own section below. If the module genuinely isn't installed, the
  PowerShell call here just fails and the error message says so.
- Upsert, not blind create: Get-DnsServerResourceRecord first. Already correct -> no-op. Exists
  but points elsewhere -> Remove then Add. Doesn't exist -> Add. Three explicit branches, rather
  than trusting that re-running Add-DnsServerResourceRecordCName silently overwrites (plausible,
  but not something to bet correctness on without having run it against a real DC) -- all run
  elevated via gsudo in one PowerShell script, with each branch printing its own marker line so
  the result can be read back out of captureOnSystem's captured text output.
- The script is echoed to the terminal before running, for transparency -- but is actually sent to
  powershell.exe via -EncodedCommand (base64 of the UTF-16LE bytes), not -Command with the raw
  text. A real bug: the exact same multi-line, quote-heavy script text ran fine pasted directly
  into an interactive PowerShell session (regular or manually-elevated), but silently failed when
  spawned through the actual chain here (Node's own Windows argv-to-command-line quoting, then
  gsudo relaying that command line to its elevated broker) -- any one of those re-quoting passes
  could corrupt or truncate it. Base64 has no characters left that need escaping, so there's
  nothing left for any layer to get wrong.
- The script sets $ErrorActionPreference = 'Stop' and wraps its whole body in try/catch, reporting
  any caught exception via its own plain "VS_INIT_CNAME_ERROR: ..." Write-Output marker (the Get
  keeps its own -ErrorAction SilentlyContinue override -- "not found yet" there is expected, not a
  failure). This exists as a second, independent layer of defense against CLIXML on top of
  runPowerShellScript's own generic wrapping (below) -- it's what actually produces the
  VS_INIT_CNAME_* markers registerCname's own logic depends on, not just a CLIXML workaround on
  its own.
- Every PowerShell invocation through captureOnSystem goes through a shared runPowerShellScript()
  helper (extension.js) rather than each script reinventing CLIXML avoidance. Root cause was
  isolated empirically by reproducing it through the exact real spawn chain, varying one thing at
  a time: a direct spawn of powershell.exe and a gsudo-wrapped spawn both stayed perfectly clean
  using -File; switching only the invocation mode to -EncodedCommand (what the real code uses, for
  the quoting-corruption reasons above) reproduced the "#< CLIXML" blob immediately and reliably.
  So the trigger is specifically -EncodedCommand combined with piped, console-less stdio -- not
  gsudo, not elevation, not -NonInteractive alone. Two things fix it, confirmed by reproducing a
  real non-terminating error and a real warning through gsudo + -EncodedCommand and verifying zero
  CLIXML in the result:
  - `& { <script> } *>&1 | Out-String -Width 4096` -- *>&1 redirects every numbered stream
    (Success/Error/Warning/Verbose/Debug/Information) into the success stream, and Out-String
    forces it all through PowerShell's own formatting *inside the process* before anything crosses
    the OS pipe boundary, so there's nothing left for the non-interactive host to serialize.
    -Width is pinned high defensively against Out-String wrapping a long single-line message --
    confirmed NOT to happen by default in this exact invocation shape even at 2000 characters, but
    cheap enough to guard explicitly rather than rely on an undocumented default.
  - $ProgressPreference = 'SilentlyContinue' -- Progress isn't one of the numbered streams *>&1
    covers (it has no redirect number at all; it's a separate host callback), so without this, a
    one-time "Preparing modules for first use" message (first module auto-load in a session) still
    showed up as its own separate CLIXML blob even with the *>&1 | Out-String wrap in place --
    reproduced, then confirmed this line removes it.
  Validated end-to-end with the real buildCnameUpsertScript output (pointed at a nonexistent DNS
  server to force a genuine DnsServer-module/CIM failure) through the real gsudo +
  -EncodedCommand chain: clean "VS_INIT_CNAME_ERROR: ..." text, zero CLIXML.
- Every PowerShell invocation through captureOnSystem goes through a shared runPowerShellScript()
  helper now, not just this one script -- see "Note: PowerShell output" below.

### Action: Pick Version (DONE)

Cue: any "image:" mapping with a value, anchored right on that line (not top-pinned like Build
Caddyfile/Transfer Enterprise Trust Anchors -- this is genuinely per-image, and a file could have
more than one service each with its own image: line).

Lets the user pick a new tag for that image straight from the real registry's own tag list -- no
local guessing about what versions exist. Queried live against both ghcr.io/vertigis/studio/base
and docker.io/library/caddy during design; findings below are from those real responses, not
hypothetical ones.

Flow:
- Parse the image reference (parseImageRef) into {registry, repository, name, tag}. No registry
  prefix defaults to docker.io, and an unqualified name (e.g. "caddy") gets Docker Hub's implicit
  "library/" namespace ("library/caddy") -- but `name` (what's used for the actual write-back) is
  kept as the exact original substring before the tag, never reconstructed from registry+
  repository, so picking a new tag for "caddy:2" writes back "caddy:<new>", never
  "docker.io/library/caddy:<new>" just because that's technically what it resolves to.
- Fetch every tag via the plain OCI Distribution Spec anonymous-pull flow -- confirmed working
  with zero credentials against both registries: GET /v2/<repo>/tags/list unauthenticated -> 401
  with a WWW-Authenticate: Bearer realm="...",service="...",scope="..." header -> GET that realm
  (passing its own service+scope straight through, not reconstructed/guessed) -> anonymous bearer
  token -> retry the original GET with it -> {"tags": [...]}. registryApiHost() translates
  "docker.io" (the conventional registry identifier used in image references, and what's shown to
  the user) to the actual API host, registry-1.docker.io, before making any request -- a real bug
  caught live: hitting docker.io directly returns Docker Hub's web UI (an HTML page, "<!DOCTYPE
  ..."), not a JSON 401 challenge, which surfaced as "Unexpected token '<' ... is not valid JSON"
  the first time this ran against caddy. Every other registry (ghcr.io included) uses the same host
  for both purposes, so this is a one-off translation, not a general pattern.
- Sanitize the raw tag list before presenting it (cleanVersionTags): confirmed the two registries
  behave completely differently here. GHCR returns tags in genuine chronological/creation order
  (confirmed: not lexical, but monotonically increasing by real version) -- the newest real tag is
  just whatever's last. Docker Hub returns tags in plain lexical string order (confirmed) -- which
  is actively wrong for version recency once double digits show up (e.g. "2.10.0" sorts before
  "2.2.0" as strings; the real caddy tag list's lexical order puts 2.10.x/2.11.x, its actually-
  newest releases, before 2.2.0 through 2.9.1). So tags are never trusted to already be in a useful
  order from either registry -- always re-sorted ourselves:
  - tokenizeTag: split into alternating digit/non-digit runs (e.g. "v1.1.1184.377622" ->
    ["v","1",".","1",".","1184",".","377622"]).
  - tagVersionKey: the digit runs only, parsed as BigInt, compared component-by-component
    (compareTagVersions) as actual numbers -- not strings -- with a missing trailing component
    treated as 0 (so "2" sorts as equivalent to "2.0.0" relative to "2.11.7"). This is what fixes
    the "2.10.0" vs "2.2.0" lexical trap.
  - isFlavoredTag: excludes platform/variant noise (confirmed against Docker Hub's real 606-tag
    list for caddy: "2-alpine", "2-builder-windowsservercore-ltsc2022", "nanoserver-ltsc2022", "2-
    nanoserver", etc.) while keeping genuine version tags, including GHCR's own real shape
    ("v1.1.598.224400-r13470513045" -- a build-id suffix, not a flavor). Rule: tokenize, and every
    non-digit run must be "trivial" to not count as flavor text -- strip any leading punctuation
    from the run, and at most one letter can remain. A bare separator ("." or "-") strips to
    nothing (trivial); a leading version-prefix letter like "v" is already just one letter
    (trivial); a build-id marker like "-r" strips to "r" (trivial). Genuine flavor text ("-alpine",
    "-builder-windowsservercore-ltsc", leading "nanoserver-ltsc") is always more than one letter
    after stripping, so it's still caught -- regardless of whether it sits before, between, or
    after the tag's numeric runs, with no separate leading/internal/trailing cases needed. A first
    version of this rule only exempted a single leading character specifically (not "any single
    letter anywhere"), which wrongly flagged GHCR's own "-r<buildid>" shape as flavored -- caught
    by testing against the real 46-tag list (only 8 survived instead of 46), not just hand-picked
    examples.
  - "latest" is excluded from this sanitizing/sorting pipeline entirely (it has no digits to
    compare by anyway) and instead hard-pinned back in as the first choice unconditionally --
    always offered regardless of whether the registry's own list would otherwise produce it in a
    form that survives the filter.
- Show the result (latest first, then every real version newest-first) in a QuickPick; write the
  picked tag back by replacing just the value on that one image: line (same quote-preserving,
  comment-preserving replaceLineValue() every other inflight edit in this extension uses).

### Note: PowerShell output

Every PowerShell invocation through captureOnSystem goes through a shared runPowerShellScript()
helper (extension.js) now, rather than each script reinventing CLIXML avoidance -- see Register
CNAME's own section above for the full empirical story (root cause isolated to -EncodedCommand
specifically, the two-part fix, and the Progress-stream edge case). Any future PowerShell-based
action should run its script through this helper rather than building its own -EncodedCommand
invocation by hand.

### Note: Per-profile launcher shortcut

shortcut.py (DONE): right before (really, right after) launching VS Code for a freshly-provisioned
profile, cli.py calls shortcut.ensure_shortcut(profile, code, folder) to leave behind a way to get
back into that same deployment later without rerunning the whole vs-init flow. Two files, each
doing a job the other can't:

- A `vs-init-<profile>.cmd` shim written into `%LocalAppData%\Microsoft\WindowsApps` -- that folder
  is on every user's PATH by default (confirmed earlier: no admin, no PATH edit needed), so typing
  `vs-init-<profile>` in any shell runs `code --remote ssh-remote+<profile> <folder>
  --disable-workspace-trust` directly, no re-provisioning.
- A `.lnk` under the per-user Start Menu, at `VertiGIS Studio\Deployment\VertiGIS Studio Deployment
  - <profile>.lnk`, created via `New-Object -ComObject WScript.Shell` through a plain
  (non-`-EncodedCommand`) `powershell -Command` call -- no CLIXML concerns here, that was specific
  to `-EncodedCommand` (see "Note: PowerShell output"). Its TargetPath points at the `.cmd` above
  (one source of truth for the actual launch command) and its IconLocation points at an icon copied
  into `~/.vs-init/studio.ico` (copied once from a bundled asset, `assets/studio.ico` -- lifted from
  apps.vertigisstudio.com/favicon.ico and vendored rather than fetched live, so setup has no network
  dependency on that site staying put). The brand name is duplicated into the filename itself, not
  just the containing folder -- confirmed empirically that Start's search matches against an item's
  own filename, not the folder path it lives in, so a `.lnk` literally named `<profile>.lnk` inside
  `VertiGIS Studio\Deployment\` is only findable by typing the bare profile name, never "VertiGIS".

Why both files, empirically confirmed live in this same session before writing any of this code:
- A bare `.cmd`/`.exe` dropped straight into a Start Menu folder (even a fresh subfolder, even after
  force-restarting `StartMenuExperienceHost.exe` to rule out caching) is invisible to modern Windows
  11 Start -- not in search, not even when just browsing "All apps". Only real `.lnk` files are
  picked up. So WindowsApps alone gives typed-command convenience but zero Start discoverability;
  a `.lnk` alone gives discoverability but no custom icon without a `.lnk` (raw scripts only ever
  get the generic file-association icon) and isn't on PATH. Doing both covers both cases from one
  `ensure_shortcut()` call.
- Two levels of Start Menu nesting (`VertiGIS Studio\Deployment\`) works fine -- confirmed live,
  same as the one-level case tested earlier.
- `.lnk` files do carry their own icon (`IconLocation`, a `"path,index"` pair, independent of the
  target's own icon) and their own argument list (`Arguments`), which is what actually makes this
  work at all -- a bare script can't carry a custom icon, and `Set-Alias`-style aliasing (considered
  and rejected earlier) can't carry arguments.

Filenames are derived from the profile name with `_INVALID_FILENAME_CHARS` subbing out
`\/:*?"<>|` -- profile names are free-form text from `sshprofile.py`'s prompt, not guaranteed to be
filesystem-safe on their own.

### Note: gsudo

Neither the Python bootstrap tool (winsudo.py) nor the VS Code extension (taskExecutor.js) manage
gsudo's credentials cache themselves -- no app-level "cache on"/PID-scoped session, no bypassing
gsudo's own prompting. The one exception is a deliberate, one-time, user-facing choice: right after
gsudo is confirmed available, cli.py asks the user to pick gsudo's own CacheMode (Convenience/Auto
vs. Explicit/safest, defaulting to Explicit) and sets it via `gsudo config CacheMode <mode>` --
see the bootstrap Flow section above for the exact wording and settings key. Outside of that one
asked-once choice, every elevated call prompts according to whatever CacheMode is actually in
effect, with nothing in this codebase trying to avoid or shortcut that.

winsudo.py only ever makes one elevated call per run (installing the OpenSSH capability) via
`run()`/`capture()`, each a plain `gsudo <args...>` invocation.

In the extension, TaskExecutor.executeOnSystem and captureOnSystem take a `gsudo: true` option so
an action just declares it needs elevation; `spawnForExecutor` (taskExecutor.js) spawns
`gsudo <command> <args...>` directly, with no cache-management step in front of it.
