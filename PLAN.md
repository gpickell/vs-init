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
- Get gsudo (sniff first then install using winget)
- Get ssh (sniff first then install using gsudo/powershell)
- Ask (y/n, default no): install RSAT: DNS Server Tools? (dnstools.py) -- optional, enables the
  Register CNAME action in the editor extension later. No sniffing first (Get-WindowsCapability
  needs elevation too; Add-WindowsCapability doesn't error against an already-installed capability
  anyway, so there's nothing to gain by checking first) -- just installs (elevated) if confirmed.
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
- Launch code but target remote system at the correct folder.

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
  - Section: Projects
    - click fast links (folder name -> open compose.yml fie)
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
- Kept as inline config in caddy(-1) compose file:
  - If none present, we add a project.
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
    (content/users/<user>/addItem, title = project folder name as a placeholder), then
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
  the resulting bundle into certs/live/<host>/cert.pem (leaf), chain.pem (the rest), fullchain.pem
  (everything), paired with the already-remote privkey.pem.

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
  failure). This isn't just tidiness: PowerShell's non-interactive host (which this always is,
  spawned and piped) serializes anything that lands on the Error/Warning/Verbose/Debug streams as
  CLIXML instead of plain text -- confirmed as the source of "weird" garbled captured output.
  Write-Output (the success/pipeline stream) never gets that treatment, and there is no flag to
  turn CLIXML off for the other streams -- routing every failure through Write-Output instead is
  what actually avoids it.

### Note: gsudo

Python (bootstrap tool, winsudo.py) (DONE): does not manage gsudo's cache at all -- no
"cache on"/"cache off", no PID-scoped cache session. It only ever makes one elevated call per
run (installing the OpenSSH capability), so there's nothing to amortize a cache across; each
call just takes whatever single UAC prompt gsudo's own default (Explicit) cache mode asks for.

VS Code extension (DONE, extension/gsudo.js): a separate, first-class implementation, not a reuse
of winsudo.py -- the extension is a long-running session where more than one elevated action is
plausible (e.g. multiple Request Cert runs), so it's worth managing its own cache: scoped to the
extension host's own process.pid (no ancestor-walking needed -- unlike winsudo.py's short-lived
CLI invocation, this process IS the long-lived thing to scope to), cache enabled for 1 hour.
TaskExecutor.executeOnSystem and the new captureOnSystem (which also buffers and returns combined
stdout+stderr for commands like certutil/certreq whose output needs parsing) both take a
`gsudo: true` option so an action just declares it needs elevation, without reimplementing the
cache dance itself.
