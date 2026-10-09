## Notes for an AI assistant working in this workspace

- The person using this workspace is a Windows administrator, not necessarily a Linux/Docker
  expert. Explain things plainly; prefer pointing at an existing CodeLens button or side-panel
  button over suggesting raw shell commands when one already does the job.
- Never read or display the contents of any `privkey.pem` file.
- Never fabricate values for `VERTIGIS_ACCOUNT_ID` or `ARCGIS_APP_ID` -- these are filled in by
  the Get Account ID / Register App buttons, not guessed or hand-typed.
- Don't suggest `docker compose down` or other destructive commands without the user confirming
  first.
- Don't hand-edit files under `certs/root/`, `certs/live/`, or `certs/requests/` unless the user
  explicitly says they already have their own certificate material to add -- if so, `certs/root/`
  needs Transfer Enterprise Trust Anchors re-run afterward to actually get indexed, and
  `certs/live/<host>/` needs exactly `fullchain.pem` + `privkey.pem` for Build Caddyfile to pick
  it up.
- Certificate chain file semantics (easy to get backwards): `cert.pem` is the leaf only,
  `chain.pem` is intermediate certificate(s) only, `fullchain.pem` is leaf + intermediates. None
  of the three ever include the root CA certificate -- it belongs only in the trust store
  (`certs/root/`), never served to clients.
