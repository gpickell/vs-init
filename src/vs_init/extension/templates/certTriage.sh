#!/bin/sh
# Ported from vss-prime's triage.sh, adjusted for this project's path
# layout (certs/requests/<host>/<subdir>/* instead of
# certs/enroll/<cn>/issued.*). Run on the remote host by requestCert()
# and retrieveCert() in extension.js, after either has already copied
# certreq's raw output back to certs/requests/<host>/<subdir>/ verbatim,
# regardless of whether that output actually "smelled good". $2
# (subdir) is "submitted" for a fresh certreq -submit or "retrieved" for
# a later certreq -retrieve -- kept separate so neither arc's raw output
# clobbers the other's.
set -e

HOST="$1"
SUBDIR="$2"
REQUEST_DIR="/opt/vertigis-studio/certs/requests/$HOST"
LIVE_DIR="/opt/vertigis-studio/certs/live/$HOST"
CHAIN="$REQUEST_DIR/$SUBDIR/chain.p7b"
CERT="$REQUEST_DIR/$SUBDIR/cert.pem"
BUNDLE="$REQUEST_DIR/.bundle.pem"

mkdir -p "$LIVE_DIR"

# Prefer the real chain (chain.p7b); fall back to treating the single
# cert.pem as a possible PKCS7 bundle itself; fall back further to just
# copying it raw if that also fails -- in that worst case no actual
# chain validation happens at all, just a straight copy.
if [ -s "$CHAIN" ] && openssl pkcs7 -in "$CHAIN" -print_certs -out "$BUNDLE" 2>/dev/null; then
    :
elif ! openssl pkcs7 -in "$CERT" -print_certs -out "$BUNDLE" 2>/dev/null; then
    cp "$CERT" "$BUNDLE"
fi

# openssl pkcs7 -print_certs prepends human-readable subject=/issuer=
# lines ahead of each cert -- strip everything but the PEM blocks
# themselves before splitting.
awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$BUNDLE" > "$BUNDLE.clean"
mv "$BUNDLE.clean" "$BUNDLE"

rm -f "$REQUEST_DIR"/.cert-*.pem
awk -v dir="$REQUEST_DIR" '
    /-----BEGIN CERTIFICATE-----/ { n++ }
    { print > (dir "/.cert-" n ".pem") }
' "$BUNDLE"

# First cert in the bundle is the leaf; everything after it is the
# intermediate/root chain.
cp "$REQUEST_DIR/.cert-1.pem" "$LIVE_DIR/cert.pem"

: > "$LIVE_DIR/chain.pem"
for f in "$REQUEST_DIR"/.cert-*.pem; do
    [ "$f" = "$REQUEST_DIR/.cert-1.pem" ] && continue
    cat "$f" >> "$LIVE_DIR/chain.pem"
done

cp "$BUNDLE" "$LIVE_DIR/fullchain.pem"
cp "$REQUEST_DIR/privkey.pem" "$LIVE_DIR/privkey.pem"

rm -f "$REQUEST_DIR"/.cert-*.pem "$BUNDLE"
