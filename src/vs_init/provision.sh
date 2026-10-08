#!/bin/sh
set -e

FORCE=0
case "$1" in
    --force) FORCE=1 ;;
esac

STUDIO_PATH="/opt/vertigis-studio"
UPDATED=0
DID_SOMETHING=0

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then
        if [ "$UPDATED" = 0 ]; then
            sudo apt-get update
            UPDATED=1
        fi
        sudo apt-get install -y "$@"
    elif command -v dnf >/dev/null 2>&1; then
        sudo dnf install -y "$@"
    else
        echo "No supported package manager (apt-get or dnf) found" >&2
        exit 1
    fi
}

# --- prerequisites ---
if [ "$FORCE" = 1 ] || ! command -v curl >/dev/null 2>&1; then
    echo "Installing curl..."
    pkg_install curl
    DID_SOMETHING=1
fi
if [ "$FORCE" = 1 ] || ! command -v setfacl >/dev/null 2>&1; then
    echo "Installing acl (for setfacl)..."
    pkg_install acl
    DID_SOMETHING=1
fi
if [ "$FORCE" = 1 ] || ! command -v openssl >/dev/null 2>&1; then
    echo "Installing openssl (for the VS Code extension's trust anchor rehash)..."
    pkg_install openssl
    DID_SOMETHING=1
fi

# --- docker ---
if [ "$FORCE" = 1 ] || ! command -v docker >/dev/null 2>&1; then
    echo "Installing Docker (official convenience script)..."
    curl -fsSL https://get.docker.com | sh
    DID_SOMETHING=1
fi

# Checked independently of the install above -- Docker may have already
# been present (pre-existing host, installed outside this script) with
# this user never added to its group.
if [ "$FORCE" = 1 ] || ! id -nG "$(id -un)" | tr ' ' '\n' | grep -qx docker; then
    echo "Adding $(id -un) to the docker group..."
    sudo usermod -aG docker "$(id -un)"
    DID_SOMETHING=1
fi

# --- /opt/vertigis-studio ---
studio_ready() {
    [ -d "$STUDIO_PATH" ] &&
        [ "$(stat -c '%G' "$STUDIO_PATH" 2>/dev/null)" = docker ] &&
        [ "$(stat -c '%A' "$STUDIO_PATH" 2>/dev/null | cut -c5-7)" = rws ] &&
        getfacl --omit-header "$STUDIO_PATH" 2>/dev/null | grep -qx 'default:group::rwx' &&
        [ -f "$STUDIO_PATH/.vscode/settings.json" ]
}

if [ "$FORCE" = 1 ] || ! studio_ready; then
    echo "Setting up $STUDIO_PATH (group docker, setgid, default group ACL)..."
    sudo mkdir -p "$STUDIO_PATH/.vscode"
    sudo chown ":docker" "$STUDIO_PATH"
    sudo chmod g+ws "$STUDIO_PATH"
    # setgid (g+ws) only makes new entries inherit the docker group; it
    # doesn't make them group-writable -- that still depends on whatever
    # umask the creating process happens to use. A default ACL fixes the
    # permission bits themselves, so every new file/dir under here is
    # group-writable regardless of umask.
    sudo setfacl -m d:g::rwx "$STUDIO_PATH"

    echo "Writing $STUDIO_PATH/.vscode/settings.json (Abyss theme)..."
    printf '%s\n' \
        '{' \
        '    "workbench.colorTheme": "Abyss"' \
        '}' | sudo tee "$STUDIO_PATH/.vscode/settings.json" >/dev/null
    sudo chown -R ":docker" "$STUDIO_PATH/.vscode"
    sudo chmod g+w "$STUDIO_PATH/.vscode" "$STUDIO_PATH/.vscode/settings.json"
    DID_SOMETHING=1
fi

if [ "$DID_SOMETHING" = 0 ]; then
    echo "Already fully provisioned; nothing to do."
fi
