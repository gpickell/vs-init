"""Ensure Visual Studio Code and the extensions we need are installed.

Extensions, split by where they actually need to run:
  - Remote Development (extension pack): SSH/container/WSL remoting.
    Declares "extensionKind": ["ui"] -- it's the thing that establishes
    a remote connection, so it has to run locally regardless. Installed
    once, locally.
  - Container Tools / Docker DX: manage containers and lint
    Dockerfiles/Compose files against a real Docker daemon. Neither
    declares an extensionKind, so VS Code defaults to running them as
    workspace extensions wherever the workspace is -- the remote host,
    once provisioned, since that's where Docker and the compose file
    actually live. Installing them only locally leaves them inactive in
    a Remote-SSH window; they need a separate install targeting that
    profile's remote extension host (see ensure_remote_extensions()).
"""
from __future__ import annotations

import importlib.resources
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Sequence

from . import vsix

PACKAGE_ID = "Microsoft.VisualStudioCode"

OWN_EXTENSION_ID = "vertigis-studio.vs-init-action"

LOCAL_EXTENSIONS: Sequence[str] = (
    "ms-vscode-remote.vscode-remote-extensionpack",
)

REMOTE_EXTENSIONS: Sequence[str] = (
    "ms-azuretools.vscode-containers",
    "docker.docker",
)

_USER_CODE_PATH = Path(os.environ.get("LocalAppData", r"C:\Users\Default\AppData\Local")) / "Programs" / "Microsoft VS Code" / "bin" / "code.cmd"
_MACHINE_CODE_PATH = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Microsoft VS Code" / "bin" / "code.cmd"

_REMOTE_PLATFORM_KEY = "remote.SSH.remotePlatform"
_USER_SETTINGS_PATH = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "Code" / "User" / "settings.json"


def find_code() -> Optional[str]:
    """Return a usable path to the ``code`` CLI, or None if it isn't
    installed. Checks PATH first, then VS Code's usual install
    locations -- useful right after installing it in this same process,
    before PATH is refreshed."""
    on_path = shutil.which("code") or shutil.which("code.cmd")
    if on_path:
        return on_path
    for candidate in (_USER_CODE_PATH, _MACHINE_CODE_PATH):
        if candidate.exists():
            return str(candidate)
    return None


def is_installed() -> bool:
    return find_code() is not None


def install() -> None:
    """Install VS Code via winget (``--scope user``: no elevation
    needed)."""
    result = subprocess.run(
        [
            "winget", "install", "--id", PACKAGE_ID, "-e", "--scope", "user",
            "--accept-package-agreements", "--accept-source-agreements",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"VS Code install failed (winget exit {result.returncode}): {result.stderr.strip()}")


def ensure_vscode() -> bool:
    """Ensure VS Code is installed. Returns True if it's available
    afterward."""
    if is_installed():
        return True
    print("Installing Visual Studio Code via winget...")
    install()
    return is_installed()


def _installed_extensions(argv_prefix: Sequence[str]) -> set[str]:
    result = subprocess.run([*argv_prefix, "--list-extensions"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Listing VS Code extensions failed: {result.stderr.strip()}")
    return {line.strip().lower() for line in result.stdout.splitlines() if line.strip()}


def _install_missing(argv_prefix: Sequence[str], extensions: Sequence[str]) -> None:
    have = _installed_extensions(argv_prefix)
    for ext_id in extensions:
        if ext_id.lower() in have:
            continue
        print(f"Installing VS Code extension {ext_id}...")
        result = subprocess.run(
            [*argv_prefix, "--install-extension", ext_id, "--force"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Installing extension {ext_id} failed: {result.stderr.strip()}")


def ensure_extensions() -> None:
    """Install any of LOCAL_EXTENSIONS that aren't already present."""
    code = find_code()
    if not code:
        raise RuntimeError("VS Code not found; install it first")
    _install_missing([code], LOCAL_EXTENSIONS)


def ensure_own_extension() -> None:
    """Build our own companion extension (src/vs_init/extension) from
    its bundled source and install it locally -- it's "extensionKind":
    ["ui"], so it runs on this machine regardless of whether the
    attached window is local or Remote-SSH, and needs installing just
    once, here, never on a remote extension host.

    Rebuilt and reinstalled fresh on every run (no Node/npm needed, see
    vsix.py) rather than version-checked, so it's never stale -- it's
    small and fast to package, and "is the installed copy current"
    isn't worth tracking separately.
    """
    code = find_code()
    if not code:
        raise RuntimeError("VS Code not found; install it first")

    with importlib.resources.as_file(importlib.resources.files(__package__) / "extension") as ext_dir:
        with tempfile.TemporaryDirectory() as tmp_dir:
            vsix_path = Path(tmp_dir) / "vs-init-action.vsix"
            vsix.build_vsix(ext_dir, vsix_path)
            result = subprocess.run(
                [code, "--install-extension", str(vsix_path), "--force"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError(f"Installing our own extension failed: {result.stderr.strip()}")


def ensure_remote_extensions(profile: str) -> None:
    """Install any of REMOTE_EXTENSIONS that aren't already present on
    ``profile``'s remote extension host."""
    code = find_code()
    if not code:
        raise RuntimeError("VS Code not found; install it first")
    _install_missing([code, "--remote", f"ssh-remote+{profile}"], REMOTE_EXTENSIONS)


def open_remote(profile: str, folder: str) -> None:
    """Launch VS Code via Remote-SSH, connected to ``profile`` with
    ``folder`` open. ``ssh-remote+<profile>`` is the authority scheme the
    Remote-SSH extension registers -- ``profile`` is looked up the same
    way plain ``ssh <profile>`` would be, via ~/.ssh/config.

    ``--disable-workspace-trust``: this window only, not a global
    setting -- reasonable here since ``folder`` is one provision.py just
    set up itself, not an unfamiliar repo someone handed us.

    Uses Popen, not run(): the ``code`` CLI either hands off to an
    already-running VS Code instance (returning almost immediately) or
    starts a new one, but either way this shouldn't block vs-init on the
    editor window being closed.
    """
    code = find_code()
    if not code:
        raise RuntimeError("VS Code not found; install it first")

    subprocess.Popen([code, "--remote", f"ssh-remote+{profile}", folder, "--disable-workspace-trust"])


def ensure_remote_platform(profile: str, platform: str = "linux") -> None:
    """Pre-seed Remote-SSH's cached OS guess for ``profile`` in VS Code's
    user settings.json, so connecting doesn't ask "What type of OS is
    your remote host?" on first use.

    Only touches the file if it parses as plain JSON. VS Code's
    settings.json is normally JSONC (comments/trailing commas allowed),
    but we don't carry a JSONC parser as a dependency, and silently
    corrupting a user's real settings file on a strict-JSON rewrite is
    worse than leaving this one setting for them to add by hand.
    """
    path = _USER_SETTINGS_PATH
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8") or "{}")
        except json.JSONDecodeError:
            print(
                f"{path} has comments or trailing commas (not plain JSON); "
                f"leaving it alone -- add {_REMOTE_PLATFORM_KEY!r}: "
                f"{{{profile!r}: {platform!r}}} yourself to skip the remote-OS prompt."
            )
            return
    else:
        data = {}

    table = data.get(_REMOTE_PLATFORM_KEY)
    if not isinstance(table, dict):
        table = {}
        data[_REMOTE_PLATFORM_KEY] = table
    if table.get(profile) == platform:
        return

    table[profile] = platform
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
