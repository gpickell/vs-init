"""Create a per-profile launcher so a deployment can be reopened later
without rerunning vs-init.

Two pieces, for two different jobs:
  - A .cmd shim in %LocalAppData%\\Microsoft\\WindowsApps -- that folder
    is on every user's PATH by default (no admin, no PATH edit needed),
    so "vs-init-<profile>" becomes a typeable command from any shell.
  - A .lnk under the per-user Start Menu (VertiGIS Studio > Deployment)
    -- confirmed empirically that WindowsApps alone is invisible to
    Start's app list/search even after a cache refresh; only real .lnk
    files are picked up there, bare .cmd/.exe files dropped in a Start
    Menu folder are ignored entirely on modern Windows. The .lnk is what
    gives it a nice name and a real icon; its target is the .cmd above,
    so there's one source of truth for the actual launch command.
"""
from __future__ import annotations

import importlib.resources
import os
import re
import subprocess
from pathlib import Path

from .settings import SETTINGS_DIR

_WINDOWS_APPS = Path(os.environ.get("LocalAppData", str(Path.home() / "AppData" / "Local"))) / "Microsoft" / "WindowsApps"
_START_MENU_PROGRAMS = Path(os.environ.get("AppData", str(Path.home() / "AppData" / "Roaming"))) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
_SHORTCUT_GROUP = _START_MENU_PROGRAMS / "VertiGIS Studio" / "Deployment"

ICON_PATH = SETTINGS_DIR / "studio.ico"

_INVALID_FILENAME_CHARS = re.compile(r'[\\/:*?"<>|]')


def _safe_name(profile: str) -> str:
    return _INVALID_FILENAME_CHARS.sub("-", profile)


def _ensure_icon() -> Path:
    """Copy the icon out of the package into ~/.vs-init once -- the .lnk
    needs a stable absolute path to point at, and a uv-managed install
    location isn't guaranteed to stay put across runs."""
    if not ICON_PATH.exists():
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        data = importlib.resources.files(__package__).joinpath("assets", "studio.ico").read_bytes()
        ICON_PATH.write_bytes(data)
    return ICON_PATH


def _write_cmd(profile: str, code: str, folder: str) -> Path:
    path = _WINDOWS_APPS / f"vs-init-{_safe_name(profile)}.cmd"
    path.write_text(
        f'@echo off\ncall "{code}" --remote "ssh-remote+{profile}" "{folder}" --disable-workspace-trust\n',
        encoding="utf-8",
    )
    return path


def _write_lnk(profile: str, cmd_path: Path, icon_path: Path) -> Path:
    """Start's search matches against the item's own filename, not the
    folder path it lives in (confirmed empirically -- browsing finds it
    fine either way, but typing "VertiGIS" only matches if that text is
    in the filename itself), so the brand name is duplicated into the
    filename even though it's also the containing folder's name."""
    _SHORTCUT_GROUP.mkdir(parents=True, exist_ok=True)
    lnk_path = _SHORTCUT_GROUP / f"VertiGIS Studio Deployment - {_safe_name(profile)}.lnk"

    script = f"""
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut('{lnk_path}')
$shortcut.TargetPath = '{cmd_path}'
$shortcut.IconLocation = '{icon_path},0'
$shortcut.Description = 'Reopen the VertiGIS Studio deployment on {profile} in VS Code.'
$shortcut.Save()
"""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Creating Start Menu shortcut failed: {result.stderr.strip()}")
    return lnk_path


def ensure_shortcut(profile: str, code: str, folder: str) -> Path:
    """Create (or refresh) the vs-init-<profile> launcher for this one
    deployment. Returns the .lnk path."""
    icon_path = _ensure_icon()
    cmd_path = _write_cmd(profile, code, folder)
    return _write_lnk(profile, cmd_path, icon_path)
