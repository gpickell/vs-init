"""Windows elevation ("sudo") facility.

Delegates actual elevation to gsudo (https://github.com/gerardog/gsudo),
installed via winget if missing. gsudo already solves the hard problems
involved in doing this well: it keeps a hidden, elevated broker alive
after the first UAC prompt and shares the console with every command it
runs for you (via handle duplication into the broker), instead of either
re-prompting per command (ShellExecuteExW + "runas") or needing
privileges an ordinary process doesn't hold (CreateProcessAsUser /
CreateProcessWithLogonW).

Deliberately does not manage gsudo's elevation cache (no "cache on"/
"cache off", no PID-scoped cache session): this tool only ever makes a
small, fixed number of elevated calls in a given run (installing the
OpenSSH capability; optionally installing RSAT: DNS Server Tools, see
dnstools.py), each independent of the others, so there's nothing
meaningful to amortize a cache across -- and proactively widening the
elevated window (even for an hour) buys nothing here. Each call just
takes whatever single UAC prompt gsudo's own default (Explicit) cache
mode asks for. The VS Code extension, a long-running session where
multiple elevated actions are plausible, manages its own cache instead
-- see extension/gsudo.js.

Trade-off: elevation now depends on a third-party binary with elevated-
execution capability, rather than ~150 lines of ctypes we fully control.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional, Sequence, Tuple

GSUDO_PACKAGE_ID = "gerardog.gsudo"


class ElevationError(RuntimeError):
    """Raised when gsudo can't be found/installed, or an elevated command
    fails."""


def find_gsudo() -> Optional[str]:
    return shutil.which("gsudo")


def _refresh_path_from_registry() -> None:
    """winget updates the persisted user/machine PATH in the registry;
    this already-running process won't see that until something re-reads
    it. Pull the current values and merge in anything new so a package
    installed moments ago is found without restarting the process."""
    import winreg

    entries = os.environ.get("PATH", "").split(os.pathsep)
    seen = {e.lower() for e in entries if e}

    for hive, subkey in (
        (winreg.HKEY_CURRENT_USER, r"Environment"),
        (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"),
    ):
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _ = winreg.QueryValueEx(key, "Path")
        except OSError:
            continue
        for entry in value.split(os.pathsep):
            if entry and entry.lower() not in seen:
                entries.append(entry)
                seen.add(entry.lower())

    os.environ["PATH"] = os.pathsep.join(entries)


def install_gsudo() -> None:
    """Install gsudo via winget. ``--scope user`` matters: without it,
    winget picks gsudo's admin-elevated MSI installer; with it, winget
    uses the portable zip distribution instead, installed per-user with
    no elevation needed."""
    result = subprocess.run(
        [
            "winget", "install", "--id", GSUDO_PACKAGE_ID, "-e", "--scope", "user",
            "--accept-package-agreements", "--accept-source-agreements",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise ElevationError(
            f"gsudo install failed (winget exit {result.returncode}): {result.stderr.strip()}"
        )


def ensure_gsudo() -> str:
    """Return a path to gsudo, installing it via winget if missing."""
    gsudo = find_gsudo()
    if gsudo:
        return gsudo

    # Not on PATH yet doesn't mean not installed -- a prior install (this
    # process, a previous run, or the user doing it themselves) lands in
    # the registry immediately but this process's PATH is stale until
    # something re-reads it. Check that before deciding to (re)install.
    _refresh_path_from_registry()
    gsudo = find_gsudo()
    if gsudo:
        return gsudo

    print("Installing gsudo via winget...")
    install_gsudo()
    _refresh_path_from_registry()
    gsudo = find_gsudo()
    if not gsudo:
        raise ElevationError("gsudo still not found on PATH after install")
    return gsudo


def run(args: Sequence[str]) -> int:
    """Run ``args`` elevated via gsudo, sharing this console. May prompt
    for admin confirmation (gsudo's own default Explicit cache mode --
    see the module docstring for why this doesn't try to avoid that)."""
    gsudo = ensure_gsudo()
    result = subprocess.run([gsudo, *args])
    return result.returncode


def capture(args: Sequence[str]) -> Tuple[int, str]:
    """Run ``args`` elevated via gsudo, returning (exit code, combined
    stdout+stderr) instead of sharing this console -- for commands whose
    output needs parsing, not just their exit code."""
    gsudo = ensure_gsudo()
    result = subprocess.run(
        [gsudo, *args], capture_output=True, text=True
    )
    return result.returncode, result.stdout + result.stderr


def set_cache_mode(mode: str) -> None:
    """Set gsudo's own persistent CacheMode config ("Auto" or
    "Explicit"). This is gsudo itself being invoked (its `config`
    subcommand) rather than a command run()/capture() wraps -- CacheMode
    is a global-only setting, so gsudo handles the elevation this needs
    internally (its own UAC prompt), the same way it did live when this
    was tested by hand."""
    gsudo = ensure_gsudo()
    result = subprocess.run([gsudo, "config", "CacheMode", mode], capture_output=True, text=True)
    if result.returncode != 0:
        raise ElevationError(f"Setting gsudo's CacheMode failed: {result.stderr.strip()}")
