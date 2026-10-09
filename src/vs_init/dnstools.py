"""Ensure Windows' RSAT: DNS Server Tools capability is available,
installing it via the elevation facility (winsudo) if the user opts in.

This is what the VS Code extension's "Register CNAME" action needs
(Add-DnsServerResourceRecordCName / Get-DnsServerResourceRecord /
Remove-DnsServerResourceRecord all come from the DnsServer PowerShell
module this capability provides) -- that action deliberately doesn't
check for or install it itself at runtime (Get-WindowsCapability needs
elevation too, confirmed, so there's no free unelevated check it could
use to skip asking; better to settle this once, here, during setup, and
have the editor action just assume the cmdlets exist -- if they don't,
it fails plainly and says so).

Entirely optional: skipping this still leaves every other action
working, so the bootstrap flow asks before installing it rather than
doing so unconditionally, the same way it asks before transferring SSH
keys for auto-logon."""
from __future__ import annotations

import shutil

from . import winsudo

_CAPABILITY_NAME = "Rsat.Dns.Tools~~~~0.0.1.0"


def is_installed() -> bool:
    """Unelevated sniff: dnscmd.exe ships as part of this capability, so
    its presence on PATH is a free stand-in for Get-WindowsCapability
    (which needs elevation just to query, unlike a plain PATH lookup)."""
    return shutil.which("dnscmd") is not None


def install() -> None:
    """Install the RSAT: DNS Server Tools Windows capability (requires
    elevation). Doesn't check whether it's already installed first --
    Get-WindowsCapability needs elevation too (confirmed; non-elevated
    callers get Access Denied), so there's no free unelevated check to
    skip this with, and Add-WindowsCapability doesn't error against an
    already-installed capability anyway, so this is fast on a repeat
    run."""
    exit_code = winsudo.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"Add-WindowsCapability -Online -Name {_CAPABILITY_NAME}",
        ]
    )
    if exit_code != 0:
        raise RuntimeError(f"RSAT: DNS Server Tools install failed with exit code {exit_code}")
