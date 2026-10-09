"""Create or choose a named SSH profile (a Host entry in ~/.ssh/config)
for a remote host.
"""
from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List, Optional

import questionary
from sshconf import read_ssh_config

from .settings import get_setting, set_setting
from .sshinstall import find_ssh
from .sshkey import PRIVATE_KEY_PATH, PUBLIC_KEY_PATH

SSH_CONFIG_PATH = Path.home() / ".ssh" / "config"
_LAST_PROFILE_KEY = "ssh_last_profile"

NEW_PROFILE = "New profile..."

# Prefixed so it can't collide with a real hostname elsewhere in
# known_hosts -- each profile gets its own host-key entry keyed by this
# instead of sharing one keyed by HostName, so two profiles pointing at
# the same box (different users) don't fight over a single known_hosts
# line.
HOST_KEY_ALIAS_PREFIX = "ssh-config--"


def _host_key_alias(name: str) -> str:
    return f"{HOST_KEY_ALIAS_PREFIX}{name}"


def _load_config():
    # read_ssh_config() opens the file directly and errors if it's
    # missing; touching it first always gets us a saveable SshConfig
    # (empty_ssh_config_file() returns the other, non-saveable type).
    SSH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    if not SSH_CONFIG_PATH.exists():
        SSH_CONFIG_PATH.write_text("", encoding="utf-8")
    return read_ssh_config(str(SSH_CONFIG_PATH))


def remembered_profiles() -> List[str]:
    """Profiles this tool created -- derived directly from ~/.ssh/config
    itself (a Host entry whose HostKeyAlias matches our naming scheme),
    not tracked separately anywhere. Nothing to keep in sync and nothing
    to migrate if this file (or its location) ever changes: the config
    file is the only source of truth."""
    config = _load_config()
    return [
        host
        for host in config.hosts()
        if config.host(host).get("hostkeyalias") == _host_key_alias(host)
    ]


def propagate_key(profile: str) -> None:
    """Copy our public key to the remote host's authorized_keys -- the
    ssh-copy-id equivalent, since Windows OpenSSH doesn't ship one.

    Connects via the profile alias (not a raw user@host), so the host
    key gets trusted under the same HostKeyAlias identity every later
    connection (including the auto-logon check) actually uses.
    Interactive (password/host-key prompts share this console)."""
    ssh = find_ssh()
    if not ssh:
        raise RuntimeError("ssh not found; install OpenSSH first")

    pubkey = PUBLIC_KEY_PATH.read_text(encoding="utf-8").strip()
    remote_command = "umask 077 && mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
    result = subprocess.run([ssh, profile, remote_command], input=pubkey + "\n", text=True)
    if result.returncode != 0:
        raise RuntimeError(f"Key propagation failed with exit code {result.returncode}")


def passwordless_login_works(profile: str) -> bool:
    """Quick, silent, non-interactive check: does key-based auth already
    work for this profile? BatchMode=yes means ssh fails fast instead of
    falling back to a password prompt."""
    ssh = find_ssh()
    if not ssh:
        raise RuntimeError("ssh not found; install OpenSSH first")

    result = subprocess.run(
        [ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", profile, "exit"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def create_profile(name: str, host: str, user: str) -> None:
    """Add (or update) a Host entry named ``name`` (distinct from the
    host itself -- the same host can have multiple profiles under
    different users). Its HostKeyAlias is what makes it show up in
    remembered_profiles() afterward -- nothing extra to remember."""
    config = _load_config()
    values = dict(
        HostName=host,
        User=user,
        IdentityFile=str(PRIVATE_KEY_PATH),
        HostKeyAlias=_host_key_alias(name),
    )
    if name in config.hosts():
        config.set(name, **values)
    else:
        config.add(name, **values)
    config.save()


def _create_new_profile() -> Optional[str]:
    """Ask for a profile name, host, and user; add the Host entry.
    Returns the new profile's name, or None if cancelled."""
    name = questionary.text("Profile:").unsafe_ask()
    if not name:
        return None
    host = questionary.text("Host:").unsafe_ask()
    if not host:
        return None
    user = questionary.text("User:").unsafe_ask()
    if not user:
        return None

    create_profile(name, host, user)
    return name


def choose_profile() -> Optional[str]:
    """Interactive picker: choose a remembered profile, or create a new
    one. Skips straight to creation if there's nothing to pick from yet.
    Defaults to whichever profile was picked last time (just Enter to
    keep using it), and remembers whatever gets picked/created this time
    for next time. Returns the chosen profile's name, or None if
    cancelled."""
    profiles = remembered_profiles()
    if not profiles:
        name = _create_new_profile()
    else:
        last = get_setting(_LAST_PROFILE_KEY)
        default = last if last in profiles else profiles[0]
        choice = questionary.select(
            "SSH profile:", choices=[*profiles, NEW_PROFILE], default=default
        ).unsafe_ask()
        if choice is None:
            return None
        name = choice if choice != NEW_PROFILE else _create_new_profile()

    if name:
        set_setting(_LAST_PROFILE_KEY, name)
    return name
