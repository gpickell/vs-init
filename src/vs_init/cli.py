"""Entry point. Each step runs automatically and flows into the next,
then the process quits.
"""
from __future__ import annotations

import sys
from typing import Optional

import questionary

from . import dnstools, provision, settings, shortcut, sshinstall, sshkey, sshprofile, vscode, winsudo

_BANNER = """\
vs-init provisions this Windows machine to do remote Linux admin work
for a Docker-centric VertiGIS Studio deployment. This run may:

  - Install gsudo via winget, if missing -- used for elevated actions.
  - Install the Windows OpenSSH client (elevated), if missing.
  - Ask whether to install RSAT: DNS Server Tools (elevated) -- optional,
    enables the "Register CNAME" action in the editor extension later.
  - Install Visual Studio Code via winget, if missing.
  - Install the Remote Development extension pack, and our own
    VertiGIS Studio companion extension, locally.
  - Generate a new SSH ed25519 keypair in ~/.ssh, if you don't have one.
  - Create or choose an SSH profile in ~/.ssh/config.
  - Pre-seed VS Code's remote-OS guess for that profile as Linux, so
    Remote-SSH won't ask what kind of host it is.
  - Copy your public key to the remote host's authorized_keys, if you
    confirm and passwordless login isn't already working.
  - On the remote host: install curl and acl (setfacl), install Docker
    via the official `curl | sh` script, add your user to the docker
    group, and share /opt/vertigis-studio for Docker use.
  - Install Container Tools and Docker DX on the remote host itself
    (they need the real Docker daemon, which lives there, not here).
  - Launch VS Code via Remote-SSH, opened (trusted, no prompt) to
    /opt/vertigis-studio on the remote host.\
"""

_PROCEED = "Proceed"
_PROCEED_SKIP = "Proceed, and skip this prompt next time"
_EXIT = "Exit"

_SKIP_INTRO_KEY = "skip_intro"


def _show_banner() -> bool:
    if settings.get_setting(_SKIP_INTRO_KEY, False):
        return True

    print(_BANNER)
    choice = questionary.select(
        "Proceed?",
        choices=[_PROCEED, _PROCEED_SKIP, _EXIT],
        default=_EXIT,
    ).ask()

    if choice == _PROCEED_SKIP:
        settings.set_setting(_SKIP_INTRO_KEY, True)
        return True
    return choice == _PROCEED


def _ensure_gsudo() -> None:
    try:
        winsudo.ensure_gsudo()
    except winsudo.ElevationError as exc:
        print(f"gsudo install failed: {exc}")
        return
    print("gsudo OK.")


def _ensure_ssh() -> None:
    try:
        ok = sshinstall.ensure_ssh()
    except (winsudo.ElevationError, RuntimeError) as exc:
        print(f"SSH install failed: {exc}")
        return
    print("SSH client OK." if ok else "SSH client still missing after install attempt.")


def _ensure_dns_tools() -> None:
    if not questionary.confirm(
        'Install RSAT: DNS Server Tools? Enables the optional "Register CNAME" action in the '
        "editor extension later. Can take a few minutes; safe to skip.",
        default=False,
    ).ask():
        return
    try:
        dnstools.install()
    except (winsudo.ElevationError, RuntimeError) as exc:
        print(f"RSAT: DNS Server Tools install failed: {exc}")
        return
    print("RSAT: DNS Server Tools OK.")


def _ensure_vscode() -> None:
    try:
        ok = vscode.ensure_vscode()
    except RuntimeError as exc:
        print(f"VS Code install failed: {exc}")
        return
    print("VS Code OK." if ok else "VS Code still missing after install attempt.")
    if not ok:
        return
    try:
        vscode.ensure_extensions()
    except RuntimeError as exc:
        print(f"VS Code extension install failed: {exc}")
        return
    print("VS Code extensions OK.")
    try:
        vscode.ensure_own_extension()
    except RuntimeError as exc:
        print(f"VertiGIS Studio extension install failed: {exc}")
        return
    print("VertiGIS Studio extension OK.")


def _ensure_key() -> None:
    try:
        ok = sshkey.ensure_key()
    except RuntimeError as exc:
        print(f"SSH key setup failed: {exc}")
        return
    print("SSH key OK." if ok else "SSH key still missing after generation attempt.")


def _choose_ssh_profile() -> Optional[str]:
    try:
        profile = sshprofile.choose_profile()
    except RuntimeError as exc:
        print(f"SSH profile setup failed: {exc}")
        return None
    print(f"Using profile: {profile}" if profile else "Cancelled.")
    return profile


def _ensure_remote_platform(profile: Optional[str]) -> None:
    if not profile or not vscode.is_installed():
        return
    try:
        vscode.ensure_remote_platform(profile)
    except OSError as exc:
        print(f"Pre-seeding VS Code's remote-OS guess failed: {exc}")


def _ensure_auto_logon(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        if sshprofile.passwordless_login_works(profile):
            print("Auto-logon OK.")
            return
        if not questionary.confirm("Transfer keys for auto login?", default=True).ask():
            return
        sshprofile.propagate_key(profile)
        ok = sshprofile.passwordless_login_works(profile)
    except RuntimeError as exc:
        print(f"Auto-logon setup failed: {exc}")
        return
    print("Auto-logon OK." if ok else "Auto-logon still not working after propagation attempt.")


def _provision(profile: Optional[str]) -> bool:
    if not profile:
        return False
    try:
        provision.provision(profile)
    except RuntimeError as exc:
        print(f"Provisioning failed: {exc}")
        return False
    print("Provisioning OK.")
    return True


def _ensure_remote_extensions(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        vscode.ensure_remote_extensions(profile)
    except RuntimeError as exc:
        print(f"Remote VS Code extension install failed: {exc}")
        return
    print("Remote VS Code extensions OK.")


def _launch_vscode_remote(profile: Optional[str]) -> None:
    if not profile:
        return
    try:
        vscode.open_remote(profile, provision.STUDIO_PATH)
    except RuntimeError as exc:
        print(f"Launching VS Code (Remote-SSH) failed: {exc}")
        return
    print("Launched VS Code (Remote-SSH).")

    code = vscode.find_code()
    if not code:
        return
    try:
        shortcut.ensure_shortcut(profile, code, provision.STUDIO_PATH)
    except (RuntimeError, OSError) as exc:
        print(f"Creating a reusable shortcut failed: {exc}")
        return
    print(
        f'You can come back to this deployment later by searching the Start Menu for '
        f'"VertiGIS Studio Deployment - {profile}", or by typing vs-init-{profile} in a terminal.'
    )


def main() -> None:
    if sys.platform != "win32":
        print("vs-init currently targets Windows hosts only.")
        return

    if not _show_banner():
        print("Cancelled.")
        return

    _ensure_gsudo()
    _ensure_ssh()
    _ensure_dns_tools()
    _ensure_vscode()
    _ensure_key()
    profile = _choose_ssh_profile()
    _ensure_remote_platform(profile)
    _ensure_auto_logon(profile)
    if _provision(profile):
        _ensure_remote_extensions(profile)
        _launch_vscode_remote(profile)


if __name__ == "__main__":
    main()
