"""Upload and run the provisioning script (provision.sh, shipped
alongside this module): ensures curl + acl, installs Docker, adds the
user to the docker group, and shares /opt/vertigis-studio for Docker use.

The script does its own detection (package manager, what's already
installed/configured) and self-elevates via sudo per privileged line, so
a fully-provisioned host needs no sudo prompt at all on a later run --
nothing here decides that in advance, it's all in the script.
"""
from __future__ import annotations

import importlib.resources

from . import remote

SCRIPT_NAME = "provision.sh"

# Must match STUDIO_PATH in provision.sh.
STUDIO_PATH = "/opt/vertigis-studio"


def _script_bytes() -> bytes:
    return importlib.resources.files(__package__).joinpath(SCRIPT_NAME).read_bytes()


def provision(profile: str) -> None:
    remote.upload_bytes(profile, _script_bytes(), SCRIPT_NAME)

    # pty=True: provision.sh invokes sudo internally for package
    # installs and the studio dir setup.
    exit_code = remote.run(profile, ["sh", SCRIPT_NAME], pty=True)
    if exit_code != 0:
        raise RuntimeError(f"Provisioning failed with exit code {exit_code}")
