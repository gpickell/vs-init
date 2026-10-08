"""Local settings directory at ~/.vs-init, with the JSON settings file
inside it (~/.vs-init/settings.json) -- a directory, not just a file,
since other per-user state needs to live there too now (e.g. the Edge
profile Register App's token capture reuses across runs)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SETTINGS_DIR = Path.home() / ".vs-init"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"


def _migrate_legacy_file() -> None:
    """~/.vs-init used to be the settings file itself (flat), not a
    directory. Preserves whatever was already in it rather than
    discarding it -- a no-op once already migrated (SETTINGS_DIR is a
    real directory by then, not a file)."""
    if not SETTINGS_DIR.exists() or not SETTINGS_DIR.is_file():
        return
    content = SETTINGS_DIR.read_text(encoding="utf-8")
    SETTINGS_DIR.unlink()
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(content, encoding="utf-8")


def _load() -> dict:
    _migrate_legacy_file()
    if not SETTINGS_FILE.exists():
        return {}
    return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))


def _save(data: dict) -> None:
    _migrate_legacy_file()
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def get_setting(key: str, default: Any = None) -> Any:
    return _load().get(key, default)


def set_setting(key: str, value: Any) -> None:
    data = _load()
    data[key] = value
    _save(data)
