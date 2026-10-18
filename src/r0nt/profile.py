"""Profile and configuration management for r0nt (SPEC_PHASE2 §2).

Handles reading and writing profiles.toml in the user configuration directory,
validating profile configurations, and ensuring no secrets are stored in configs.
"""

from __future__ import annotations

import os
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import platformdirs
import tomli_w

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # pragma: no cover

from r0nt.chunker import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_FILE_COUNT,
    DEFAULT_MAX_FILE_SIZE,
    DEFAULT_MAX_TOTAL_SIZE,
)
from r0nt.signing import _set_restrictive_permissions

DEFAULT_EXCLUDES = [
    "*.tmp",
    "*~",
    ".cache/**",
    "node_modules/**",
    ".git/**",
    "$RECYCLE.BIN/**",
    "System Volume Information/**",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
]

FORBIDDEN_CONFIG_KEYS = {
    "password",
    "passphrase",
    "secret",
    "private_key",
    "privkey",
    "private_key_data",
}


@dataclass
class SourceConfig:
    """A single source directory with its top-level canonical label."""
    label: str
    path: str

    def __post_init__(self) -> None:
        if not self.label or not self.label.strip():
            raise ValueError("Source label cannot be empty.")
        if '/' in self.label or '\\' in self.label:
            raise ValueError(f"Source label '{self.label}' cannot contain path separators.")
        if not self.path or not self.path.strip():
            raise ValueError(f"Source path for label '{self.label}' cannot be empty.")


@dataclass
class Profile:
    """Backup job configuration profile."""
    name: str
    sources: list[SourceConfig]
    repo: str
    witness_db: str
    key_path: str
    pubkey_path: str
    chunk_size: int = DEFAULT_CHUNK_SIZE
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    max_file_count: int = DEFAULT_MAX_FILE_COUNT
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("Profile name cannot be empty.")
        if not self.sources:
            raise ValueError("At least one source must be configured.")

        # Ensure unique labels
        labels: set[str] = set()
        for s in self.sources:
            if s.label in labels:
                raise ValueError(f"Duplicate source label '{s.label}' in profile '{self.name}'.")
            labels.add(s.label)

        if not self.repo or not self.repo.strip():
            raise ValueError("Profile 'repo' path cannot be empty.")
        if not self.witness_db or not self.witness_db.strip():
            raise ValueError("Profile 'witness_db' path cannot be empty.")
        if not self.key_path and self.pubkey_path:
            self.key_path = self.pubkey_path
        if not self.pubkey_path and self.key_path:
            self.pubkey_path = self.key_path
        if not self.key_path or not self.key_path.strip():
            raise ValueError("Profile 'key_path' cannot be empty.")
        if not self.pubkey_path or not self.pubkey_path.strip():
            raise ValueError("Profile 'pubkey_path' cannot be empty.")


class ProfileManager:
    """Manages loading, validating, and writing profiles.toml."""

    def __init__(self, config_path: Path | None = None) -> None:
        if config_path is not None:
            self.config_path = config_path
        else:
            config_dir = Path(platformdirs.user_config_dir("r0nt"))
            config_dir.mkdir(parents=True, exist_ok=True)
            self.config_path = config_dir / "profiles.toml"

    def _load_raw_data(self) -> dict[str, Any]:
        if not self.config_path.exists():
            return {"profiles": {}}
        raw_bytes = self.config_path.read_bytes()
        try:
            return tomllib.loads(raw_bytes.decode('utf-8'))
        except Exception as exc:
            raise ValueError(f"Invalid TOML in {self.config_path}: {exc}") from exc

    def _save_raw_data(self, data: dict[str, Any]) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        toml_str = tomli_w.dumps(data)
        self.config_path.write_bytes(toml_str.encode('utf-8'))
        _set_restrictive_permissions(self.config_path)

    def list_profiles(self) -> list[str]:
        data = self._load_raw_data()
        profiles = data.get("profiles", {})
        return sorted(profiles.keys())

    def get_profile(self, name: str) -> Profile | None:
        data = self._load_raw_data()
        profiles = data.get("profiles", {})
        if name not in profiles:
            return None

        p_data = profiles[name]

        # Security check: forbid embedded secrets
        for k in p_data.keys():
            if k.lower() in FORBIDDEN_CONFIG_KEYS:
                raise ValueError(
                    f"Forbidden secret or unrecognized field '{k}' found in profile '{name}'."
                )

        raw_sources = p_data.get("sources", [])
        source_configs: list[SourceConfig] = []
        for s in raw_sources:
            if isinstance(s, dict):
                source_configs.append(SourceConfig(label=s["label"], path=s["path"]))
            elif isinstance(s, str):
                source_configs.append(SourceConfig(label=Path(s).name or "source", path=s))

        return Profile(
            name=name,
            sources=source_configs,
            repo=p_data["repo"],
            witness_db=p_data["witness_db"],
            key_path=p_data["key_path"],
            pubkey_path=p_data["pubkey_path"],
            chunk_size=p_data.get("chunk_size", DEFAULT_CHUNK_SIZE),
            max_file_size=p_data.get("max_file_size", DEFAULT_MAX_FILE_SIZE),
            max_total_size=p_data.get("max_total_size", DEFAULT_MAX_TOTAL_SIZE),
            max_file_count=p_data.get("max_file_count", DEFAULT_MAX_FILE_COUNT),
            exclude=p_data.get("exclude", list(DEFAULT_EXCLUDES)),
        )

    def save_profile(self, profile: Profile) -> None:
        data = self._load_raw_data()
        if "profiles" not in data:
            data["profiles"] = {}

        p_dict = {
            "name": profile.name,
            "sources": [{"label": s.label, "path": s.path} for s in profile.sources],
            "repo": profile.repo,
            "witness_db": profile.witness_db,
            "key_path": profile.key_path,
            "pubkey_path": profile.pubkey_path,
            "chunk_size": profile.chunk_size,
            "max_file_size": profile.max_file_size,
            "max_total_size": profile.max_total_size,
            "max_file_count": profile.max_file_count,
            "exclude": profile.exclude,
        }

        data["profiles"][profile.name] = p_dict
        self._save_raw_data(data)

    def delete_profile(self, name: str) -> bool:
        data = self._load_raw_data()
        profiles = data.get("profiles", {})
        if name in profiles:
            del profiles[name]
            self._save_raw_data(data)
            return True
        return False

    def get_settings(self) -> dict[str, Any]:
        """Load UI and application settings from the configuration file."""
        data = self._load_raw_data()
        return dict(data.get("settings", {}))

    def update_settings(self, **kwargs: Any) -> dict[str, Any]:
        """Update and persist UI and application settings."""
        data = self._load_raw_data()
        settings = dict(data.get("settings", {}))
        settings.update(kwargs)
        data["settings"] = settings
        self._save_raw_data(data)
        return settings
