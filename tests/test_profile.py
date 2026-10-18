"""Tests for r0nt profile and configuration management (SPEC_PHASE2 §2)."""

from __future__ import annotations

from pathlib import Path
import pytest

from r0nt.profile import (
    DEFAULT_EXCLUDES,
    Profile,
    ProfileManager,
    SourceConfig,
)


def test_default_excludes_content():
    assert any("node_modules" in pat for pat in DEFAULT_EXCLUDES)
    assert any("$RECYCLE.BIN" in pat for pat in DEFAULT_EXCLUDES)
    assert any("pagefile.sys" in pat for pat in DEFAULT_EXCLUDES)


def test_profile_creation_and_defaults(tmp_path: Path):
    source = tmp_path / "data"
    source.mkdir()
    repo = tmp_path / "repo"
    wdb = tmp_path / "witness.db"
    key = tmp_path / "key.pem"
    pubkey = tmp_path / "key.pub.pem"

    profile = Profile(
        name="test_proj",
        sources=[SourceConfig(label="data", path=str(source))],
        repo=str(repo),
        witness_db=str(wdb),
        key_path=str(key),
        pubkey_path=str(pubkey),
    )

    assert profile.name == "test_proj"
    assert profile.chunk_size == 1024 * 1024
    assert profile.exclude == DEFAULT_EXCLUDES
    assert len(profile.sources) == 1
    assert profile.sources[0].label == "data"


def test_profile_validation_duplicate_labels(tmp_path: Path):
    s1 = tmp_path / "s1"
    s2 = tmp_path / "s2"
    s1.mkdir()
    s2.mkdir()

    with pytest.raises(ValueError, match="Duplicate source label"):
        Profile(
            name="dups",
            sources=[
                SourceConfig(label="docs", path=str(s1)),
                SourceConfig(label="docs", path=str(s2)),
            ],
            repo=str(tmp_path / "repo"),
            witness_db=str(tmp_path / "w.db"),
            key_path=str(tmp_path / "k.pem"),
            pubkey_path=str(tmp_path / "k.pub.pem"),
        )


def test_profile_validation_empty_sources(tmp_path: Path):
    with pytest.raises(ValueError, match="At least one source"):
        Profile(
            name="nosources",
            sources=[],
            repo=str(tmp_path / "repo"),
            witness_db=str(tmp_path / "w.db"),
            key_path=str(tmp_path / "k.pem"),
            pubkey_path=str(tmp_path / "k.pub.pem"),
        )


def test_profile_round_trip_toml(tmp_path: Path):
    config_file = tmp_path / "profiles.toml"
    manager = ProfileManager(config_path=config_file)

    p1 = Profile(
        name="p1",
        sources=[
            SourceConfig(label="docs", path=str(tmp_path / "docs")),
            SourceConfig(label="photos", path=str(tmp_path / "photos")),
        ],
        repo=str(tmp_path / "repo"),
        witness_db=str(tmp_path / "w.db"),
        key_path=str(tmp_path / "k.pem"),
        pubkey_path=str(tmp_path / "k.pub.pem"),
        exclude=["*.log"],
    )

    manager.save_profile(p1)
    assert config_file.exists()

    manager2 = ProfileManager(config_path=config_file)
    loaded = manager2.get_profile("p1")
    assert loaded is not None
    assert loaded.name == "p1"
    assert len(loaded.sources) == 2
    assert loaded.sources[0].label == "docs"
    assert loaded.sources[1].label == "photos"
    assert loaded.exclude == ["*.log"]


def test_profile_crud_operations(tmp_path: Path):
    config_file = tmp_path / "profiles.toml"
    manager = ProfileManager(config_path=config_file)

    assert manager.list_profiles() == []

    p1 = Profile(
        name="work",
        sources=[SourceConfig(label="work", path=str(tmp_path / "work"))],
        repo=str(tmp_path / "repo"),
        witness_db=str(tmp_path / "w.db"),
        key_path=str(tmp_path / "k.pem"),
        pubkey_path=str(tmp_path / "k.pub.pem"),
    )
    manager.save_profile(p1)
    assert manager.list_profiles() == ["work"]

    p2 = Profile(
        name="personal",
        sources=[SourceConfig(label="personal", path=str(tmp_path / "personal"))],
        repo=str(tmp_path / "repo2"),
        witness_db=str(tmp_path / "w2.db"),
        key_path=str(tmp_path / "k2.pem"),
        pubkey_path=str(tmp_path / "k2.pub.pem"),
    )
    manager.save_profile(p2)
    assert sorted(manager.list_profiles()) == ["personal", "work"]

    # Delete profile
    deleted = manager.delete_profile("work")
    assert deleted is True
    assert manager.list_profiles() == ["personal"]
    assert manager.get_profile("work") is None


def test_profile_delete_preserves_external_files(tmp_path: Path):
    config_file = tmp_path / "profiles.toml"
    repo = tmp_path / "repo"
    repo.mkdir()
    wdb = tmp_path / "w.db"
    wdb.write_text("dummy witness")
    key = tmp_path / "key.pem"
    key.write_text("dummy key")

    manager = ProfileManager(config_path=config_file)
    p = Profile(
        name="preserve_test",
        sources=[SourceConfig(label="src", path=str(tmp_path / "src"))],
        repo=str(repo),
        witness_db=str(wdb),
        key_path=str(key),
        pubkey_path=str(key),
    )
    manager.save_profile(p)
    manager.delete_profile("preserve_test")

    # Ensure profile is removed from config, but external files are NOT touched
    assert manager.get_profile("preserve_test") is None
    assert repo.exists()
    assert wdb.exists()
    assert key.exists()


def test_profile_rejects_inline_secrets(tmp_path: Path):
    config_file = tmp_path / "profiles.toml"
    # Write raw TOML containing a forbidden secret field
    raw_toml = """
    [profiles.bad]
    name = "bad"
    repo = "/repo"
    witness_db = "/w.db"
    key_path = "/k.pem"
    pubkey_path = "/k.pub.pem"
    password = "supersecretpassword"
    [[profiles.bad.sources]]
    label = "s"
    path = "/s"
    """
    config_file.write_text(raw_toml, encoding="utf-8")

    manager = ProfileManager(config_path=config_file)
    with pytest.raises(ValueError, match="Forbidden secret or unrecognized field"):
        manager.get_profile("bad")
