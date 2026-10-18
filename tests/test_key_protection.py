"""Tests for Ed25519 key protection, encryption, and export (SPEC_PHASE2 §4)."""

from __future__ import annotations

from pathlib import Path
import pytest

from r0nt.signing import (
    compute_key_id,
    export_public_key,
    generate_keypair,
    is_private_key_encrypted,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
)


def test_unencrypted_key_roundtrip(tmp_path: Path):
    priv, pub = generate_keypair()
    key_path = tmp_path / "plain.pem"
    save_private_key(priv, key_path)

    assert not is_private_key_encrypted(key_path)
    loaded = load_private_key(key_path)
    assert compute_key_id(loaded.public_key()) == compute_key_id(pub)


def test_encrypted_key_with_passphrase(tmp_path: Path):
    priv, pub = generate_keypair()
    key_path = tmp_path / "enc.pem"
    save_private_key(priv, key_path, passphrase="super-secret-passphrase")

    assert is_private_key_encrypted(key_path)

    # Correct passphrase loads key
    loaded = load_private_key(key_path, passphrase="super-secret-passphrase")
    assert compute_key_id(loaded.public_key()) == compute_key_id(pub)

    # Missing passphrase fails
    with pytest.raises(ValueError, match="Passphrase required or invalid"):
        load_private_key(key_path, passphrase=None)

    # Incorrect passphrase fails
    with pytest.raises(ValueError, match="Passphrase required or invalid"):
        load_private_key(key_path, passphrase="wrong-passphrase")


def test_export_public_key_from_private(tmp_path: Path):
    priv, pub = generate_keypair()
    pub_path = tmp_path / "exported.pub.pem"
    export_public_key(pub, pub_path)

    assert pub_path.exists()
    loaded_pub = load_public_key(pub_path)
    assert compute_key_id(loaded_pub) == compute_key_id(pub)
