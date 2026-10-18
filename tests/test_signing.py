import hashlib
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

from r0nt.signing import (
    compute_key_id,
    derive_witness_key,
    generate_keypair,
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key,
    sign,
    verify_signature,
)


def test_generate_keypair():
    priv, pub = generate_keypair()
    assert isinstance(priv, Ed25519PrivateKey)
    assert isinstance(pub, Ed25519PublicKey)


def test_sign_and_verify():
    priv, pub = generate_keypair()
    data = b"tamper evident backup payload"
    sig = sign(priv, data)

    assert len(sig) == 64
    assert verify_signature(pub, data, sig)

    # Verification fails on modified data
    assert not verify_signature(pub, data + b"!", sig)

    # Verification fails on corrupted signature
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0xFF
    assert not verify_signature(pub, data, bytes(bad_sig))

    # Verification fails with different key
    _, other_pub = generate_keypair()
    assert not verify_signature(other_pub, data, sig)


def test_compute_key_id():
    _, pub = generate_keypair()
    key_id = compute_key_id(pub)

    assert len(key_id) == 16
    assert key_id == key_id.lower()

    raw_pub = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    expected = hashlib.sha256(raw_pub).hexdigest()[:16]
    assert key_id == expected


def test_derive_witness_key():
    _, pub = generate_keypair()
    wkey = derive_witness_key(pub)
    assert len(wkey) == 32
    assert isinstance(wkey, bytes)

    # Deterministic
    assert derive_witness_key(pub) == wkey

    # Distinct for different pubkey
    _, pub2 = generate_keypair()
    assert derive_witness_key(pub2) != wkey


def test_key_file_io(tmp_path: Path):
    priv, pub = generate_keypair()
    priv_file = tmp_path / "keys" / "private.pem"
    pub_file = tmp_path / "keys" / "public.pem"

    save_private_key(priv, priv_file)
    save_public_key(pub, pub_file)

    assert priv_file.exists()
    assert pub_file.exists()

    loaded_priv = load_private_key(priv_file)
    loaded_pub = load_public_key(pub_file)

    # Verify loaded keys work for sign/verify
    data = b"roundtrip check"
    signature = sign(loaded_priv, data)
    assert verify_signature(loaded_pub, data, signature)
    assert compute_key_id(loaded_pub) == compute_key_id(pub)


def test_load_invalid_keys(tmp_path: Path):
    bad_file = tmp_path / "bad.pem"
    bad_file.write_text("NOT A VALID PEM")

    with pytest.raises(Exception):
        load_private_key(bad_file)

    with pytest.raises(Exception):
        load_public_key(bad_file)
