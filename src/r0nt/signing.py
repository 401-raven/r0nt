"""Ed25519 key generation, signing, verification, and key I/O.

Uses the ``cryptography`` library exclusively (SPEC §decisions).
Key files are PEM-encoded.  Private key files get restrictive
permissions (0600 / Windows owner-only ACLs) per SPEC §5.
"""

from __future__ import annotations

import hashlib
import os
import platform
import stat
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization


# ---------------------------------------------------------------------------
# Key generation
# ---------------------------------------------------------------------------

def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    private = Ed25519PrivateKey.generate()
    return private, private.public_key()


# ---------------------------------------------------------------------------
# Key ID  (SPEC §3)
# ---------------------------------------------------------------------------

def compute_key_id(public_key: Ed25519PublicKey) -> str:
    """First 16 hex chars of SHA-256(raw 32-byte public key), lowercase."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def derive_witness_key(public_key: Ed25519PublicKey) -> bytes:
    """Derive a 32-byte witness-DB HMAC key from an Ed25519 public key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(b"r0nt-witness-db-hmac-v1:" + raw).digest()


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def sign(private_key: Ed25519PrivateKey, data: bytes) -> bytes:
    """Sign *data* with Ed25519.  Returns the raw 64-byte signature."""
    return private_key.sign(data)


def verify_signature(
    public_key: Ed25519PublicKey,
    data: bytes,
    signature: bytes,
) -> bool:
    """Verify an Ed25519 signature.  Returns ``True`` if valid.

    The ``cryptography`` library uses constant-time comparison internally.
    """
    try:
        public_key.verify(signature, data)
        return True
    except Exception:          # InvalidSignature or other crypto errors
        return False


# ---------------------------------------------------------------------------
# Key file I/O
# ---------------------------------------------------------------------------

def _set_restrictive_permissions(filepath: Path) -> None:
    """Set owner-only permissions (0600 on Unix, ACLs on Windows)."""
    if platform.system() == 'Windows':
        import subprocess
        try:
            username = os.getlogin()
        except OSError:
            username = os.environ.get('USERNAME') or 'Everyone'
        # Remove inherited permissions, grant owner read+write only
        try:
            subprocess.run(
                ['icacls', str(filepath), '/inheritance:r',
                 '/grant:r', f'{username}:(R,W)'],
                check=True, capture_output=True,
            )
        except Exception:
            pass
    else:
        try:
            filepath.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass


def save_private_key(
    private_key: Ed25519PrivateKey,
    filepath: Path,
    passphrase: str | bytes | None = None,
) -> None:
    """Write a private key to *filepath* in PEM format with 0600 perms."""
    if passphrase:
        pw = passphrase.encode('utf-8') if isinstance(passphrase, str) else passphrase
        encryption = serialization.BestAvailableEncryption(pw)
    else:
        encryption = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(pem)
    _set_restrictive_permissions(filepath)


def load_private_key(
    filepath: Path,
    passphrase: str | bytes | None = None,
) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    pw = passphrase.encode('utf-8') if isinstance(passphrase, str) else passphrase
    try:
        key = serialization.load_pem_private_key(filepath.read_bytes(), password=pw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Passphrase required or invalid for private key: {filepath}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def is_private_key_encrypted(filepath: Path) -> bool:
    """Return True if the private key PEM file is encrypted with a passphrase."""
    raw = filepath.read_bytes()
    return b"ENCRYPTED PRIVATE KEY" in raw


def save_public_key(public_key: Ed25519PublicKey, filepath: Path) -> None:
    """Write a public key to *filepath* in PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_bytes(pem)


def export_public_key(public_key: Ed25519PublicKey, filepath: Path) -> None:
    """Export public key to filepath in PEM format without exposing private key."""
    save_public_key(public_key, filepath)


def load_public_key(filepath: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file (public or private)."""
    raw = filepath.read_bytes()
    try:
        key = serialization.load_pem_public_key(raw)
        if isinstance(key, Ed25519PublicKey):
            return key
    except Exception:
        pass

    try:
        priv = load_private_key(filepath)
        return priv.public_key()
    except Exception:
        pass

    raise ValueError(f"Could not load Ed25519 public key from {filepath}")

