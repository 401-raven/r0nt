import pytest

from r0nt.chain import Finding, validate_chain
from r0nt.manifest import build_manifest, manifest_hash
from r0nt.signing import generate_keypair


def _make_dummy_manifest(priv, pub, seq: int, prev_hash: str | None) -> dict:
    return build_manifest(
        file_results=[],
        skipped_files=[],
        chunk_size=1048576,
        prev_manifest_hash=prev_hash,
        sequence_number=seq,
        private_key=priv,
        public_key=pub,
    )


def test_validate_chain_valid():
    priv, pub = generate_keypair()
    m1 = _make_dummy_manifest(priv, pub, 1, None)
    h1 = manifest_hash(m1)
    m2 = _make_dummy_manifest(priv, pub, 2, h1)
    h2 = manifest_hash(m2)

    witness_records = [
        {"backup_id": m1["backup_id"], "sequence_number": 1, "manifest_hash": h1},
        {"backup_id": m2["backup_id"], "sequence_number": 2, "manifest_hash": h2},
    ]

    findings = validate_chain([m1, m2], witness_records)
    assert findings == []


def test_validate_chain_snapshot_missing():
    priv, pub = generate_keypair()
    m1 = _make_dummy_manifest(priv, pub, 1, None)
    h1 = manifest_hash(m1)

    # Witness DB knows about m2, but m2 is missing from repo
    witness_records = [
        {"backup_id": m1["backup_id"], "sequence_number": 1, "manifest_hash": h1},
        {"backup_id": "deleted-uuid", "sequence_number": 2, "manifest_hash": "deadbeef" * 8},
    ]

    findings = validate_chain([m1], witness_records)
    missing = [f for f in findings if f.type == "snapshot_missing"]
    assert len(missing) == 1
    assert missing[0].backup_id == "deleted-uuid"


def test_validate_chain_rolled_back():
    priv, pub = generate_keypair()
    m1 = _make_dummy_manifest(priv, pub, 1, None)
    h1 = manifest_hash(m1)

    # Witness DB recorded seq 2, but repo only has seq 1
    witness_records = [
        {"backup_id": m1["backup_id"], "sequence_number": 1, "manifest_hash": h1},
        {"backup_id": "rolled-back-id", "sequence_number": 2, "manifest_hash": "abcd" * 16},
    ]

    findings = validate_chain([m1], witness_records)
    rb = [f for f in findings if f.type == "rolled_back"]
    assert len(rb) == 1


def test_validate_chain_broken_link():
    priv, pub = generate_keypair()
    # Sequence 1 with bad prev hash
    m1 = _make_dummy_manifest(priv, pub, 1, "not-null" * 8)
    findings = validate_chain([m1], [])
    assert any(f.type == "chain_broken" for f in findings)

    # Sequence 2 with unknown prev hash
    m1_clean = _make_dummy_manifest(priv, pub, 1, None)
    m2_bad = _make_dummy_manifest(priv, pub, 2, "unknown" * 8)
    findings = validate_chain([m1_clean, m2_bad], [])
    assert any(f.type == "chain_broken" for f in findings)


def test_validate_chain_sequence_gap():
    priv, pub = generate_keypair()
    m1 = _make_dummy_manifest(priv, pub, 1, None)
    h1 = manifest_hash(m1)
    # Gap: 1 -> 3
    m3 = _make_dummy_manifest(priv, pub, 3, h1)

    findings = validate_chain([m1, m3], [])
    assert any(f.type == "chain_broken" and "Sequence gap" in f.message for f in findings)


def test_validate_chain_manifest_hash_mismatch():
    priv, pub = generate_keypair()
    m1 = _make_dummy_manifest(priv, pub, 1, None)
    h1 = manifest_hash(m1)

    # Witness DB has a different hash for m1
    witness_records = [
        {"backup_id": m1["backup_id"], "sequence_number": 1, "manifest_hash": "different" * 8},
    ]

    findings = validate_chain([m1], witness_records)
    mod = [f for f in findings if f.type == "manifest_modified"]
    assert len(mod) == 1
