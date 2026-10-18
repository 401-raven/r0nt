from pathlib import Path
import pytest

from r0nt.chunker import hash_chunk
from r0nt.manifest import build_manifest, manifest_to_bytes
from r0nt.signing import derive_witness_key, generate_keypair
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_all


def _setup_backup_env(tmp_path: Path):
    repo = tmp_path / "repo"
    wdb_path = tmp_path / "witness.sqlite"
    priv, pub = generate_keypair()
    mac_key = derive_witness_key(pub)
    wdb = WitnessDB(wdb_path, mac_key)

    chunk_store = ChunkStore(repo)
    manifest_store = ManifestStore(repo)

    # File 1: 2 chunks
    c1_data = b"chunk 1 data"
    c2_data = b"chunk 2 data"
    h1 = hash_chunk(c1_data)
    h2 = hash_chunk(c2_data)

    chunk_store.write_chunk(h1, c1_data)
    chunk_store.write_chunk(h2, c2_data)

    from r0nt.chunker import ChunkInfo, FileResult
    fr = FileResult(
        path="docs/sample.txt",
        size=len(c1_data) + len(c2_data),
        mtime=1700000000,
        chunks=[ChunkInfo(hash=h1, data=c1_data), ChunkInfo(hash=h2, data=c2_data)],
        unstable=False,
    )

    manifest = build_manifest(
        file_results=[fr],
        skipped_files=[],
        chunk_size=1024,
        prev_manifest_hash=None,
        sequence_number=1,
        private_key=priv,
        public_key=pub,
    )

    manifest_store.write_manifest(manifest)
    wdb.record_manifest(manifest)

    return repo, wdb, pub, manifest, [h1, h2]


def test_verify_clean(tmp_path: Path):
    repo, wdb, pub, manifest, _ = _setup_backup_env(tmp_path)
    findings = verify_all(repo, None, pub, wdb)
    assert findings == []
    wdb.close()


def test_verify_chunk_missing(tmp_path: Path):
    repo, wdb, pub, manifest, chunk_hashes = _setup_backup_env(tmp_path)
    # Delete first chunk
    h = chunk_hashes[0]
    chunk_file = repo / "chunks" / h[:2] / h
    chunk_file.unlink()

    findings = verify_all(repo, None, pub, wdb)
    missing = [f for f in findings if f.type == "chunk_missing"]
    assert len(missing) == 1
    assert missing[0].chunk_hash == h
    assert missing[0].file_path == "docs/sample.txt"
    wdb.close()


def test_verify_chunk_modified(tmp_path: Path):
    repo, wdb, pub, manifest, chunk_hashes = _setup_backup_env(tmp_path)
    # Flip a byte in the second chunk
    h = chunk_hashes[1]
    chunk_file = repo / "chunks" / h[:2] / h
    data = bytearray(chunk_file.read_bytes())
    data[0] ^= 0xFF
    chunk_file.write_bytes(data)

    findings = verify_all(repo, None, pub, wdb)
    mod = [f for f in findings if f.type == "chunk_modified"]
    assert len(mod) == 1
    assert mod[0].chunk_hash == h
    wdb.close()


def test_verify_signature_invalid(tmp_path: Path):
    repo, wdb, pub, manifest, _ = _setup_backup_env(tmp_path)
    # Tamper with manifest signature
    m_path = repo / "manifests" / f"{manifest['backup_id']}.json"
    data = manifest
    data["signature"] = "00" * 64
    m_path.write_bytes(manifest_to_bytes(data))

    findings = verify_all(repo, None, pub, wdb)
    sig_invalid = [f for f in findings if f.type == "signature_invalid"]
    assert len(sig_invalid) == 1
    wdb.close()


def test_verify_witness_db_tampered(tmp_path: Path):
    repo, wdb, pub, manifest, _ = _setup_backup_env(tmp_path)
    # Tamper with root_hash in witness DB directly
    wdb.conn.execute("UPDATE manifests SET root_hash = 'tampered' WHERE backup_id = ?", (manifest["backup_id"],))
    wdb.conn.commit()

    findings = verify_all(repo, None, pub, wdb)
    assert any("Witness DB row MAC invalid" in f.message for f in findings)
    wdb.close()


def test_verify_manifest_in_repo_not_in_witness(tmp_path: Path):
    repo, wdb, pub, manifest, _ = _setup_backup_env(tmp_path)
    # Write an extra manifest to repo
    m_store = ManifestStore(repo)
    extra = dict(manifest)
    extra["backup_id"] = "extra-uuid-1234"
    m_store.write_manifest(extra)

    findings = verify_all(repo, None, pub, wdb)
    added = [f for f in findings if f.type == "file_added"]
    assert len(added) == 1
    assert added[0].backup_id == "extra-uuid-1234"
    wdb.close()
