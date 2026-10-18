"""Acceptance tests for r0nt v1 (SPEC §9 items 1–8).

Verifies the tamper-evident security properties under adversarial actions.
"""

from pathlib import Path
import json
import pytest

from r0nt.chunker import hash_chunk
from r0nt.cli import main
from r0nt.manifest import (
    build_manifest,
    canonical_json,
    manifest_from_bytes,
    manifest_hash,
    manifest_to_bytes,
)
from r0nt.merkle import MerkleTree, empty_root, leaf_hash
from r0nt.signing import (
    derive_witness_key,
    generate_keypair,
    load_public_key,
    save_private_key,
    save_public_key,
)
from r0nt.store import ChunkStore, ManifestStore, WitnessDB
from r0nt.verify import verify_all


@pytest.fixture
def test_env(tmp_path: Path):
    """Sets up a complete working environment with a source dir, repo, and witness DB."""
    source = tmp_path / "source"
    source.mkdir()
    (source / "file1.txt").write_text("Hello, world! This is file 1.")
    (source / "sub").mkdir()
    (source / "sub" / "file2.txt").write_text("Second file inside a subdirectory.")

    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    priv_file = keys_dir / "key.pem"
    pub_file = keys_dir / "key.pub.pem"

    priv, pub = generate_keypair()
    save_private_key(priv, priv_file)
    save_public_key(pub, pub_file)

    repo = tmp_path / "repo"
    witness_db = tmp_path / "witness.sqlite"

    return {
        "source": source,
        "repo": repo,
        "witness_db": witness_db,
        "priv_file": priv_file,
        "pub_file": pub_file,
        "priv": priv,
        "pub": pub,
    }


def test_acceptance_1_flip_byte_in_stored_chunk(test_env):
    """1. Flip one byte in a stored chunk: detected, and that chunk is named."""
    # 1. Take a backup via CLI
    ret = main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])
    assert ret == 0

    # 2. Pick a stored chunk and flip a byte
    chunk_store = ChunkStore(test_env["repo"])
    chunks = chunk_store.list_chunks()
    assert len(chunks) > 0
    target_chunk = chunks[0]
    chunk_file = test_env["repo"] / "chunks" / target_chunk[:2] / target_chunk

    data = bytearray(chunk_file.read_bytes())
    data[0] ^= 0xFF
    chunk_file.write_bytes(data)

    # 3. Verify must fail and name the chunk
    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    assert len(findings) > 0
    chunk_mod_findings = [f for f in findings if f.type == "chunk_modified"]
    assert len(chunk_mod_findings) >= 1
    assert any(f.chunk_hash == target_chunk for f in chunk_mod_findings)


def test_acceptance_2_delete_stored_chunk(test_env):
    """2. Delete a stored chunk: detected."""
    # 1. Take backup
    ret = main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])
    assert ret == 0

    # 2. Delete a chunk
    chunk_store = ChunkStore(test_env["repo"])
    chunks = chunk_store.list_chunks()
    target_chunk = chunks[0]
    chunk_file = test_env["repo"] / "chunks" / target_chunk[:2] / target_chunk
    chunk_file.unlink()

    # 3. Verify detects chunk_missing
    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    missing = [f for f in findings if f.type == "chunk_missing"]
    assert len(missing) >= 1
    assert any(f.chunk_hash == target_chunk for f in missing)


def test_acceptance_3_delete_snapshot_manifest(test_env):
    """3. Delete a snapshot manifest: detected as snapshot_missing or chain_broken."""
    # 1. Take 2 backups
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    (test_env["source"] / "file3.txt").write_text("Snapshot 2 file")
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    # 2. Delete the first manifest
    manifest_store = ManifestStore(test_env["repo"])
    manifest_ids = manifest_store.list_manifests()
    assert len(manifest_ids) == 2
    first_id = manifest_ids[0]
    manifest_store.delete_manifest(first_id)

    # 3. Verify
    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    types = {f.type for f in findings}
    assert ("snapshot_missing" in types) or ("chain_broken" in types)


def test_acceptance_4_replace_latest_snapshot_with_older(test_env):
    """4. Replace the latest snapshot with an older one: detected as rolled_back (via witness DB)."""
    # 1. Take snapshot 1
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    manifest_store = ManifestStore(test_env["repo"])
    snap1_id = manifest_store.list_manifests()[0]
    snap1_content = (test_env["repo"] / "manifests" / f"{snap1_id}.json").read_bytes()

    # 2. Take snapshot 2
    (test_env["source"] / "update.txt").write_text("Update")
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    all_ids = manifest_store.list_manifests()
    assert len(all_ids) == 2
    snap2_id = [bid for bid in all_ids if bid != snap1_id][0]

    # 3. Simulate rollback attack: delete snapshot 2 from repo
    manifest_store.delete_manifest(snap2_id)

    # 4. Verify detects rollback via witness DB
    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    types = {f.type for f in findings}
    assert "rolled_back" in types or "snapshot_missing" in types


def test_acceptance_5_edit_manifest_without_key(test_env):
    """5. Edit a manifest without the key: signature_invalid."""
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    manifest_store = ManifestStore(test_env["repo"])
    bid = manifest_store.list_manifests()[0]
    m_file = test_env["repo"] / "manifests" / f"{bid}.json"
    manifest = json.loads(m_file.read_text(encoding="utf-8"))

    # Attacker modifies a file size or path without resigning
    manifest["files"][0]["size"] += 1
    m_file.write_bytes(manifest_to_bytes(manifest))

    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    types = {f.type for f in findings}
    assert "signature_invalid" in types


def test_acceptance_6_edit_manifest_and_hashes_together_without_key(test_env):
    """6. Edit manifest and hashes together without the key: signature_invalid."""
    main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])

    manifest_store = ManifestStore(test_env["repo"])
    bid = manifest_store.list_manifests()[0]
    m_file = test_env["repo"] / "manifests" / f"{bid}.json"
    manifest = json.loads(m_file.read_text(encoding="utf-8"))

    # Attacker rewrites both chunks and manifest root_hash, but cannot forge the signature
    manifest["root_hash"] = "99" * 32
    if manifest["files"]:
        manifest["files"][0]["file_root"] = "99" * 32
    m_file.write_bytes(manifest_to_bytes(manifest))

    mac_key = derive_witness_key(test_env["pub"])
    wdb = WitnessDB(test_env["witness_db"], mac_key)
    findings = verify_all(test_env["repo"], None, test_env["pub"], wdb)
    wdb.close()

    types = {f.type for f in findings}
    assert "signature_invalid" in types


def test_acceptance_7_merkle_edge_cases():
    """7. Merkle edge cases:

    - empty tree
    - one leaf
    - odd leaf counts
    - empty file
    - duplicated-leaf case that must produce a different root.
    """
    # Empty tree
    tree_empty = MerkleTree([])
    assert tree_empty.root == empty_root()

    # One leaf
    leaf_a = b"chunk_a"
    tree_one = MerkleTree([leaf_a])
    assert tree_one.root == leaf_hash(leaf_a)

    # Odd leaf counts (3, 5)
    leaves_3 = [b"c1", b"c2", b"c3"]
    tree_3 = MerkleTree(leaves_3)
    assert tree_3.leaf_count == 3
    for i in range(3):
        assert MerkleTree.verify_proof(leaves_3[i], tree_3.proof(i), tree_3.root)

    leaves_5 = [b"c1", b"c2", b"c3", b"c4", b"c5"]
    tree_5 = MerkleTree(leaves_5)
    assert tree_5.leaf_count == 5
    for i in range(5):
        assert MerkleTree.verify_proof(leaves_5[i], tree_5.proof(i), tree_5.root)

    # Empty file has zero chunks -> its file root is empty_root()
    empty_file_chunks = []
    tree_empty_file = MerkleTree(empty_file_chunks)
    assert tree_empty_file.root == empty_root()

    # Duplicated-leaf case: [a, b, c] vs [a, b, c, c] MUST produce different roots
    tree_abc = MerkleTree([b"a", b"b", b"c"])
    tree_abcc = MerkleTree([b"a", b"b", b"c", b"c"])
    assert tree_abc.root != tree_abcc.root


def test_acceptance_8_unmodified_backups_verify_clean(test_env):
    """8. Unmodified backups verify clean with no false positives."""
    # 1. Initial backup
    ret1 = main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])
    assert ret1 == 0

    # 2. Subsequent backup with added file
    (test_env["source"] / "another.txt").write_text("Another clean file")
    ret2 = main([
        "backup",
        str(test_env["source"]),
        "--repo", str(test_env["repo"]),
        "--key", str(test_env["priv_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])
    assert ret2 == 0

    # 3. Verify via CLI
    ret_verify = main([
        "verify",
        "--repo", str(test_env["repo"]),
        "--pubkey", str(test_env["pub_file"]),
        "--witness-db", str(test_env["witness_db"]),
    ])
    assert ret_verify == 0
