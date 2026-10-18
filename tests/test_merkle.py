import hashlib
import pytest
from r0nt.merkle import (
    MerkleTree,
    empty_root,
    internal_hash,
    leaf_hash,
    LEAF_PREFIX,
    INTERNAL_PREFIX,
    EMPTY_PREFIX,
    EMPTY_SENTINEL,
)


def test_domain_separation_prefixes():
    assert LEAF_PREFIX == b'\x00'
    assert INTERNAL_PREFIX == b'\x01'
    assert EMPTY_PREFIX == b'\x02'
    assert EMPTY_SENTINEL == b'empty'

    data = b"sample_data"
    expected_leaf = hashlib.sha256(b'\x00' + data).digest()
    assert leaf_hash(data) == expected_leaf

    left = hashlib.sha256(b"left").digest()
    right = hashlib.sha256(b"right").digest()
    expected_internal = hashlib.sha256(b'\x01' + left + right).digest()
    assert internal_hash(left, right) == expected_internal

    expected_empty = hashlib.sha256(b'\x02empty').digest()
    assert empty_root() == expected_empty


def test_empty_tree():
    tree = MerkleTree([])
    assert tree.root == empty_root()
    assert tree.leaf_count == 0
    assert tree.root_hex == empty_root().hex()

    with pytest.raises(IndexError, match="Cannot produce a proof for an empty tree"):
        tree.proof(0)


def test_single_leaf_tree():
    data = b"single chunk"
    tree = MerkleTree([data])
    assert tree.leaf_count == 1
    assert tree.root == leaf_hash(data)

    proof = tree.proof(0)
    assert len(proof) == 0
    assert MerkleTree.verify_proof(data, proof, tree.root)
    assert not MerkleTree.verify_proof(b"different", proof, tree.root)


def test_two_leaf_tree():
    d1 = b"leaf 1"
    d2 = b"leaf 2"
    tree = MerkleTree([d1, d2])
    assert tree.leaf_count == 2
    expected = internal_hash(leaf_hash(d1), leaf_hash(d2))
    assert tree.root == expected

    proof0 = tree.proof(0)
    assert len(proof0) == 1
    assert proof0[0].hash == leaf_hash(d2)
    assert not proof0[0].is_left
    assert MerkleTree.verify_proof(d1, proof0, tree.root)

    proof1 = tree.proof(1)
    assert len(proof1) == 1
    assert proof1[0].hash == leaf_hash(d1)
    assert proof1[0].is_left
    assert MerkleTree.verify_proof(d2, proof1, tree.root)


def test_odd_node_promotion_not_duplicated():
    """Verify odd node is promoted unchanged, NOT duplicated.

    A tree with [d1, d2, d3] must NOT equal [d1, d2, d3, d3].
    """
    d1, d2, d3 = b"leaf 1", b"leaf 2", b"leaf 3"
    tree_odd = MerkleTree([d1, d2, d3])
    tree_dup = MerkleTree([d1, d2, d3, d3])

    # Odd promotion calculation:
    # Level 0: [h1, h2, h3]
    # Level 1: [internal(h1, h2), h3]
    # Root: internal(internal(h1, h2), h3)
    h1 = leaf_hash(d1)
    h2 = leaf_hash(d2)
    h3 = leaf_hash(d3)
    expected_odd_root = internal_hash(internal_hash(h1, h2), h3)
    assert tree_odd.root == expected_odd_root

    # Duplication would be: internal(internal(h1, h2), internal(h3, h3))
    assert tree_odd.root != tree_dup.root


def test_proof_verification_various_sizes():
    for count in [1, 2, 3, 4, 5, 7, 8, 15, 16, 17]:
        leaves = [f"leaf-{i}".encode("utf-8") for i in range(count)]
        tree = MerkleTree(leaves)

        for i in range(count):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, tree.root)

            # Verification should fail with wrong leaf data
            assert not MerkleTree.verify_proof(b"tampered", proof, tree.root)

            # Verification should fail with corrupted proof step
            if proof:
                bad_proof = list(proof)
                bad_step = bad_proof[0]._replace(hash=b'\x00' * 32)
                bad_proof[0] = bad_step
                assert not MerkleTree.verify_proof(leaves[i], bad_proof, tree.root)


def test_proof_index_out_of_range():
    tree = MerkleTree([b"a", b"b"])
    with pytest.raises(IndexError):
        tree.proof(-1)
    with pytest.raises(IndexError):
        tree.proof(2)
