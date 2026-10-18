"""Merkle tree construction, root computation, and inclusion proofs.

Domain separation (SPEC §2):
  - Leaf:     SHA-256(0x00 ‖ data)
  - Internal: SHA-256(0x01 ‖ left ‖ right)
  - Empty:    SHA-256(0x02 ‖ b"empty")

Odd node at a level is promoted unchanged (never duplicated).
"""

from __future__ import annotations

import hashlib
from typing import NamedTuple

# Domain-separation prefixes
LEAF_PREFIX = b'\x00'
INTERNAL_PREFIX = b'\x01'
EMPTY_PREFIX = b'\x02'
EMPTY_SENTINEL = b'empty'


# ---------------------------------------------------------------------------
# Primitive hash helpers
# ---------------------------------------------------------------------------

def leaf_hash(data: bytes) -> bytes:
    """SHA-256(0x00 ‖ data) → 32-byte digest."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def internal_hash(left: bytes, right: bytes) -> bytes:
    """SHA-256(0x01 ‖ left ‖ right) → 32-byte digest."""
    return hashlib.sha256(INTERNAL_PREFIX + left + right).digest()


def empty_root() -> bytes:
    """SHA-256(0x02 ‖ b'empty') → 32-byte digest for an empty tree."""
    return hashlib.sha256(EMPTY_PREFIX + EMPTY_SENTINEL).digest()


# ---------------------------------------------------------------------------
# Proof data
# ---------------------------------------------------------------------------

class ProofStep(NamedTuple):
    """One step in a Merkle inclusion proof."""
    hash: bytes       # sibling hash (32 bytes)
    is_left: bool     # True ⟹ sibling is the *left* child


# ---------------------------------------------------------------------------
# Tree
# ---------------------------------------------------------------------------

class MerkleTree:
    """Merkle tree over a list of leaf data items.

    Each leaf is hashed with the leaf-domain prefix.  Internal nodes use
    the internal-domain prefix.  An odd node at a level is promoted
    unchanged — it is **not** duplicated.

    The tree stores every level so inclusion proofs can be extracted.
    """

    def __init__(self, leaves: list[bytes]) -> None:
        """Build the tree.

        Args:
            leaves: Raw data for each leaf.  Each is hashed as
                    ``SHA256(0x00 ‖ data)``.
        """
        self._leaf_count = len(leaves)
        self._levels: list[list[bytes]] = []

        if not leaves:
            self._root = empty_root()
            return

        # Level 0: leaf hashes
        current = [leaf_hash(d) for d in leaves]
        self._levels.append(list(current))

        # Build upward until a single root remains
        while len(current) > 1:
            nxt: list[bytes] = []
            i = 0
            while i < len(current):
                if i + 1 < len(current):
                    nxt.append(internal_hash(current[i], current[i + 1]))
                else:
                    # Odd node: promote unchanged
                    nxt.append(current[i])
                i += 2
            current = nxt
            self._levels.append(list(current))

        self._root = current[0]

    # -- properties ---------------------------------------------------------

    @property
    def root(self) -> bytes:
        """32-byte Merkle root."""
        return self._root

    @property
    def root_hex(self) -> str:
        """Merkle root as lowercase hex string."""
        return self._root.hex()

    @property
    def leaf_count(self) -> int:
        return self._leaf_count

    # -- proofs -------------------------------------------------------------

    def proof(self, index: int) -> list[ProofStep]:
        """Return an inclusion proof for the leaf at *index* (0-based).

        The proof is a list of ``ProofStep(hash, is_left)`` entries from
        the leaf level up toward the root.

        Raises ``IndexError`` for out-of-range or empty trees.
        """
        if self._leaf_count == 0:
            raise IndexError("Cannot produce a proof for an empty tree")
        if index < 0 or index >= self._leaf_count:
            raise IndexError(
                f"Leaf index {index} out of range [0, {self._leaf_count})"
            )

        steps: list[ProofStep] = []
        idx = index

        for level in self._levels[:-1]:           # every level except root
            if idx % 2 == 0:                       # left child
                if idx + 1 < len(level):
                    steps.append(ProofStep(hash=level[idx + 1], is_left=False))
                # else: promoted odd node, no sibling
            else:                                  # right child
                steps.append(ProofStep(hash=level[idx - 1], is_left=True))
            idx //= 2

        return steps

    # -- static verification ------------------------------------------------

    @staticmethod
    def verify_proof(
        leaf_data: bytes,
        proof: list[ProofStep],
        expected_root: bytes,
    ) -> bool:
        """Verify an inclusion proof against an expected root.

        *leaf_data* is the original (unhashed) leaf payload.
        """
        current = leaf_hash(leaf_data)
        for step in proof:
            if step.is_left:
                current = internal_hash(step.hash, current)
            else:
                current = internal_hash(current, step.hash)
        return current == expected_root
