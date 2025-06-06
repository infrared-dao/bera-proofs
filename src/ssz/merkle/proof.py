"""
Merkle Proof Generation and Verification

This module provides functions for generating and verifying merkle proofs,
which are essential for creating cryptographic witnesses that allow
verification of specific data within larger merkle trees.
"""

from hashlib import sha256
from typing import List

from ..constants import ZERO_HASHES


def get_fixed_capacity_proof(
    leaves: List[bytes], index: int, capacity: int
) -> List[bytes]:
    """
    Build a Merkle proof for `index` in a tree of exactly `capacity` leaves,
    where:
      • The first len(leaves) are "real" leaf hashes (32 bytes each).
      • The remaining (capacity - len(leaves)) leaf positions are implicitly zero-leaves.
    capacity must be a power of two (e.g. 2^40 for validators).
    Returns a list of log2(capacity) sibling hashes.
    """
    assert (capacity & (capacity - 1)) == 0, "capacity must be a power of two"
    n_real = len(leaves)
    assert 0 <= index < n_real, "index must lie within the real leaves"

    proof: List[bytes] = []
    depth = capacity.bit_length() - 1  # since capacity = 2^depth

    # current_index = the position of our target leaf at the current level
    current_index = index
    # num_real = how many "real" nodes exist at this level
    num_real = n_real

    # We'll build only the "real" subtree hashes up to the root of the real chunk.
    # On each iteration, we compute the array `parents` that holds the real parents for the next level.
    parents: List[bytes]

    for level in range(depth):
        sibling_index = current_index ^ 1

        # 1) Determine sibling_hash at this level:
        if level == 0:
            # Level 0: siblings come from the `leaves[]` or are zero if beyond n_real
            if sibling_index < num_real:
                sibling_hash = leaves[sibling_index]
            else:
                sibling_hash = ZERO_HASHES[0]
        else:
            # Level > 0: siblings come from the previous level's `parents[]` or ZERO_HASHES[level]
            if sibling_index < len(parents):
                sibling_hash = parents[sibling_index]
            else:
                sibling_hash = ZERO_HASHES[level]

        proof.append(sibling_hash)

        # 2) Build the next‐level "parents" array from the current real nodes only:
        if level == 0:
            # Start from leaf level: pair up `leaves[i]` (if i < num_real) or ZERO_HASHES[0]
            parents = []
            for i in range(0, num_real, 2):
                left = leaves[i]
                right = leaves[i + 1] if (i + 1) < num_real else ZERO_HASHES[0]
                parents.append(sha256(left + right).digest())
            num_real = (num_real + 1) // 2
        else:
            # We already have a `parents` from the previous iteration's "left/right hashing."
            new_parents: List[bytes] = []
            # Only iterate over *actual* real parents, not capacity
            for i in range(0, num_real, 2):
                left = parents[i]
                right = parents[i + 1] if (i + 1) < num_real else ZERO_HASHES[level]
                new_parents.append(sha256(left + right).digest())
            parents = new_parents
            num_real = (num_real + 1) // 2

        current_index //= 2

    return proof


def compute_root_from_proof(leaf: bytes, index: int, proof: List[bytes]) -> bytes:
    """
    Rebuild the merkle root from a 32-byte leaf and its fixed-capacity proof.
    
    Args:
        leaf: 32-byte hash of the target element
        index: 0-based position of that leaf in the capacity-sized tree
        proof: List of sibling hashes, one per level, as returned by get_fixed_capacity_proof
        
    Returns:
        The reconstructed 32-byte merkle root
        
    Examples:
        >>> root = compute_root_from_proof(leaf_hash, 5, proof_siblings)
    """
    current = leaf
    for level, sibling in enumerate(proof):
        # Check the bit at position `level` in `index`:
        if ((index >> level) & 1) == 0:
            # Our node was on the left, sibling is on the right
            current = sha256(current + sibling).digest()
        else:
            # Our node was on the right, sibling is on the left
            current = sha256(sibling + current).digest()
    return current


def get_proof(tree: List[List[bytes]], index: int) -> List[bytes]:
    """
    Extract a Merkle proof from a tree for a given leaf index.
    
    This function traverses up the tree from a leaf to the root,
    collecting sibling nodes to form the proof path.
    
    Args:
        tree: Complete Merkle tree as list of levels, where tree[0] is leaves
        index: Index of the leaf to generate proof for
        
    Returns:
        List of sibling hashes forming the proof path
        
    Example:
        >>> leaves = [b'leaf0', b'leaf1', b'leaf2', b'leaf3']  
        >>> tree = build_merkle_tree(leaves)
        >>> proof = get_proof(tree, 1)  # Proof for leaf1
        >>> # proof contains siblings needed to reconstruct root
    """
    proof = []
    level = 0
    i = index
    
    while level < len(tree) - 1:
        sibling_i = i ^ 1  # XOR to get sibling index
        if sibling_i < len(tree[level]):
            sibling = tree[level][sibling_i]
        else:
            sibling = b"\0" * 32  # Zero padding for incomplete levels
        proof.append(sibling)
        i //= 2  # Move to parent index
        level += 1
        
    return proof


def verify_merkle_proof(
    leaf: bytes, proof: List[bytes], index: int, root: bytes
) -> bool:
    """
    Verify a merkle proof against a known root.
    
    Args:
        leaf: The leaf value being proven
        proof: List of sibling hashes
        index: Index of the leaf in the tree
        root: Expected merkle root
        
    Returns:
        True if the proof is valid
        
    Examples:
        >>> is_valid = verify_merkle_proof(leaf, proof, 5, expected_root)
    """
    current = leaf
    for sibling in proof:
        if index % 2 == 0:
            current = sha256(current + sibling).digest()  # Leaf is left
        else:
            current = sha256(sibling + current).digest()  # Leaf is right
        index //= 2  # Move up the tree
    return current == root


def validate_proof_length(proof: List[bytes], tree_depth: int) -> bool:
    """
    Validate that a proof has the correct length for a given tree depth.
    
    Args:
        proof: The merkle proof
        tree_depth: Expected depth of the tree
        
    Returns:
        True if proof length matches expected depth
    """
    return len(proof) == tree_depth


def get_proof_indices(index: int, tree_depth: int) -> List[int]:
    """
    Calculate the sibling indices for a merkle proof path.
    
    Args:
        index: Index of the target leaf
        tree_depth: Depth of the merkle tree
        
    Returns:
        List of sibling indices at each level
        
    Examples:
        >>> indices = get_proof_indices(5, 10)  # Proof path for index 5 in depth-10 tree
    """
    indices = []
    current_index = index
    
    for _ in range(tree_depth):
        sibling_index = current_index ^ 1
        indices.append(sibling_index)
        current_index //= 2
    
    return indices


def batch_verify_proofs(
    leaves: List[bytes], 
    proofs: List[List[bytes]], 
    indices: List[int], 
    root: bytes
) -> List[bool]:
    """
    Verify multiple merkle proofs against the same root.
    
    Args:
        leaves: List of leaf values being proven
        proofs: List of merkle proofs (one per leaf)
        indices: List of leaf indices
        root: Expected merkle root
        
    Returns:
        List of boolean results for each proof
    """
    results = []
    for leaf, proof, index in zip(leaves, proofs, indices):
        is_valid = verify_merkle_proof(leaf, proof, index, root)
        results.append(is_valid)
    return results 