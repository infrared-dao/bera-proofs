"""
Merkle Tree Building and Manipulation Utilities

This module provides utilities for building and manipulating merkle trees,
including functions for efficient tree construction, chunk processing,
and specialized operations for SSZ types.
"""

import math
from hashlib import sha256
from typing import List

from ..constants import ZERO_HASHES, VALIDATOR_REGISTRY_LIMIT


def merkleize_chunks(chunks: List[bytes], limit: int) -> bytes:
    """
    Merkleize a list of 32-byte chunks using simplified pairing.
    
    This is a simplified approach that pairs chunks and hashes
    them iteratively until reaching a single root.
    
    Args:
        chunks: List of 32-byte chunks to merkleize
        limit: Limit parameter (currently unused but kept for compatibility)
        
    Returns:
        32-byte merkle root
    """
    tree = chunks[:]
    while len(tree) > 1:
        new_tree = []
        for i in range(0, len(tree), 2):
            left = tree[i]
            right = tree[i + 1] if i + 1 < len(tree) else b"\x00" * 32
            combined = left + right
            new_tree.append(sha256(combined).digest())
        tree = new_tree
    return tree[0] if tree else b"\x00" * 32


def merkle_root_from_chunks(chunks: List[bytes]) -> bytes:
    """
    Compute merkle root from a list of 32-byte chunks.
    
    Pads chunks to next power of two and builds merkle tree.
    
    Args:
        chunks: List of 32-byte chunks
        
    Returns:
        32-byte merkle root
    """
    chunks = _pad_to_power_of_two(chunks)
    while len(chunks) > 1:
        paired = []
        for i in range(0, len(chunks), 2):
            left, right = chunks[i], chunks[i + 1]
            paired.append(sha256(left + right).digest())
        chunks = paired
    return chunks[0]


def merkle_root_list_fixed(chunks: List[bytes], limit: int) -> bytes:
    """
    Merkle-root a list of 32-byte chunks, exactly out to 'limit' leaves.
    
    This function efficiently handles large fixed-capacity lists by using
    precomputed zero hashes for padding beyond the actual data.
    
    Args:
        chunks: List of 32-byte chunks (actual data)
        limit: Fixed capacity (must be power of two)
        
    Returns:
        32-byte merkle root
        
    Examples:
        >>> merkle_root_list_fixed([b'\\x01'*32, b'\\x02'*32], 1024)
    """
    n = len(chunks)
    
    # Validate inputs
    if not (limit & (limit - 1) == 0):
        raise ValueError("limit must be a power of two")
    if n > limit:
        raise ValueError(f"Too many leaves: {n} > {limit}")

    # Step A: pad the first n chunks up to m = next_pow2(n)
    if n == 0:
        m = 1
    else:
        m = 1 << ((n - 1).bit_length())  # next power of two ≥ n

    # Build bottom-level nodes
    node_list = []
    for i in range(m):
        if i < n:
            node_list.append(chunks[i])
        else:
            node_list.append(ZERO_HASHES[0])

    # Step B: climb up from m leaves → subtree_root_of_size_m
    levels_m = int(math.log2(m))
    for lvl in range(levels_m):
        next_level = []
        for i in range(0, len(node_list), 2):
            next_level.append(sha256(node_list[i] + node_list[i + 1]).digest())
        node_list = next_level

    subtree_root = node_list[0]  # root over m leaves

    # Step C: keep doubling m → m * 2, hashing (subtree_root || ZERO_HASHES[lvl]) each time,
    # until we reach 'limit'.
    current_size = m
    lvl = levels_m
    while current_size < limit:
        subtree_root = sha256(subtree_root + ZERO_HASHES[lvl]).digest()
        current_size *= 2
        lvl += 1

    return subtree_root


def _pad_to_power_of_two(chunks: List[bytes]) -> List[bytes]:
    """
    Pad a list of 32-byte chunks to a power-of-two length with zero chunks.
    
    Args:
        chunks: List of 32-byte chunks
        
    Returns:
        Padded list with power-of-two length
    """
    n = len(chunks)
    if n == 0:
        return [b"\x00" * 32]
    
    # Next power-of-two ≥ n
    m = 1 << (n - 1).bit_length()
    return chunks + [b"\x00" * 32] * (m - n)


def pack_vector_uint64(values: List[int], vector_length: int) -> List[bytes]:
    """
    SSZ-pack a list of uint64 values into 32-byte chunks for a fixed-length vector.
    
    Args:
        values: List of uint64 values
        vector_length: Fixed length of the vector
        
    Returns:
        List of 32-byte chunks containing the packed data
        
    Examples:
        >>> pack_vector_uint64([1, 2, 3], 8)  # Pads to 8 elements
    """
    # Pad the list to fixed length with zeros
    vals = list(values) + [0] * (vector_length - len(values))
    
    # Serialize to little-endian bytes (8 bytes per uint64)
    data = b"".join(v.to_bytes(8, "little") for v in vals)
    
    # Right-pad to 32-byte multiple
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    
    # Split into 32-byte chunks
    return [data[i : i + 32] for i in range(0, len(data), 32)]


def pack_vector_bytes32(values: List[bytes], vector_length: int) -> List[bytes]:
    """
    SSZ-pack a list of 32-byte items into 32-byte chunks.
    
    Args:
        values: List of 32-byte values (bytes or hex strings)
        vector_length: Fixed length of the vector
        
    Returns:
        List of 32-byte chunks
        
    Examples:
        >>> pack_vector_bytes32([b'\\x01'*32, b'\\x02'*32], 8)
    """
    # Pad the list to fixed length with zero-bytes32
    vals = list(values) + [b"\x00" * 32] * (vector_length - len(values))
    
    # Convert each entry to bytes (if hex string, strip 0x)
    data = b""
    for v in vals:
        if isinstance(v, str):
            h = v[2:] if v.startswith("0x") else v
            v = bytes.fromhex(h)
        if len(v) != 32:
            raise ValueError("Each bytes32 entry must be 32 bytes")
        data += v
    
    # Split into 32-byte chunks (length is already multiple of 32)
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    return [data[i : i + 32] for i in range(0, len(data), 32)]


def get_tree_depth(capacity: int) -> int:
    """
    Calculate the depth of a merkle tree for given capacity.
    
    Args:
        capacity: Number of leaves (must be power of two)
        
    Returns:
        Tree depth (number of levels from leaves to root)
        
    Examples:
        >>> get_tree_depth(1024)  # Returns 10
        >>> get_tree_depth(8)     # Returns 3
    """
    if not (capacity & (capacity - 1) == 0):
        raise ValueError("Capacity must be a power of two")
    
    return capacity.bit_length() - 1


def validate_tree_structure(tree: List[List[bytes]]) -> bool:
    """
    Validate that a tree has the correct structure for a binary merkle tree.
    
    Args:
        tree: List of tree levels from leaves to root
        
    Returns:
        True if tree structure is valid
    """
    if not tree:
        return False
    
    # Check each level has half the nodes of the previous level
    for i in range(1, len(tree)):
        expected_size = (len(tree[i-1]) + 1) // 2
        if len(tree[i]) != expected_size:
            return False
    
    # Root level should have exactly one node
    return len(tree[-1]) == 1 