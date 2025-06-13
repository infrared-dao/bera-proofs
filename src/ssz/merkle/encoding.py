"""
Special Encoding Functions for BeaconState Lists and Vectors

This module contains specialized encoding functions for various BeaconState
fields that require custom merkleization logic specific to Berachain's SSZ
implementation.
"""

from typing import List
from hashlib import sha256
import math

from ..constants import (
    VALIDATOR_REGISTRY_LIMIT,
    SLOTS_PER_HISTORICAL_ROOT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR,
    MAX_VALIDATORS,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT,
    ZERO_HASHES,
)


def pack_vector_uint64(values: List[int], vector_length: int) -> List[bytes]:
    """SSZ-pack a list of uint64 (little-endian) into 32-byte chunks for a fixed-length vector."""
    # Pad the list to fixed length with zeros
    vals = list(values) + [0] * (vector_length - len(values))
    # Serialize to little-endian bytes
    data = b"".join(v.to_bytes(8, "little") for v in vals)
    # Right-pad to 32-byte multiple
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    # Split into 32-byte chunks
    return [data[i : i + 32] for i in range(0, len(data), 32)]


def pack_vector_bytes32(values: List[bytes], vector_length: int) -> List[bytes]:
    """SSZ-pack a list of 32-byte items (given as bytes or hex strings) into 32-byte chunks."""
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
    # (Length is already a multiple of 32, but for safety:)
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    return [data[i : i + 32] for i in range(0, len(data), 32)]


def merkle_root_list_fixed(chunks: List[bytes], limit: int) -> bytes:
    """
    Merkle-root a list of 32-byte chunks, exactly out to 'limit' leaves
    (limit must be a power of two). Leaves beyond len(chunks) are zeros.
    """
    n = len(chunks)
    assert (limit & (limit - 1)) == 0, "limit must be a power of two"
    assert n <= limit, f"Too many leaves: {n} > {limit}"

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


def encode_pending_partial_withdrawals_leaf_list(ppw_list_leaves: List[bytes]) -> bytes:
    """
    Encode a list of pending partial withdrawal merkle roots.
    Note: assumes ppw structs are already merkleized into list of leaves.
    """
    if len(ppw_list_leaves) > MAX_VALIDATORS:
        raise ValueError(
            f"Pending partial withdrawals list too large: {len(ppw_list_leaves)} > {MAX_VALIDATORS}"
        )

    # Calculate limit for Merkleization
    ppw_list_root = merkle_root_list_fixed(
        ppw_list_leaves, PENDING_PARTIAL_WITHDRAWALS_LIMIT
    )
    ppw_list_root = sha256(
        ppw_list_root + len(ppw_list_leaves).to_bytes(32, "little")
    ).digest()

    return ppw_list_root


def encode_validators_leaf_list(validator_list_leaves: List[bytes]) -> bytes:
    """
    Encode a list of validator merkle roots.
    Note: assumes validator structs are already merkleized into list of leaves.
    """
    if len(validator_list_leaves) > VALIDATOR_REGISTRY_LIMIT:
        raise ValueError(
            f"Validators list too large: {len(validator_list_leaves)} > {VALIDATOR_REGISTRY_LIMIT}"
        )

    # Calculate limit for Merkleization
    validator_list_root = merkle_root_list_fixed(
        validator_list_leaves, VALIDATOR_REGISTRY_LIMIT
    )
    validator_list_root = sha256(
        validator_list_root + len(validator_list_leaves).to_bytes(32, "little")
    ).digest()

    return validator_list_root


def encode_balances(balances: List[int]) -> bytes:
    """Encode validator balances list."""
    if len(balances) > MAX_VALIDATORS:
        raise ValueError(f"Balances list too large: {len(balances)} > {MAX_VALIDATORS}")

    bal_chunks = pack_vector_uint64(balances, MAX_VALIDATORS)

    # Calculate limit for Merkleization
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    balances_root = merkle_root_list_fixed(bal_chunks, limit)
    balances_root = sha256(
        balances_root + len(balances).to_bytes(32, "little")
    ).digest()

    return balances_root


def encode_randao_mixes(randao_mixes: List[bytes]) -> bytes:
    """Encode randao mixes vector."""
    if len(randao_mixes) > EPOCHS_PER_HISTORICAL_VECTOR:
        raise ValueError(
            f"RandaoMixes list too large: {len(randao_mixes)} > {EPOCHS_PER_HISTORICAL_VECTOR}"
        )

    randao_chunks = pack_vector_bytes32(randao_mixes, 8)

    randao_root = merkle_root_list_fixed(randao_chunks, EPOCHS_PER_HISTORICAL_VECTOR)
    randao_root = sha256(
        randao_root + len(randao_mixes).to_bytes(32, "little")
    ).digest()

    return randao_root


def encode_block_roots(block_roots: List[bytes]) -> bytes:
    """Encode block roots vector."""
    if len(block_roots) > SLOTS_PER_HISTORICAL_ROOT:
        raise ValueError(
            f"Block roots list too large: {len(block_roots)} > {SLOTS_PER_HISTORICAL_ROOT}"
        )

    # Note: In your coworker's implementation, they're passing the raw block_roots
    # without packing them first - this suggests they're already 32-byte chunks
    br_root = merkle_root_list_fixed(block_roots, SLOTS_PER_HISTORICAL_ROOT)
    br_root = sha256(br_root + len(block_roots).to_bytes(32, "little")).digest()

    return br_root


def encode_slashings(slashings: List[int]) -> bytes:
    """Encode slashings vector."""
    if len(slashings) > EPOCHS_PER_SLASHINGS_VECTOR:
        raise ValueError(
            f"Slashings list too large: {len(slashings)} > {EPOCHS_PER_SLASHINGS_VECTOR}"
        )

    slash_chunks = pack_vector_uint64(slashings, EPOCHS_PER_SLASHINGS_VECTOR)
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    slash_root = merkle_root_list_fixed(slash_chunks, limit)
    slash_root = sha256(slash_root + len(slashings).to_bytes(32, "little")).digest()

    return slash_root
