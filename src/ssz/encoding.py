"""
Specialized SSZ Encoding Functions

This module provides specialized encoding functions for specific data structures
like balances, randao mixes, block roots, and slashings. These functions handle
the complex encoding rules for BeaconChain-specific data types.
"""

from hashlib import sha256
from typing import List

from .constants import (
    MAX_VALIDATORS, 
    VALIDATOR_REGISTRY_LIMIT, 
    EPOCHS_PER_HISTORICAL_VECTOR,
    SLOTS_PER_HISTORICAL_ROOT,
    ZERO_HASHES
)
from .merkle.tree import merkle_root_list_fixed, pack_vector_uint64, pack_vector_bytes32


def encode_balances(balances: List[int]) -> bytes:
    """
    Encode a list of validator balances according to SSZ rules.
    
    This function handles the encoding of validator balances as a List[uint64, VALIDATOR_REGISTRY_LIMIT],
    which involves packing the values into chunks and computing the Merkle root with length mixing.
    
    Args:
        balances: List of validator balance values (uint64)
        
    Returns:
        32-byte Merkle root of the encoded balances
        
    Raises:
        ValueError: If balances list exceeds MAX_VALIDATORS
        
    Examples:
        >>> balances = [32000000000, 32000000000, 31500000000]
        >>> root = encode_balances(balances)
    """
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
    """
    Encode a list of randao mixes according to SSZ rules.
    
    This function handles the encoding of randao mixes as a Vector[bytes32, EPOCHS_PER_HISTORICAL_VECTOR],
    with proper chunk packing and Merkle root computation.
    
    Args:
        randao_mixes: List of 32-byte randao mix values
        
    Returns:
        32-byte Merkle root of the encoded randao mixes
        
    Raises:
        ValueError: If randao_mixes list exceeds EPOCHS_PER_HISTORICAL_VECTOR
        
    Examples:
        >>> mixes = [b'\\x00' * 32, b'\\x01' * 32]
        >>> root = encode_randao_mixes(mixes)
    """
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
    """
    Encode block roots for the beacon chain state.
    
    This function encodes a list of block root hashes using SSZ encoding
    with proper length validation and merkleization.
    
    Args:
        block_roots: List of 32-byte block root hashes
        
    Returns:
        Encoded block roots as 32-byte hash
        
    Raises:
        ValueError: If block_roots list exceeds maximum allowed size
        
    Example:
        >>> roots = [b'root1'.ljust(32, b'\\x00'), b'root2'.ljust(32, b'\\x00')]
        >>> encoded = encode_block_roots(roots)
        >>> len(encoded) == 32  # Returns 32-byte hash
        True
    """
    if len(block_roots) > SLOTS_PER_HISTORICAL_ROOT:
        raise ValueError(
            f"Block roots list too large: {len(block_roots)} > {SLOTS_PER_HISTORICAL_ROOT}"
        )

    br_root = merkle_root_list_fixed(block_roots, SLOTS_PER_HISTORICAL_ROOT)
    br_root = sha256(br_root + len(block_roots).to_bytes(32, "little")).digest()

    return br_root


def encode_slashings(slashings: List[bytes]) -> bytes:
    """
    Encode slashings data for the beacon chain state.
    
    This function encodes a list of slashing amounts using SSZ encoding
    with proper chunking and merkleization.
    
    Args:
        slashings: List of slashing amount bytes
        
    Returns:
        Encoded slashings as 32-byte hash
        
    Raises:
        ValueError: If slashings list exceeds maximum allowed size
        
    Example:
        >>> slashings = [b'slash1'.ljust(32, b'\\x00')]
        >>> encoded = encode_slashings(slashings)
        >>> len(encoded) == 32  # Returns 32-byte hash
        True
    """
    if len(slashings) > EPOCHS_PER_HISTORICAL_VECTOR:
        raise ValueError(
            f"Slashings list too large: {len(slashings)} > {EPOCHS_PER_HISTORICAL_VECTOR}"
        )

    slash_chunks = pack_vector_bytes32(slashings, 8)
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    slash_root = merkle_root_list_fixed(slash_chunks, limit)
    slash_root = sha256(slash_root + len(slashings).to_bytes(32, "little")).digest()

    return slash_root


def validate_encoding_constraints(
    data_length: int, 
    max_length: int, 
    data_type: str
) -> None:
    """
    Validate that data meets encoding constraints.
    
    Args:
        data_length: Length of the data being encoded
        max_length: Maximum allowed length
        data_type: Type description for error messages
        
    Raises:
        ValueError: If data_length exceeds max_length
    """
    if data_length > max_length:
        raise ValueError(f"{data_type} list too large: {data_length} > {max_length}")


def compute_list_root_with_length(
    chunks: List[bytes], 
    limit: int, 
    actual_length: int
) -> bytes:
    """
    Compute the SSZ list root with length mixing.
    
    This is a common pattern in SSZ where the Merkle root of the data
    is mixed with the length of the list.
    
    Args:
        chunks: The data chunks to merkleize
        limit: The fixed capacity limit for merkleization
        actual_length: The actual length of the original data
        
    Returns:
        32-byte root with length mixed in
    """
    data_root = merkle_root_list_fixed(chunks, limit)
    length_bytes = actual_length.to_bytes(32, "little")
    return sha256(data_root + length_bytes).digest() 