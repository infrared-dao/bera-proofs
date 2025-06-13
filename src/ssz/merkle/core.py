"""
Core Merkle Tree Functions for SSZ

This module implements the core merkle root calculation functions for SSZ types.
Merkle trees are fundamental to SSZ as they provide efficient cryptographic
commitments to data structures and enable proof generation.

SSZ Merkleization Rules:
- Basic types are padded to 32 bytes (or hashed if >32 bytes)
- Lists are merkleized with length mixing
- Vectors are merkleized with zero padding to fixed size
- Containers have their field roots merkleized

References:
- SSZ Specification: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
"""

import math
from hashlib import sha256
from typing import Any, List, TYPE_CHECKING

# Import our own modules
from ..constants import ZERO_HASHES, MAX_VALIDATORS, VALIDATOR_REGISTRY_LIMIT
from ..serialization import (
    serialize_uint64,
    serialize_uint256,
    serialize_bool,
    serialize_bytes,
)

# Avoid circular imports for type checking
if TYPE_CHECKING:
    from ..containers.base import SSZContainer


def merkle_root_basic(value: Any, type_str: str) -> bytes:
    """
    Calculate the merkle root for basic SSZ types.

    Basic types are atomic values that are either padded to 32 bytes
    or hashed if they exceed 32 bytes.

    Args:
        value: The value to merkleize
        type_str: SSZ type string (e.g., 'uint64', 'bytes32', 'Boolean')

    Returns:
        32-byte merkle root (padded value or hash)

    Examples:
        >>> merkle_root_basic(123, 'uint64')  # Returns padded uint64
        >>> merkle_root_basic(b'\\x01' * 32, 'bytes32')  # Returns as-is
        >>> merkle_root_basic(b'\\x01' * 48, 'bytes48')  # Returns hash
    """
    # Handle hex string conversion for bytes types
    if type_str.startswith("bytes") and isinstance(value, str):
        if value.startswith("0x"):
            value = bytes.fromhex(value[2:])
        else:
            value = bytes.fromhex(value)

    if type_str == "bytes32":
        return serialize_bytes(value, 32)  # Already 32 bytes, return directly
    elif type_str == "uint64":
        serialized = serialize_uint64(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "uint256":
        serialized = serialize_uint256(value)
        return serialized  # Already 32 bytes, no hash
    elif type_str == "Boolean":
        serialized = serialize_bool(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes48":
        # Split into chunks and hash (BLS public key case)
        chunk1 = value[0:32]
        chunk2 = value[32:48] + b"\0" * 16
        return sha256(chunk1 + chunk2).digest()  # >32 bytes, hash required
    elif type_str == "bytes20":
        # Ethereum address case
        serialized = serialize_bytes(value, 20)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes256":
        # Logs bloom case - split into chunks and merkleize
        chunks = [value[i : i + 32] for i in range(0, 256, 32)]
        return merkle_root_list(chunks)  # Fixed-size, Merkleize chunks
    elif type_str == "bytes4":
        # Version bytes case
        serialized = serialize_bytes(value, 4)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes":
        # Variable-length bytes (extra_data case)
        # This is actually ByteList[32] but 'bytes' is used as shortcut
        max_length = 32  # MAX_EXTRA_DATA_BYTES
        if len(value) > max_length:
            raise ValueError(
                f"ExtraData length {len(value)} exceeds maximum {max_length}"
            )

        # Form single chunk for data
        if len(value) == 0:
            chunks_root = b"\0" * 32
        else:
            chunk = value + b"\0" * (32 - len(value))  # Pad to 32 bytes
            chunks_root = chunk  # Single chunk, no Merkle tree needed

        # Mix in length (SSZ list requirement)
        length_packed = len(value).to_bytes(32, "little")
        return sha256(chunks_root + length_packed).digest()
    else:
        raise ValueError(f"Unsupported basic type: {type_str}")


def merkle_root_byte_list(value: bytes, max_length: int) -> bytes:
    """
    Calculate merkle root for a variable-length byte list.

    ByteList types are chunked into 32-byte pieces, merkleized,
    and then mixed with their length.

    Args:
        value: The byte array to merkleize
        max_length: Maximum allowed length for validation

    Returns:
        32-byte merkle root
    """
    if len(value) > max_length:
        raise ValueError(f"Byte list length {len(value)} exceeds maximum {max_length}")

    # Split into 32-byte chunks
    chunks = [value[i : i + 32] for i in range(0, len(value), 32)]

    # Pad last chunk if needed
    if chunks and len(chunks[-1]) < 32:
        chunks[-1] += b"\0" * (32 - len(chunks[-1]))

    # Get merkle root of chunks
    chunks_root = merkle_root_list(chunks)

    # Mix in length
    length_packed = len(value).to_bytes(32, "little")
    return sha256(chunks_root + length_packed).digest()


def merkle_root_container(obj: Any, fields: List[tuple]) -> bytes:
    """
    Calculate merkle root for an SSZ container.

    Containers are merkleized by calculating the merkle root of each field
    and then merkleizing the list of field roots.

    Args:
        obj: The container object
        fields: List of (field_name, field_type) tuples describing the container

    Returns:
        32-byte merkle root of the container

    Examples:
        >>> fields = [('slot', 'uint64'), ('root', 'bytes32')]
        >>> merkle_root_container(beacon_block_header, fields)
    """
    field_roots = []

    for field_name, field_type in fields:
        field_value = getattr(obj, field_name)

        # Handle container types (they have their own merkle_root method)
        if field_type in {
            "Fork",
            "BeaconBlockHeader",
            "Eth1Data",
            "ExecutionPayloadHeader",
            "Validator",
        }:
            root = field_value.merkle_root()
        # Handle SSZ List types
        elif field_type.startswith("List["):
            elem_type = field_type.split("[")[1].split(",")[0]
            limit = int(field_type.split(",")[1].strip("]"))
            root = merkle_root_ssz_list(field_value, elem_type, limit)
        # Handle SSZ Vector types
        elif field_type.startswith("Vector["):
            elem_type = field_type.split("[")[1].split(",")[0]
            limit = int(field_type.split(",")[1].strip("]"))
            root = merkle_root_vector(field_value, elem_type, limit)
        # Handle basic types
        else:
            root = merkle_root_basic(field_value, field_type)

        field_roots.append(root)

    return merkle_root_list(field_roots)


def merkle_root_element(value: Any, elem_type: str) -> bytes:
    """
    Calculate merkle root for a single element (used in lists/vectors).

    Args:
        value: The element value
        elem_type: SSZ type of the element

    Returns:
        32-byte merkle root of the element
    """
    # Handle container element types
    if elem_type in {
        "Fork",
        "BeaconBlockHeader",
        "Eth1Data",
        "ExecutionPayloadHeader",
        "Validator",
    }:
        return value.merkle_root()
    else:
        return merkle_root_basic(value, elem_type)


def merkle_root_list(roots: List[bytes]) -> bytes:
    """
    Calculate merkle root of a list of 32-byte roots.

    This is the fundamental building block for merkleization.
    The list is padded to the next power of two and then
    a binary merkle tree is constructed.

    Args:
        roots: List of 32-byte hash values

    Returns:
        32-byte merkle root

    Examples:
        >>> merkle_root_list([b'\\x01' * 32, b'\\x02' * 32])
        >>> merkle_root_list([])  # Returns zero hash
    """
    if not roots:
        return b"\0" * 32

    # Pad to next power of two
    n = len(roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)

    return build_merkle_tree(padded)[-1][0]


def merkle_root_vector(values: List[Any], elem_type: str, limit: int) -> bytes:
    """
    Calculate merkle root for an SSZ Vector.

    Vectors have a fixed capacity and are padded with zero elements
    to reach that capacity before merkleization.

    Args:
        values: List of values in the vector
        elem_type: SSZ type of vector elements
        limit: Fixed capacity of the vector

    Returns:
        32-byte merkle root

    Examples:
        >>> merkle_root_vector([b'\\x01'*32, b'\\x02'*32], 'bytes32', 8)
    """
    # Calculate roots for actual elements
    elements_roots = [merkle_root_element(v, elem_type) for v in values]

    # Pad to the fixed limit with zero hashes
    elements_roots += [b"\0" * 32] * (limit - len(elements_roots))

    return merkle_root_list(elements_roots)


def merkle_root_ssz_list(values: List[Any], elem_type: str, limit: int) -> bytes:
    """
    Calculate merkle root for an SSZ List.

    Lists are variable-length but have a maximum capacity.
    The merkle root is calculated from the element roots
    and then mixed with the actual length.

    Args:
        values: List of values
        elem_type: SSZ type of list elements
        limit: Maximum capacity of the list

    Returns:
        32-byte merkle root

    Examples:
        >>> merkle_root_ssz_list([validator1, validator2], 'Validator', 1000)
    """
    if not values:
        chunks_root = b"\0" * 32
    else:
        elements_roots = [merkle_root_element(v, elem_type) for v in values]
        chunks_root = merkle_root_list(elements_roots)

    # Mix in the actual length
    length_packed = len(values).to_bytes(32, "little")
    return sha256(chunks_root + length_packed).digest()


def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    """
    Build a complete binary merkle tree from leaf nodes.

    Returns the full tree structure, with leaves at index 0
    and root at the last index.

    Args:
        leaves: List of 32-byte leaf hashes (should be power-of-two length)

    Returns:
        List of tree levels, from leaves to root

    Examples:
        >>> tree = build_merkle_tree([b'\\x01'*32, b'\\x02'*32])
        >>> root = tree[-1][0]  # Root is at top level
    """
    if not leaves:
        return [[b"\0" * 32]]

    tree = [leaves]
    current = leaves

    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else b"\0" * 32
            parent = sha256(left + right).digest()
            next_level.append(parent)
        tree.append(next_level)
        current = next_level

    return tree


def merkle_list_tree(roots: List[bytes]) -> bytes:
    """
    Build merkle tree and return the full tree structure.

    Similar to merkle_root_list but returns the tree instead of just root.

    Args:
        roots: List of 32-byte root hashes

    Returns:
        Complete merkle tree structure
    """
    if not roots:
        return b"\0" * 32

    # Pad to next power of two
    n = len(roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)

    return build_merkle_tree(padded)
