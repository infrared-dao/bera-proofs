"""
SSZ Basic Serialization Functions

This module implements the core SSZ (Simple Serialize) serialization functions
for basic data types as defined in the Ethereum consensus specification.

SSZ is a serialization format used throughout the Ethereum beacon chain for
encoding data structures in a deterministic, merkle-tree-friendly manner.

References:
- SSZ Specification: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
"""

from typing import Union


def serialize_uint64(value: int) -> bytes:
    """
    Serialize a 64-bit unsigned integer to SSZ format.
    
    SSZ Rule: Integers are serialized as little-endian byte arrays
    of their respective byte length.
    
    Args:
        value: Integer value (0 <= value < 2^64)
        
    Returns:
        8-byte little-endian representation
        
    Raises:
        OverflowError: If value is too large for uint64
        
    Examples:
        >>> serialize_uint64(0)
        b'\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        >>> serialize_uint64(1)
        b'\\x01\\x00\\x00\\x00\\x00\\x00\\x00\\x00'
        >>> serialize_uint64(1234567890)
        b'\\xd2\\x02\\x96\\x49\\x00\\x00\\x00\\x00'
    """
    if value < 0:
        raise ValueError("uint64 values must be non-negative")
    if value >= 2**64:
        raise OverflowError("Value too large for uint64")
    
    return value.to_bytes(8, "little")


def serialize_uint256(value: int) -> bytes:
    """
    Serialize a 256-bit unsigned integer to SSZ format.
    
    SSZ Rule: Large integers are serialized as little-endian byte arrays
    of their respective byte length.
    
    Args:
        value: Integer value (0 <= value < 2^256)
        
    Returns:
        32-byte little-endian representation
        
    Raises:
        OverflowError: If value is too large for uint256
        
    Examples:
        >>> serialize_uint256(0)
        b'\\x00' * 32
        >>> serialize_uint256(1)
        b'\\x01' + b'\\x00' * 31
    """
    if value < 0:
        raise ValueError("uint256 values must be non-negative")
    if value >= 2**256:
        raise OverflowError("Value too large for uint256")
    
    return value.to_bytes(32, "little")


def serialize_uint32(value: int) -> bytes:
    """
    Serialize a 32-bit unsigned integer to SSZ format.
    
    Args:
        value: Integer value (0 <= value < 2^32)
        
    Returns:
        4-byte little-endian representation
    """
    if value < 0:
        raise ValueError("uint32 values must be non-negative")
    if value >= 2**32:
        raise OverflowError("Value too large for uint32")
    
    return value.to_bytes(4, "little")


def serialize_uint16(value: int) -> bytes:
    """
    Serialize a 16-bit unsigned integer to SSZ format.
    
    Args:
        value: Integer value (0 <= value < 2^16)
        
    Returns:
        2-byte little-endian representation
    """
    if value < 0:
        raise ValueError("uint16 values must be non-negative")
    if value >= 2**16:
        raise OverflowError("Value too large for uint16")
    
    return value.to_bytes(2, "little")


def serialize_uint8(value: int) -> bytes:
    """
    Serialize an 8-bit unsigned integer to SSZ format.
    
    Args:
        value: Integer value (0 <= value < 2^8)
        
    Returns:
        1-byte representation
    """
    if value < 0:
        raise ValueError("uint8 values must be non-negative")
    if value >= 2**8:
        raise OverflowError("Value too large for uint8")
    
    return value.to_bytes(1, "little")


def serialize_bool(value: bool) -> bytes:
    """
    Serialize a boolean value to SSZ format.
    
    SSZ Rule: Booleans are serialized as a single byte,
    0x00 for False, 0x01 for True.
    
    Args:
        value: Boolean value to serialize
        
    Returns:
        Single byte (0x00 or 0x01)
        
    Examples:
        >>> serialize_bool(True)
        b'\\x01'
        >>> serialize_bool(False)
        b'\\x00'
    """
    return b"\x01" if value else b"\x00"


def serialize_bytes(value: bytes, length: int) -> bytes:
    """
    Serialize a fixed-length byte array to SSZ format.
    
    SSZ Rule: Fixed-length byte arrays are serialized as-is,
    with no length prefix or padding.
    
    Args:
        value: Byte array to serialize
        length: Expected length in bytes
        
    Returns:
        The input bytes unchanged
        
    Raises:
        AssertionError: If the byte array length doesn't match expected length
        
    Examples:
        >>> serialize_bytes(b'\\x01\\x02\\x03\\x04', 4)
        b'\\x01\\x02\\x03\\x04'
    """
    if len(value) != length:
        raise AssertionError(f"Expected {length} bytes, got {len(value)}")
    
    return value


def serialize_bytes_dynamic(value: bytes) -> bytes:
    """
    Serialize a variable-length byte array to SSZ format.
    
    SSZ Rule: Variable-length arrays are serialized as-is when used
    within containers (the length is tracked separately).
    
    Args:
        value: Byte array to serialize
        
    Returns:
        The input bytes unchanged
    """
    return value


def deserialize_uint64(data: bytes) -> int:
    """
    Deserialize a uint64 from SSZ format.
    
    Args:
        data: 8-byte little-endian byte array
        
    Returns:
        Integer value
        
    Raises:
        ValueError: If data is not exactly 8 bytes
    """
    if len(data) != 8:
        raise ValueError(f"Expected 8 bytes for uint64, got {len(data)}")
    
    return int.from_bytes(data, "little")


def deserialize_uint256(data: bytes) -> int:
    """
    Deserialize a uint256 from SSZ format.
    
    Args:
        data: 32-byte little-endian byte array
        
    Returns:
        Integer value
        
    Raises:
        ValueError: If data is not exactly 32 bytes
    """
    if len(data) != 32:
        raise ValueError(f"Expected 32 bytes for uint256, got {len(data)}")
    
    return int.from_bytes(data, "little")


def deserialize_bool(data: bytes) -> bool:
    """
    Deserialize a boolean from SSZ format.
    
    Args:
        data: Single byte (0x00 or 0x01)
        
    Returns:
        Boolean value
        
    Raises:
        ValueError: If data is not exactly 1 byte or not 0x00/0x01
    """
    if len(data) != 1:
        raise ValueError(f"Expected 1 byte for boolean, got {len(data)}")
    
    if data[0] == 0:
        return False
    elif data[0] == 1:
        return True
    else:
        raise ValueError(f"Invalid boolean byte: {data[0]:02x}")


def get_serialized_size(type_str: str) -> int:
    """
    Get the serialized size in bytes for a given SSZ type.
    
    Args:
        type_str: SSZ type string (e.g., 'uint64', 'bytes32', 'Boolean')
        
    Returns:
        Size in bytes, or -1 for variable-length types
        
    Examples:
        >>> get_serialized_size('uint64')
        8
        >>> get_serialized_size('bytes32')
        32
        >>> get_serialized_size('bytes')
        -1
    """
    type_sizes = {
        'uint8': 1,
        'uint16': 2,
        'uint32': 4,
        'uint64': 8,
        'uint256': 32,
        'Boolean': 1,
        'bytes1': 1,
        'bytes4': 4,
        'bytes20': 20,
        'bytes32': 32,
        'bytes48': 48,
        'bytes256': 256,
    }
    
    if type_str in type_sizes:
        return type_sizes[type_str]
    
    # Handle bytesN patterns
    if type_str.startswith('bytes') and type_str[5:].isdigit():
        return int(type_str[5:])
    
    # Variable-length types
    if type_str in ['bytes', 'string']:
        return -1
    
    # Complex types are variable-length
    return -1 