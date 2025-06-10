"""
Hex String and Naming Convention Utilities

This module provides utilities for handling hex strings and converting between
different naming conventions used in JSON data and Python code.
"""

import re
from typing import Optional


def normalize_hex(hex_str: str, expected_bytes: Optional[int] = None) -> str:
    """
    Normalize a hex string to ensure proper formatting.
    
    Args:
        hex_str: The hex string to normalize (should start with '0x')
        expected_bytes: Optional expected byte length for validation
        
    Returns:
        Normalized hex string with proper padding
        
    Raises:
        ValueError: If the hex string contains invalid characters
        
    Examples:
        >>> normalize_hex("0x123")
        "0x0123"
        >>> normalize_hex("0x1234")
        "0x1234"
    """
    if not isinstance(hex_str, str) or not hex_str.startswith("0x"):
        return hex_str
        
    hex_part = hex_str[2:]
    
    # Validate hex characters
    if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
        raise ValueError(f"Invalid hex string: {hex_str}")
    
    # Pad to even length
    if len(hex_part) % 2 == 1:
        hex_part = "0" + hex_part
    
    normalized = "0x" + hex_part
    
    # Validate expected byte length if provided
    if expected_bytes is not None:
        actual_bytes = len(hex_part) // 2
        if actual_bytes != expected_bytes:
            raise ValueError(f"Expected {expected_bytes} bytes, got {actual_bytes} bytes")
    
    return normalized


def camel_to_snake(name: str) -> str:
    """
    Convert camelCase naming to snake_case naming.
    
    This is used to convert JSON field names (which use camelCase)
    to Python attribute names (which use snake_case).
    
    Args:
        name: The camelCase string to convert
        
    Returns:
        The string converted to snake_case
        
    Examples:
        >>> camel_to_snake("camelCase")
        "camel_case"
        >>> camel_to_snake("thisIsCamelCase")
        "this_is_camel_case"
        >>> camel_to_snake("snake_case")
        "snake_case"
    """
    # Insert underscore before capital letters that follow lowercase letters
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    
    # Insert underscore before capital letters that follow lowercase letters or numbers
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def hex_to_bytes(hex_str: str) -> bytes:
    """
    Convert a hex string to bytes.
    
    Args:
        hex_str: Hex string (with or without '0x' prefix)
        
    Returns:
        Bytes representation of the hex string
        
    Examples:
        >>> hex_to_bytes("0x1234")
        b'\x12\x34'
        >>> hex_to_bytes("1234")
        b'\x12\x34'
    """
    if hex_str.startswith("0x"):
        hex_str = hex_str[2:]
    
    # Pad to even length
    if len(hex_str) % 2 == 1:
        hex_str = "0" + hex_str
        
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes, prefix: bool = True) -> str:
    """
    Convert bytes to a hex string.
    
    Args:
        data: Bytes to convert
        prefix: Whether to include '0x' prefix
        
    Returns:
        Hex string representation
        
    Examples:
        >>> bytes_to_hex(b'\x12\x34')
        "0x1234"
        >>> bytes_to_hex(b'\x12\x34', prefix=False)
        "1234"
    """
    hex_str = data.hex()
    return f"0x{hex_str}" if prefix else hex_str


def validate_hex_length(hex_str: str, expected_bytes: int) -> bool:
    """
    Validate that a hex string represents the expected number of bytes.
    
    Args:
        hex_str: The hex string to validate
        expected_bytes: Expected number of bytes
        
    Returns:
        True if the hex string has the correct length
    """
    if not hex_str.startswith("0x"):
        return False
        
    hex_part = hex_str[2:]
    actual_bytes = len(hex_part) // 2
    
    return actual_bytes == expected_bytes 