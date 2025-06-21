"""
SSZ Utility Functions

This package provides utility functions for hex string handling, naming conventions,
and other common operations used throughout the SSZ library.
"""

from .hex_helpers import (
    normalize_hex,
    camel_to_snake,
    hex_to_bytes,
    bytes_to_hex,
    validate_hex_length,
)

__all__ = [
    'normalize_hex',
    'camel_to_snake', 
    'hex_to_bytes',
    'bytes_to_hex',
    'validate_hex_length',
] 