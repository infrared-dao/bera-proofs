"""
SSZ Containers Package

This package provides SSZ container definitions and utilities for Ethereum Beacon Chain
data structures. It includes:

- Base container classes with common SSZ functionality
- Beacon chain specific data structures (Fork, BeaconState, etc.)  
- Utilities for JSON conversion and data loading

The containers follow the SSZ specification and provide methods for:
- Merkle root calculation
- Field validation and access
- JSON serialization/deserialization
"""

from .base import SSZContainer
from .beacon import (
    Fork,
    BeaconBlockHeader, 
    Eth1Data,
    ExecutionPayloadHeader,
    Validator,
    BeaconState
)
from .utils import json_to_class, load_and_process_state

__all__ = [
    # Base classes
    'SSZContainer',
    
    # Beacon chain containers
    'Fork',
    'BeaconBlockHeader',
    'Eth1Data', 
    'ExecutionPayloadHeader',
    'Validator',
    'BeaconState',
    
    # Utilities
    'json_to_class',
    'load_and_process_state'
] 