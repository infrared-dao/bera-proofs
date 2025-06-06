"""
SSZ (Simple Serialize) Library

A comprehensive implementation of the SSZ serialization standard used in Ethereum 2.0.
This library provides functions for serializing, deserializing, and merkleizing data
according to the SSZ specification.

Key features:
- Basic and container serialization/deserialization
- Merkle tree operations and proof generation
- Support for all SSZ types (uint64, bytes, lists, vectors, containers)
- Efficient chunk-based operations
- Comprehensive validation and error handling

Modules:
- constants: SSZ constants and configuration values
- serialization: Core serialization functions  
- encoding: Specialized encoding functions
- merkle: Merkle tree operations and proofs
- containers: SSZ container definitions and utilities
- utils: Utility functions and helpers
"""

# Core functionality
from .constants import *
from .serialization import *
from .encoding import *

# Merkle operations  
from .merkle import *

# Container definitions
from .containers import *

# Utilities
from .utils import *

__all__ = [
    # Constants
    'BYTES_PER_CHUNK',
    'SLOTS_PER_HISTORICAL_ROOT', 
    'VALIDATOR_REGISTRY_LIMIT',
    'EPOCHS_PER_HISTORICAL_VECTOR',
    'EPOCHS_PER_SLASHINGS_VECTOR',
    
    # Core serialization
    'serialize_uint64',
    'serialize_bytes', 
    'serialize_list',
    'serialize_vector',
    'serialize_container',
    'deserialize_uint64',
    'deserialize_bytes',
    'deserialize_list', 
    'deserialize_vector',
    'deserialize_container',
    
    # Encoding functions
    'encode_balances',
    'encode_randao_mixes',
    'encode_block_roots',
    'encode_slashings',
    
    # Core Merkle functions
    'merkle_root_basic',
    'merkle_root_byte_list',
    'merkle_root_container', 
    'merkle_root_element',
    'merkle_root_list',
    'merkle_root_vector',
    'merkle_root_ssz_list',
    'build_merkle_tree',
    'merkle_list_tree',
    
    # Tree utilities
    'merkleize_chunks',
    'merkle_root_from_chunks',
    'merkle_root_list_fixed',
    'pack_vector_uint64',
    'pack_vector_bytes32',
    'get_tree_depth',
    'validate_tree_structure',
    
    # Proof functions
    'get_fixed_capacity_proof',
    'compute_root_from_proof',
    'verify_merkle_proof',
    'get_proof',
    
    # Container classes
    'SSZContainer',
    'Fork',
    'BeaconBlockHeader',
    'Eth1Data',
    'ExecutionPayloadHeader', 
    'Validator',
    'BeaconState',
    
    # Container utilities
    'json_to_class',
    'load_and_process_state',
    
    # Utility functions
    'bytes_to_hex',
    'hex_to_bytes',
    'validate_hex_string',
    'ensure_bytes',
    'ensure_hex_string'
] 