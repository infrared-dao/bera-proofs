"""
SSZ Merkle Tree Operations

This package provides comprehensive Merkle tree functionality for SSZ serialization,
including core merkleization functions, tree building utilities, and proof generation/verification.

The module is organized into three main components:
- core: Core SSZ merkleization functions following the official specification
- tree: Tree building and manipulation utilities
- proof: Proof generation and verification functions
"""

# Core merkleization functions
from .core import (
    merkle_root_basic,
    merkle_root_byte_list,
    merkle_root_container,
    merkle_root_element,
    merkle_root_list,
    merkle_root_vector,
    merkle_root_ssz_list,
    build_merkle_tree,
    merkle_list_tree,
)

# Tree building utilities
from .tree import (
    merkleize_chunks,
    merkle_root_from_chunks,
    merkle_root_list_fixed,
    pack_vector_uint64,
    pack_vector_bytes32,
    get_tree_depth,
    validate_tree_structure,
)

# Proof generation and verification
from .proof import (
    get_fixed_capacity_proof,
    compute_root_from_proof,
    get_proof,
    verify_merkle_proof,
    validate_proof_length,
    get_proof_indices,
    batch_verify_proofs,
)

__all__ = [
    # Core functions
    "merkle_root_basic",
    "merkle_root_byte_list",
    "merkle_root_container",
    "merkle_root_element",
    "merkle_root_list",
    "merkle_root_vector",
    "merkle_root_ssz_list",
    "build_merkle_tree",
    "merkle_list_tree",
    # Tree utilities
    "merkleize_chunks",
    "merkle_root_from_chunks",
    "merkle_root_list_fixed",
    "pack_vector_uint64",
    "pack_vector_bytes32",
    "get_tree_depth",
    "validate_tree_structure",
    # Proof functions
    "get_fixed_capacity_proof",
    "compute_root_from_proof",
    "get_proof",
    "verify_merkle_proof",
    "validate_proof_length",
    "get_proof_indices",
    "batch_verify_proofs",
] 