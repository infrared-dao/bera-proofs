"""
Refactored Main Module

This module provides flexible proof generation functions that can be used
by both CLI and API interfaces. Supports validator, balance, and proposer proofs.
"""

import math
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from .ssz import (
    # Constants
    VALIDATOR_REGISTRY_LIMIT,
    SLOTS_PER_HISTORICAL_ROOT,
    EPOCHS_PER_SLASHINGS_VECTOR,
    
    # Core functions
    merkle_root_basic,
    merkle_root_element,
    merkle_root_ssz_list,
    build_merkle_tree,
    merkle_list_tree,
    
    # Tree and proof functions
    get_fixed_capacity_proof,
    compute_root_from_proof,
    get_proof,
    
    # Encoding functions
    encode_balances,
    encode_randao_mixes,
    encode_block_roots,
    encode_slashings,
    
    # Container classes and utilities
    BeaconState,
    load_and_process_state,
)
import json


@dataclass
class ProofResult:
    """Container for proof generation results."""
    proof: List[bytes]
    root: bytes
    metadata: Dict[str, Any]


def generate_validator_proof(state_file: str, validator_index: int, 
                           prev_state_root: Optional[str] = None, 
                           prev_block_root: Optional[str] = None) -> Dict[str, Any]:
    """Generate a Merkle proof for a validator."""
    state = load_and_process_state(state_file)
    
    # Use existing values from position 2 if not provided
    if prev_state_root is None:
        prev_state_root = state.state_roots[2]
    if prev_block_root is None:
        prev_block_root = state.block_roots[2]
    
    # Validate validator index
    if validator_index >= len(state.validators):
        raise ValueError(f"Validator index {validator_index} out of range (max: {len(state.validators)-1})")
    
    # Prepare state for merkleization (reset state root as in original code)
    state.latest_block_header.state_root = int(0).to_bytes(32)
    
    # Generate validator proof within the validators list
    validator_elements = [merkle_root_element(v, "Validator") for v in state.validators]
    val_proof = get_fixed_capacity_proof(
        validator_elements, 
        validator_index, 
        VALIDATOR_REGISTRY_LIMIT
    )
    
    # Add length mixing for the validators list
    length_chunk = len(validator_elements).to_bytes(32, "little")
    val_proof.append(length_chunk)
    
    # Generate state proof for the validators field (field index 9)
    state_proof = _generate_state_proof(state, field_index=9, prev_state_root=prev_state_root, prev_block_root=prev_block_root)
    
    # Combine proofs
    full_proof = val_proof + state_proof
    
    # Get state root
    state_root = _compute_state_root(state)
    
    metadata = {
        "proof_length": len(full_proof),
        "validator_count": len(state.validators),
        "validator_pubkey": state.validators[validator_index].pubkey.hex(),
        "slot": state.slot,
        "field_index": 9  # validators field
    }
    
    return ProofResult(full_proof, state_root, metadata)


def generate_balance_proof(state_file: str, validator_index: int,
                         prev_state_root: Optional[str] = None,
                         prev_block_root: Optional[str] = None) -> Dict[str, Any]:
    """Generate a Merkle proof for a validator balance."""
    state = load_and_process_state(state_file)
    
    # Use existing values from position 2 if not provided
    if prev_state_root is None:
        prev_state_root = state.state_roots[2]
    if prev_block_root is None:
        prev_block_root = state.block_roots[2]
    
    # Validate validator index
    if validator_index >= len(state.balances):
        raise ValueError(f"Balance index {validator_index} out of range (max: {len(state.balances)-1})")
    
    # Prepare state for merkleization
    state.latest_block_header.state_root = int(0).to_bytes(32)
    
    # Generate balance proof within the balances list
    balance_elements = [merkle_root_basic(balance, "uint64") for balance in state.balances]
    bal_proof = get_fixed_capacity_proof(
        balance_elements,
        validator_index,
        VALIDATOR_REGISTRY_LIMIT  # Same capacity as validators
    )
    
    # Add length mixing for the balances list
    length_chunk = len(balance_elements).to_bytes(32, "little")
    bal_proof.append(length_chunk)
    
    # Generate state proof for the balances field (field index 10)
    state_proof = _generate_state_proof(state, field_index=10, prev_state_root=prev_state_root, prev_block_root=prev_block_root)
    
    # Combine proofs
    full_proof = bal_proof + state_proof
    
    # Get state root
    state_root = _compute_state_root(state)
    
    metadata = {
        "proof_length": len(full_proof),
        "balance": str(state.balances[validator_index]),
        "validator_count": len(state.validators),
        "slot": state.slot,
        "field_index": 10  # balances field
    }
    
    return ProofResult(full_proof, state_root, metadata)


def generate_proposer_proof(state_file: str, validator_index: int,
                          prev_state_root: Optional[str] = None,
                          prev_block_root: Optional[str] = None) -> Dict[str, Any]:
    """Generate a Merkle proof for a proposer."""
    state = load_and_process_state(state_file)
    
    # Use existing values from position 2 if not provided
    if prev_state_root is None:
        prev_state_root = state.state_roots[2]
    if prev_block_root is None:
        prev_block_root = state.block_roots[2]
    
    # Validate validator index
    if validator_index >= len(state.validators):
        raise ValueError(f"Validator index {validator_index} out of range (max: {len(state.validators)-1})")
    
    # Prepare state for merkleization
    state.latest_block_header.state_root = int(0).to_bytes(32)
    
    # Generate pubkey proof within the validator (field index 0)
    validator = state.validators[validator_index]
    validator_field_roots = [
        merkle_root_basic(validator.pubkey, "bytes48"),  # field 0
        merkle_root_basic(validator.withdrawal_credentials, "bytes32"),  # field 1
        merkle_root_basic(validator.effective_balance, "uint64"),  # field 2
        merkle_root_basic(validator.slashed, "Boolean"),  # field 3
        merkle_root_basic(validator.activation_eligibility_epoch, "uint64"),  # field 4
        merkle_root_basic(validator.activation_epoch, "uint64"),  # field 5
        merkle_root_basic(validator.exit_epoch, "uint64"),  # field 6
        merkle_root_basic(validator.withdrawable_epoch, "uint64"),  # field 7
    ]
    
    # Pad validator fields to next power of 2 and build tree
    n = len(validator_field_roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded_fields = validator_field_roots + [b"\0" * 32] * (num_leaves - n)
    validator_tree = build_merkle_tree(padded_fields)
    pubkey_proof = get_proof(validator_tree, 0)  # pubkey at index 0
    
    # Generate validator proof within the validators list
    validator_elements = [merkle_root_element(v, "Validator") for v in state.validators]
    val_proof = get_fixed_capacity_proof(
        validator_elements,
        validator_index,
        VALIDATOR_REGISTRY_LIMIT
    )
    
    # Add length mixing
    length_chunk = len(validator_elements).to_bytes(32, "little")
    val_proof.append(length_chunk)
    
    # Generate state proof for validators field (field index 9)
    state_proof = _generate_state_proof(state, field_index=9, prev_state_root=prev_state_root, prev_block_root=prev_block_root)
    
    # Generate header proof for state_root field (field index 3 in BeaconBlockHeader)
    header_field_roots = [
        merkle_root_basic(state.latest_block_header.slot, "uint64"),  # field 0
        merkle_root_basic(state.latest_block_header.proposer_index, "uint64"),  # field 1
        merkle_root_basic(state.latest_block_header.parent_root, "bytes32"),  # field 2
        merkle_root_basic(state.latest_block_header.state_root, "bytes32"),  # field 3
        merkle_root_basic(state.latest_block_header.body_root, "bytes32"),  # field 4
    ]
    
    # Pad header fields and build tree
    n = len(header_field_roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded_header_fields = header_field_roots + [b"\0" * 32] * (num_leaves - n)
    header_tree = build_merkle_tree(padded_header_fields)
    header_proof = get_proof(header_tree, 3)  # state_root at index 3
    
    # Combine all proofs
    full_proof = pubkey_proof + val_proof + state_proof + header_proof
    
    # Return latest_block_header root for proposer proofs
    header_root = header_tree[-1][0]
    
    metadata = {
        "proof_length": len(full_proof),
        "validator_count": len(state.validators), 
        "pubkey": validator.pubkey.hex(),
        "slot": state.slot,
        "pubkey_proof_length": len(pubkey_proof),
        "validator_proof_length": len(val_proof),
        "state_proof_length": len(state_proof),
        "header_proof_length": len(header_proof)
    }
    
    return ProofResult(full_proof, header_root, metadata)


def _generate_state_proof(
    state: BeaconState, 
    field_index: int, 
    prev_state_root: bytes, 
    prev_block_root: bytes
) -> List[bytes]:
    """
    Generate proof for a field within BeaconState.
    
    Args:
        state: BeaconState instance
        field_index: Index of the field to prove (9 for validators, 10 for balances)
        prev_state_root: Previous cycle state root
        prev_block_root: Previous cycle block root
        
    Returns:
        List of proof steps for the state field
    """
    # Build state field roots
    state_fields = [
        # Field (0): genesis_validators_root
        merkle_root_basic(state.genesis_validators_root, "bytes32"),
        # Field (1): slot
        merkle_root_basic(state.slot, "uint64"),
        # Field (2): fork
        state.fork.merkle_root(),
        # Field (3): latest_block_header
        state.latest_block_header.merkle_root(),
        # Field (4): block_roots
        encode_block_roots(state.block_roots),
        # Field (5): state_roots
        encode_block_roots(state.state_roots),
        # Field (6): eth1_data
        state.eth1_data.merkle_root(),
        # Field (7): eth1_deposit_index
        merkle_root_basic(state.eth1_deposit_index, "uint64"),
        # Field (8): latest_execution_payload_header
        state.latest_execution_payload_header.merkle_root(),
        # Field (9): validators
        _encode_validators_field(state.validators),
        # Field (10): balances
        encode_balances(state.balances),
        # Field (11): randao_mixes
        encode_randao_mixes(state.randao_mixes),
        # Field (12): next_withdrawal_index
        merkle_root_basic(state.next_withdrawal_index, "uint64"),
        # Field (13): next_withdrawal_validator_index
        merkle_root_basic(state.next_withdrawal_validator_index, "uint64"),
        # Field (14): slashings
        encode_slashings(state.slashings),
        # Field (15): total_slashing
        merkle_root_basic(state.total_slashing, "uint64"),
    ]
    
    # Pad to next power of two
    n = len(state_fields)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = state_fields + [b"\0" * 32] * (num_leaves - n)

    # Build state tree and get proof
    state_tree = build_merkle_tree(padded)
    return get_proof(state_tree, field_index)


def _encode_validators_field(validators) -> bytes:
    """Encode validators field for merkleization."""
    validator_elements = [merkle_root_element(v, "Validator") for v in validators]
    validators_root = merkle_root_ssz_list(validators, "Validator", VALIDATOR_REGISTRY_LIMIT)
    return validators_root


def _compute_state_root(state: BeaconState) -> bytes:
    """Compute the BeaconState merkle root."""
    return state.merkle_root()


# Legacy function for backwards compatibility
def generate_merkle_witness(
    state_file: str, validator_index: int
) -> tuple[List[bytes], bytes]:
    """
    Legacy function for backwards compatibility.
    
    Args:
        state_file: Path to JSON state file
        validator_index: Index of validator to prove
        
    Returns:
        Tuple of (proof_list, state_root)
    """
    state = load_and_process_state(state_file)
    
    # Use the existing values from the JSON at position 2 instead of hardcoded values
    prev_state_root = state.state_roots[2]  # Use existing value from JSON
    prev_block_root = state.block_roots[2]   # Use existing value from JSON
    
    print(f"Using existing state_roots[2]: {prev_state_root.hex()}")
    print(f"Using existing block_roots[2]: {prev_block_root.hex()}")
    
    # Don't override them since we're using the existing values
    # state.state_roots[2] = prev_state_root  # Not needed
    # state.block_roots[2] = prev_block_root  # Not needed
    
    result = generate_validator_proof(state_file, validator_index, prev_state_root, prev_block_root)
    return result.proof, result.root


# Example usage
if __name__ == "__main__":
    proof, state_root = generate_merkle_witness("test/data/state.json", 39)
    print("Merkle Witness (hex):")
    for i, h in enumerate(proof):
        print(f"Step {i}: {h.hex()}")
    print(f"State Root: {state_root.hex()}")
