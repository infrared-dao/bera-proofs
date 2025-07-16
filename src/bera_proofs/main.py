"""
Bera Proofs - Main proof generation module

This module contains the core functions for generating Merkle proofs from BeaconState data
by both CLI and API interfaces. Supports validator and balance proofs.
"""

import json
import logging
import math
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass

from .ssz import (
    BeaconState, 
    Validator,
    ValidatorBalance,
    merkle_root_basic,
    get_proof,
    get_fixed_capacity_proof,
    compute_root_from_proof,
    build_merkle_tree,
    merkle_list_tree,
    VALIDATOR_REGISTRY_LIMIT
)
from .ssz.containers.utils import load_and_process_state as _load_state

def load_and_process_state(state_file: str) -> 'BeaconState':
    """Load and process beacon state from JSON file."""
    return _load_state(state_file)

from bera_proofs.ssz.merkle import (
    get_fixed_capacity_proof,
    merkle_list_tree
)

logger = logging.getLogger(__name__)

@dataclass
class ProofResult:
    """Container for proof generation results."""
    proof: List[bytes]
    root: bytes
    metadata: Dict[str, Any]

@dataclass
class ProofCombinedResult:
    """Container for proof generation results."""
    balance_proof: List[bytes]
    validator_proof: List[bytes]
    state_root: bytes
    balance_leaf: bytes
    balances_root: bytes
    validator_index: int
    header_root: bytes
    header: Dict[str, Any]
    validator_data: Dict[str, Any]
    metadata: Dict[str, Any]


def generate_validator_proof(state_file: str, validator_index: int, 
                           prev_state_root: Optional[str] = None, 
                           prev_block_root: Optional[str] = None) -> ProofResult:
    """Generate a Merkle proof for a validator."""
    state = load_and_process_state(state_file)
    
    # Convert string parameters to bytes if provided
    prev_state_root_bytes = None
    prev_block_root_bytes = None
    
    if prev_state_root is not None:
        prev_state_root_bytes = bytes.fromhex(prev_state_root.replace('0x', ''))
    if prev_block_root is not None:
        prev_block_root_bytes = bytes.fromhex(prev_block_root.replace('0x', ''))
    
    # Use existing values from calculated position if not provided (fallback for compatibility)
    if prev_state_root_bytes is None:
        prev_state_root_bytes = state.state_roots[state.slot % 8]
    if prev_block_root_bytes is None:
        prev_block_root_bytes = state.block_roots[state.slot % 8]
    
    # Validate validator index
    if validator_index >= len(state.validators):
        raise ValueError(f"Validator index {validator_index} out of range (max: {len(state.validators)-1})")
    
    # Prepare state for merkleization
    state.latest_block_header.state_root = int(0).to_bytes(32)
    
    # Apply historical data modifications (8 slots ago as per spec)
    state.state_roots[state.slot % 8] = prev_state_root_bytes
    state.block_roots[state.slot % 8] = prev_block_root_bytes
    
    # Generate validator proof within the validators list
    validator_elements = [v.merkle_root() for v in state.validators]
    val_proof = get_fixed_capacity_proof(
        validator_elements,
        validator_index,
        VALIDATOR_REGISTRY_LIMIT
    )
    
    # Add length mixing
    length_chunk = len(validator_elements).to_bytes(32, "little")
    val_proof.append(length_chunk)
    
    # Recompute validators root using the proof (matching working implementation)
    leaf = validator_elements[validator_index]
    validators_root = compute_root_from_proof(
        leaf, validator_index, val_proof
    )
    
    # Generate state proof for validators field (field index 9)
    state_proof = _generate_state_proof(state, field_index=9, prev_state_root=prev_state_root_bytes, prev_block_root=prev_block_root_bytes)
    
    # Combine all proofs
    full_proof = val_proof + state_proof
    
    # Compute final state root (matching working approach)
    state_root = _compute_state_root(state, validators_root)
    
    # Get the validator object
    validator = state.validators[validator_index]
    
    # Get the validator leaf (merkle root)
    validator_leaf = validator.merkle_root()
    
    # Create ValidatorBalance container
    validator_balance = ValidatorBalance(
        validator=validator,
        balance=state.balances[validator_index]
    )

    state.header.state_root = state_root
    header_root = state.header.merkle_root()
    
    metadata = {
        "proof_length": len(full_proof),
        "validator_index": validator_index,
        "validator_pubkey": validator.pubkey.hex(),
        "validator_leaf": validator_leaf.hex(),
        "validator_balance_root": validator_balance.merkle_root().hex(),
        "validator": {
            "pubkey": validator.pubkey.hex(),
            "withdrawal_credentials": validator.withdrawal_credentials.hex(),
            "effective_balance": validator.effective_balance,
            "slashed": validator.slashed,
            "activation_eligibility_epoch": validator.activation_eligibility_epoch,
            "activation_epoch": validator.activation_epoch,
            "exit_epoch": validator.exit_epoch,
            "withdrawable_epoch": validator.withdrawable_epoch
        },
        "header_root": header_root.hex(),
        "header": {
            "slot": state.latest_block_header.slot,
            "proposer_index": state.latest_block_header.proposer_index,
            "parent_root": state.latest_block_header.parent_root.hex(),
            "state_root": state.latest_block_header.state_root.hex(),
            "body_root": state.latest_block_header.body_root.hex()
        },
        "timestamp": state.latest_execution_payload_header.timestamp,
        "block_number": state.latest_execution_payload_header.block_number,
        "prev_state_root": prev_state_root_bytes.hex(),
        "prev_block_root": prev_block_root_bytes.hex()
    }
    
    return ProofResult(full_proof, state_root, metadata)


def generate_balance_proof(state_file: str, validator_index: int,
                         prev_state_root: Optional[str] = None,
                         prev_block_root: Optional[str] = None) -> ProofResult:
    """Generate a Merkle proof for a validator balance."""
    state = load_and_process_state(state_file)
    
    # Convert string parameters to bytes if provided
    prev_state_root_bytes = None
    prev_block_root_bytes = None
    
    if prev_state_root is not None:
        prev_state_root_bytes = bytes.fromhex(prev_state_root.replace('0x', ''))
    if prev_block_root is not None:
        prev_block_root_bytes = bytes.fromhex(prev_block_root.replace('0x', ''))
    
    # Use existing values from calculated position if not provided (fallback for compatibility)
    if prev_state_root_bytes is None:
        prev_state_root_bytes = state.state_roots[state.slot % 8]
    if prev_block_root_bytes is None:
        prev_block_root_bytes = state.block_roots[state.slot % 8]
    
    # Validate validator index
    if validator_index >= len(state.balances):
        raise ValueError(f"Validator index {validator_index} out of range (max: {len(state.balances)-1})")
    
    # Prepare state for merkleization
    state.latest_block_header.state_root = int(0).to_bytes(32)
    
    # Apply historical data modifications (8 slots ago as per spec)
    state.state_roots[state.slot % 8] = prev_state_root_bytes
    state.block_roots[state.slot % 8] = prev_block_root_bytes
    
    # Generate balance proof within the balances list
    # Balances are packed 4 per chunk (32 bytes / 8 bytes per uint64)
    from .ssz.merkle.tree import pack_vector_uint64
    
    # Pack all balances into chunks
    balance_chunks = pack_vector_uint64(state.balances, len(state.balances))
    
    # The validator's balance is in chunk at index validator_index // 4
    chunk_index = validator_index // 4
    
    # Calculate the limit for balance chunks
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    
    balance_proof = get_fixed_capacity_proof(
        balance_chunks,
        chunk_index,
        limit
    )
    
    # Add length mixing
    length_chunk = len(state.balances).to_bytes(32, "little")
    balance_proof.append(length_chunk)
    
    # Recompute balances root using the proof (matching working implementation)
    leaf = balance_chunks[chunk_index]
    balances_root = compute_root_from_proof(
        leaf, chunk_index, balance_proof
    )
    
    # Generate state proof for balances field (field index 10)
    state_proof = _generate_state_proof(state, field_index=10, prev_state_root=prev_state_root_bytes, prev_block_root=prev_block_root_bytes)
    
    # Combine all proofs
    full_proof = balance_proof + state_proof
    
    # Compute final state root
    state_root = _compute_state_root(state)
    
    # Get balance and validator
    balance = state.balances[validator_index]
    validator = state.validators[validator_index]
    
    # Create ValidatorBalance container
    validator_balance = ValidatorBalance(
        validator=validator,
        balance=balance
    )

    state.header.state_root = state_root
    header_root = state.header.merkle_root()
    
    metadata = {
        "proof_length": len(full_proof),
        "validator_index": validator_index,
        "balance": str(balance),
        "effective_balance": str(validator.effective_balance),
        "balances_root": balances_root.hex(),
        "balance_leaf": leaf.hex(),
        "validator_balance_root": validator_balance.merkle_root().hex(),
        "validator": {
            "pubkey": validator.pubkey.hex(),
            "withdrawal_credentials": validator.withdrawal_credentials.hex(),
            "effective_balance": validator.effective_balance,
            "slashed": validator.slashed,
            "activation_eligibility_epoch": validator.activation_eligibility_epoch,
            "activation_epoch": validator.activation_epoch,
            "exit_epoch": validator.exit_epoch,
            "withdrawable_epoch": validator.withdrawable_epoch
        },
        "header_root": header_root.hex(),
        "header": {
            "slot": state.latest_block_header.slot,
            "proposer_index": state.latest_block_header.proposer_index,
            "parent_root": state.latest_block_header.parent_root.hex(),
            "state_root": state.latest_block_header.state_root.hex(),
            "body_root": state.latest_block_header.body_root.hex()
        },
        "timestamp": state.latest_execution_payload_header.timestamp,
        "block_number": state.latest_execution_payload_header.block_number,
        "prev_state_root": prev_state_root_bytes.hex(),
        "prev_block_root": prev_block_root_bytes.hex()
    }
    
    return ProofResult(full_proof, state_root, metadata)

def generate_validator_and_balance_proofs(state_file: str, validator_index: int) -> ProofCombinedResult:
    """Generate a Merkle proofs for a validator and balance."""
    state = load_and_process_state(state_file)
    
    # Generate balance proof within the balances list
    # Balances are packed 4 per chunk (32 bytes / 8 bytes per uint64)
    from .ssz.merkle.tree import pack_vector_uint64
    
    # Pack all balances into chunks
    balance_chunks = pack_vector_uint64(state.balances, len(state.balances))
    
    # The validator's balance is in chunk at index validator_index // 4
    chunk_index = validator_index // 4
    
    # Calculate the limit for balance chunks
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    
    balance_proof = get_fixed_capacity_proof(
        balance_chunks,
        chunk_index,
        limit
    )
    
    # Add length mixing
    length_chunk = len(state.balances).to_bytes(32, "little")
    balance_proof.append(length_chunk)
    
    # Recompute balances root using the proof (matching working implementation)
    balance_leaf = balance_chunks[chunk_index]
    balances_root = compute_root_from_proof(
        balance_leaf, chunk_index, balance_proof
    )
    
    # Generate state proof for balances field (field index 10)
    state_proof_balance = _generate_state_proof(state, field_index=10)
    
    # Combine all proofs
    full_proof_balance = balance_proof + state_proof_balance

    # Generate validator proof within the validators list
    validator_elements = [v.merkle_root() for v in state.validators]
    val_proof = get_fixed_capacity_proof(
        validator_elements,
        validator_index,
        VALIDATOR_REGISTRY_LIMIT
    )
    
    # Add length mixing
    length_chunk = len(validator_elements).to_bytes(32, "little")
    val_proof.append(length_chunk)
    
    # Recompute validators root using the proof (matching working implementation)
    validator_leaf = validator_elements[validator_index]
    validators_root = compute_root_from_proof(
        validator_leaf, validator_index, val_proof
    )
    
    # Generate state proof for validators field (field index 9)
    state_proof_validator = _generate_state_proof(state, field_index=9)
    
    # Combine all proofs
    full_proof_validator = val_proof + state_proof_validator
    
    # Compute final state root
    state_root = _compute_state_root(state)
    
    # Get balance and validator
    balance = state.balances[validator_index]
    validator = state.validators[validator_index]
    
    # Create ValidatorBalance container
    validator_balance = ValidatorBalance(
        validator=validator,
        balance=balance
    )
    
    metadata = {
        "balance_proof_length": len(full_proof_balance),
        "validator_proof_length": len(full_proof_validator),
        "balance": str(balance),
        "effective_balance": str(validator.effective_balance),
        "timestamp": state.latest_execution_payload_header.timestamp,
        "block_number": state.latest_execution_payload_header.block_number
    }
     
    # Set the state root on the header before calculating header root
    state.latest_block_header.state_root = state_root
    header_root = state.latest_block_header.merkle_root()
    
    return ProofCombinedResult(
        balance_proof=full_proof_balance,
        validator_proof=full_proof_validator,
        state_root=state_root,
        balance_leaf=balance_leaf,
        balances_root=balances_root,
        validator_index=validator_index,
        header_root=header_root,
        header={
            "slot": state.latest_block_header.slot,
            "proposer_index": state.latest_block_header.proposer_index,
            "parent_root": f"0x{state.latest_block_header.parent_root.hex()}",
            "state_root": f"0x{state_root.hex()}",
            "body_root": f"0x{state.latest_block_header.body_root.hex()}"
        },
        validator_data={
            "pubkey": f"0x{validator.pubkey.hex()}",
            "withdrawal_credentials": f"0x{validator.withdrawal_credentials.hex()}",
            "effective_balance": validator.effective_balance,
            "slashed": validator.slashed,
            "activation_eligibility_epoch": validator.activation_eligibility_epoch,
            "activation_epoch": validator.activation_epoch,
            "exit_epoch": validator.exit_epoch,
            "withdrawable_epoch": validator.withdrawable_epoch
        },
        metadata=metadata
    )

def _generate_state_proof(
    state: BeaconState, 
    field_index: int, 
    prev_state_root: bytes = None, 
    prev_block_root: bytes = None
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
    # Get serialized state fields using the container's serialize method
    # Note: We assume this is not Electra for now
    state_fields = state.serialize(prev_block_root, prev_state_root, is_electra=True)
    
    # The serialize method already returns the properly padded fields
    # Build state tree and get proof
    state_tree = build_merkle_tree(state_fields)
    return get_proof(state_tree, field_index)


def _compute_state_root(state: BeaconState, validators_root: Optional[bytes] = None) -> bytes:
    """Compute the BeaconState merkle root using the state tree approach."""
    # We need to extract the historical roots that were already set
    # They should be at index (slot % 8) as per ETH2 spec
    prev_state_root = state.state_roots[state.slot % 8]
    prev_block_root = state.block_roots[state.slot % 8]
    
    # Use the new serialize method to get all field roots
    state_fields = state.serialize(prev_block_root, prev_state_root, is_electra=True)
    
    # If validators_root is provided, replace field 9 with it
    if validators_root is not None:
        state_fields[9] = validators_root
    
    # Build the merkle tree and get root
    state_tree = build_merkle_tree(state_fields)
    return state_tree[-1][0]  # Root is at the top level


def generate_merkle_witness(
    json_file: str, 
    validator_index: int,
    prev_state_root: Optional[str] = None,
    prev_block_root: Optional[str] = None
) -> Tuple[List[bytes], bytes]:
    """
    Generate a Merkle witness for a validator in the beacon state.
    
    Args:
        json_file: Path to the JSON file containing beacon state data
        validator_index: Index of the validator to generate proof for
        prev_state_root: Previous state root from 8 slots ago (hex string), uses default if None
        prev_block_root: Previous block root from 8 slots ago (hex string), uses default if None
        
    Returns:
        Tuple of (proof_steps, state_root) where:
        - proof_steps: List of 32-byte proof elements
        - state_root: 32-byte state root
        
    Note:
        The prev_state_root and prev_block_root represent values from 8 slots ago,
        as required by the Beacon Chain specification. Default values are loaded
        from test/data/state-8.json if available, otherwise hardcoded fallbacks are used.
    """
    # Load and process the beacon state
    state = load_and_process_state(json_file)
    
    # Handle historical root parameters
    prev_state_root_bytes = None
    prev_block_root_bytes = None
    
    if prev_state_root is not None:
        prev_state_root_bytes = bytes.fromhex(prev_state_root.replace('0x', ''))
    if prev_block_root is not None:
        prev_block_root_bytes = bytes.fromhex(prev_block_root.replace('0x', ''))
    
    # Load historical values from state-8.json if not provided
    if prev_state_root_bytes is None or prev_block_root_bytes is None:
        try:
            with open("test/data/state-8.json", "r") as f:
                state_8_data = json.load(f)["data"]
            if prev_state_root_bytes is None:
                prev_state_root_hex = state_8_data["state_roots"][2][2:]  # Remove 0x prefix
                prev_state_root_bytes = bytes.fromhex(prev_state_root_hex)
            if prev_block_root_bytes is None:
                prev_block_root_hex = state_8_data["block_roots"][2][2:]  # Remove 0x prefix
                prev_block_root_bytes = bytes.fromhex(prev_block_root_hex)
        except FileNotFoundError:
            # Fallback to hardcoded values if file not found
            if prev_state_root_bytes is None:
                prev_state_root_bytes = bytes.fromhex("01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8")
            if prev_block_root_bytes is None:
                prev_block_root_bytes = bytes.fromhex("28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74")
    
    # Set the state root from 8 slots ago (required by Beacon Chain spec)
    state.latest_block_header.state_root = int(0).to_bytes(32)
    state.state_roots[state.slot % 8] = prev_state_root_bytes
    state.block_roots[state.slot % 8] = prev_block_root_bytes
    
    print(f"Using prev_state_root (8 slots ago): {prev_state_root_bytes.hex()}")
    print(f"Using prev_block_root (8 slots ago): {prev_block_root_bytes.hex()}")
    
    # Generate the proof
    proof = []
    current_index = validator_index
    
    # Step 1: Get proof of validator within validators list
    validator_tree = merkle_list_tree([v.merkle_root() for v in state.validators])
    validator_proof = get_fixed_capacity_proof(validator_tree, current_index, VALIDATOR_REGISTRY_LIMIT)
    proof.extend(validator_proof)
    
    # Step 2: Get proof that validators list is in state
    state_proof = _generate_state_proof(
        state, 
        9,  # Field index for validators
        prev_state_root_bytes,
        prev_block_root_bytes
    )
    proof.extend(state_proof)
    
    # Compute final state root
    state_root = _compute_state_root(state)
    
    return proof, state_root


# Example usage
if __name__ == "__main__":
    proof, state_root = generate_merkle_witness("test/data/state.json", 39)
    print("Merkle Witness (hex):")
    for i, h in enumerate(proof):
        print(f"Step {i}: {h.hex()}")
    print(f"State Root: {state_root.hex()}")
