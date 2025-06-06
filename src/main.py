"""
Refactored Main Module

This module provides the same functionality as main.py but uses the modular
SSZ library structure for better organization and maintainability.
"""

import math
from typing import List, Tuple
from ssz import (
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


def generate_merkle_witness(
    state_file: str, validator_index: int
) -> tuple[List[bytes], bytes]:
    # Load state as BeaconState instance
    state = load_and_process_state(state_file)

    # reset state root for merkle
    state.latest_block_header.state_root = int(0).to_bytes(32)
    state.state_roots[2] = bytes.fromhex(
        "01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8"
    )
    # state.state_roots[2] = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    state.block_roots[2] = bytes.fromhex(
        "28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"
    )
    # state.block_roots[2] = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")

    # Compute validator roots
    # validator_roots = [v.merkle_root() for v in state.validators]
    # validators_tree = build_merkle_tree(validator_roots)
    # validators_root = validators_tree[-1][0]
    validators_root = merkle_root_ssz_list(
        state.validators, "Validator", VALIDATOR_REGISTRY_LIMIT
    )
    validators_tree = merkle_list_tree([v.merkle_root() for v in state.validators])
    print(validators_root.hex())

    elements_roots = [merkle_root_element(v, "Validator") for v in state.validators]

    # Berachain treats the validator registry as exactly Vector[Validator, 2^40].
    validator_capacity = VALIDATOR_REGISTRY_LIMIT  # 2^40

    # We need a proof for index 51 in a 2^40‐sized tree,
    # where only the first len(elements_roots) leaves are "real" and the rest are zeros.
    validator_list_proof = get_fixed_capacity_proof(
        elements_roots, index=validator_index, capacity=validator_capacity
    )
    length_chunk = len(elements_roots).to_bytes(32, "little")  # b'\x45' + b'\x00'*31
    validator_list_proof.append(length_chunk)

    leaf = elements_roots[validator_index]

    validators_root = compute_root_from_proof(
        leaf, validator_index, validator_list_proof
    )
    # validators_root = sha256(validators_root + length_chunk).digest()

    # Compute state root
    # state_root = state.merkle_root()

    # Generate proofs
    # proof_list = get_proof(validators_tree, validator_index)

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
        # merkle_root_vector(state.block_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
        encode_block_roots(state.block_roots),
        # Field (5): state_roots
        # merkle_root_vector(state.state_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
        encode_block_roots(state.state_roots),
        # Field (6): eth1_data
        state.eth1_data.merkle_root(),
        # Field (7): eth1_deposit_index
        merkle_root_basic(state.eth1_deposit_index, "uint64"),
        # Field (8): latest_execution_payload_header
        state.latest_execution_payload_header.merkle_root(),
        # Field (9): validators
        validators_root,
        # Field (10): balances
        # merkle_root_vector(state.balances, "uint64", MAX_VALIDATORS),
        # merkle_root_ssz_list(state.balances, "uint64", MAX_VALIDATORS),
        encode_balances(state.balances),
        # merkle_root_ssz_list(state.balances, "uint64", VALIDATOR_REGISTRY_LIMIT),
        # Field (11): randao_mixes
        # merkle_root_vector(state.randao_mixes, "bytes32", EPOCHS_PER_HISTORICAL_VECTOR),
        # merkle_root_ssz_list(
        #     state.randao_mixes, "bytes32", EPOCHS_PER_HISTORICAL_VECTOR
        # ),
        encode_randao_mixes(state.randao_mixes),
        # Field (12): next_withdrawal_index
        merkle_root_basic(state.next_withdrawal_index, "uint64"),
        # Field (13): next_withdrawal_validator_index
        merkle_root_basic(state.next_withdrawal_validator_index, "uint64"),
        # Field (14): slashings
        # merkle_root_vector(state.slashings, "uint64", EPOCHS_PER_SLASHINGS_VECTOR),
        encode_slashings(state.slashings),
        # Field (15): total_slashing
        merkle_root_basic(state.total_slashing, "uint64"),
    ]
    # Pad to next power of two
    n = len(state_fields)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = state_fields + [b"\0" * 32] * (num_leaves - n)

    state_tree = build_merkle_tree(padded)

    proof_state = get_proof(
        state_tree,
        9,
    )  # validators at index 9

    # # Berachain treats BeaconState as a Vector of length 32 (i.e., pad 16→32).
    # state_capacity = 32
    # # We want a proof for field index 9 in a 32‐leaf tree
    # proof_state = get_fixed_capacity_proof(
    #     state_fields, index=9, capacity=state_capacity
    # )

    leaf = state_fields[9]

    # state_root = compute_root_from_proof(leaf, 9, proof_state)
    state_root = state_tree[-1][0]

    # Combine proofs
    full_proof = validator_list_proof + proof_state
    return full_proof, state_root


# Example usage
if __name__ == "__main__":
    proof, state_root = generate_merkle_witness("test/data/state.json", 39)
    print("Merkle Witness (hex):")
    for i, h in enumerate(proof):
        print(f"Step {i}: {h.hex()}")
    print(f"State Root: {state_root.hex()}")
