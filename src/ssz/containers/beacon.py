"""
Beacon Chain Data Structures

This module contains SSZ container definitions for Ethereum Beacon Chain data structures.
"""

from dataclasses import dataclass
from typing import List, Tuple

from ..constants import (
    SLOTS_PER_HISTORICAL_ROOT,
    VALIDATOR_REGISTRY_LIMIT,
    EPOCHS_PER_HISTORICAL_VECTOR,
    EPOCHS_PER_SLASHINGS_VECTOR
)


@dataclass
class Fork:
    """Fork represents a network fork with version information."""
    previous_version: bytes
    current_version: bytes
    epoch: int

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Fork."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("previous_version", "bytes4"),
            ("current_version", "bytes4"),
            ("epoch", "uint64"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class BeaconBlockHeader:
    """BeaconBlockHeader represents the header of a beacon chain block."""
    slot: int
    proposer_index: int
    parent_root: bytes
    state_root: bytes
    body_root: bytes

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for BeaconBlockHeader."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("slot", "uint64"),
            ("proposer_index", "uint64"),
            ("parent_root", "bytes32"),
            ("state_root", "bytes32"),
            ("body_root", "bytes32"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class Eth1Data:
    """Eth1Data represents Ethereum 1.0 chain data in the beacon chain."""
    deposit_root: bytes
    deposit_count: int
    block_hash: bytes

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Eth1Data."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("deposit_root", "bytes32"),
            ("deposit_count", "uint64"),
            ("block_hash", "bytes32"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class ExecutionPayloadHeader:
    """ExecutionPayloadHeader represents the header of an execution payload."""
    parent_hash: bytes
    fee_recipient: bytes
    state_root: bytes
    receipts_root: bytes
    logs_bloom: bytes
    prev_randao: bytes
    block_number: int
    gas_limit: int
    gas_used: int
    timestamp: int
    extra_data: bytes
    base_fee_per_gas: int
    block_hash: bytes
    transactions_root: bytes
    withdrawals_root: bytes
    blob_gas_used: int
    excess_blob_gas: int

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for ExecutionPayloadHeader."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("parent_hash", "bytes32"),
            ("fee_recipient", "bytes20"),
            ("state_root", "bytes32"),
            ("receipts_root", "bytes32"),
            ("logs_bloom", "bytes256"),
            ("prev_randao", "bytes32"),
            ("block_number", "uint64"),
            ("gas_limit", "uint64"),
            ("gas_used", "uint64"),
            ("timestamp", "uint64"),
            ("extra_data", "bytes"),
            ("base_fee_per_gas", "uint256"),
            ("block_hash", "bytes32"),
            ("transactions_root", "bytes32"),
            ("withdrawals_root", "bytes32"),
            ("blob_gas_used", "uint64"),
            ("excess_blob_gas", "uint64"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class Validator:
    """Validator represents a beacon chain validator."""
    pubkey: bytes
    withdrawal_credentials: bytes
    effective_balance: int
    slashed: bool
    activation_eligibility_epoch: int
    activation_epoch: int
    exit_epoch: int
    withdrawable_epoch: int

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Validator."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("pubkey", "bytes48"),
            ("withdrawal_credentials", "bytes32"),
            ("effective_balance", "uint64"),
            ("slashed", "Boolean"),
            ("activation_eligibility_epoch", "uint64"),
            ("activation_epoch", "uint64"),
            ("exit_epoch", "uint64"),
            ("withdrawable_epoch", "uint64"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class BeaconState:
    """BeaconState represents the complete state of the beacon chain."""
    genesis_validators_root: bytes
    slot: int
    fork: Fork
    latest_block_header: BeaconBlockHeader
    block_roots: List[bytes]
    state_roots: List[bytes]
    eth1_data: Eth1Data
    eth1_deposit_index: int
    latest_execution_payload_header: ExecutionPayloadHeader
    validators: List[Validator]
    balances: List[int]
    randao_mixes: List[bytes]
    next_withdrawal_index: int
    next_withdrawal_validator_index: int
    slashings: List[int]
    total_slashing: int

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for BeaconState."""
        from ..merkle.core import merkle_root_container
        
        fields = [
            ("genesis_validators_root", "bytes32"),
            ("slot", "uint64"),
            ("fork", "Fork"),
            ("latest_block_header", "BeaconBlockHeader"),
            ("block_roots", f"Vector[bytes32, {SLOTS_PER_HISTORICAL_ROOT}]"),
            ("state_roots", f"Vector[bytes32, {SLOTS_PER_HISTORICAL_ROOT}]"),
            ("eth1_data", "Eth1Data"),
            ("eth1_deposit_index", "uint64"),
            ("latest_execution_payload_header", "ExecutionPayloadHeader"),
            ("validators", f"List[Validator, {VALIDATOR_REGISTRY_LIMIT}]"),
            ("balances", f"List[uint64, {VALIDATOR_REGISTRY_LIMIT}]"),
            ("randao_mixes", f"Vector[bytes32, {EPOCHS_PER_HISTORICAL_VECTOR}]"),
            ("next_withdrawal_index", "uint64"),
            ("next_withdrawal_validator_index", "uint64"),
            ("slashings", f"Vector[uint64, {EPOCHS_PER_SLASHINGS_VECTOR}]"),
            ("total_slashing", "uint64"),
        ]
        return merkle_root_container(self, fields) 