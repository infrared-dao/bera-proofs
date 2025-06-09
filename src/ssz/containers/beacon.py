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
    EPOCHS_PER_SLASHINGS_VECTOR,
    BERACHAIN_VECTOR,
    PENDING_PARTIAL_WITHDRAWALS_LIMIT,
)


@dataclass
class Fork:
    """Fork represents a network fork with version information."""
    previous_version: bytes
    current_version: bytes
    epoch: int

    def serialize(self) -> List[bytes]:
        """Serialize Fork fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(merkle_root_basic(self.previous_version, "bytes4"))
        roots.append(merkle_root_basic(self.current_version, "bytes4"))
        roots.append(merkle_root_basic(self.epoch, "uint64"))
        # pad to 4 leaves with zero-hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for Fork."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Fork."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


@dataclass
class BeaconBlockHeader:
    """BeaconBlockHeader represents the header of a beacon chain block."""
    slot: int
    proposer_index: int
    parent_root: bytes
    state_root: bytes
    body_root: bytes

    def serialize(self) -> List[bytes]:
        """Serialize BeaconBlockHeader fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(merkle_root_basic(self.slot, "uint64"))
        roots.append(merkle_root_basic(self.proposer_index, "uint64"))
        roots.append(self.parent_root)
        roots.append(self.state_root)
        roots.append(self.body_root)
        # pad to 8 leaves (2³) with zero-hash
        roots += [b"\x00" * 32] * 3
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for BeaconBlockHeader."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for BeaconBlockHeader."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


@dataclass
class Eth1Data:
    """Eth1Data represents Ethereum 1.0 chain data in the beacon chain."""
    deposit_root: bytes
    deposit_count: int
    block_hash: bytes

    def serialize(self) -> List[bytes]:
        """Serialize Eth1Data fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(self.deposit_root)
        roots.append(merkle_root_basic(self.deposit_count, "uint64"))
        roots.append(self.block_hash)
        # pad to 4 leaves with zero-hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for Eth1Data."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Eth1Data."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


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

    def serialize(self) -> List[bytes]:
        """Serialize ExecutionPayloadHeader fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(self.parent_hash)
        roots.append(merkle_root_basic(self.fee_recipient, "bytes20"))
        roots.append(self.state_root)
        roots.append(self.receipts_root)
        roots.append(merkle_root_basic(self.logs_bloom, "bytes256"))
        roots.append(self.prev_randao)
        roots.append(merkle_root_basic(self.block_number, "uint64"))
        roots.append(merkle_root_basic(self.gas_limit, "uint64"))
        roots.append(merkle_root_basic(self.gas_used, "uint64"))
        roots.append(merkle_root_basic(self.timestamp, "uint64"))
        roots.append(merkle_root_basic(self.extra_data, "bytes"))
        roots.append(merkle_root_basic(self.base_fee_per_gas, "uint64"))
        roots.append(self.block_hash)
        roots.append(self.transactions_root)
        roots.append(self.withdrawals_root)
        roots.append(merkle_root_basic(self.blob_gas_used, "uint64"))
        roots.append(merkle_root_basic(self.excess_blob_gas, "uint64"))
        # pad to 32 leaves with zero-hash
        roots += [b"\x00" * 32] * 15
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for ExecutionPayloadHeader."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for ExecutionPayloadHeader."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


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

    def serialize(self) -> List[bytes]:
        """Serialize Validator fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(merkle_root_basic(self.pubkey, "bytes48"))
        roots.append(self.withdrawal_credentials)
        roots.append(merkle_root_basic(self.effective_balance, "uint64"))
        roots.append(merkle_root_basic(self.slashed, "Boolean"))
        roots.append(merkle_root_basic(self.activation_eligibility_epoch, "uint64"))
        roots.append(merkle_root_basic(self.activation_epoch, "uint64"))
        roots.append(merkle_root_basic(self.exit_epoch, "uint64"))
        roots.append(merkle_root_basic(self.withdrawable_epoch, "uint64"))
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for Validator."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for Validator."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


@dataclass
class PendingPartialWithdrawal:
    """PendingPartialWithdrawal represents a pending withdrawal from a validator."""
    validator_index: int  # uint64
    amount: int  # uint64
    withdrawable_epoch: int  # uint64

    def serialize(self) -> List[bytes]:
        """Serialize PendingPartialWithdrawal fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        
        roots = []
        roots.append(merkle_root_basic(self.validator_index, "uint64"))
        roots.append(merkle_root_basic(self.amount, "uint64"))
        roots.append(merkle_root_basic(self.withdrawable_epoch, "uint64"))
        # pad to 4 leaves with zero-hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for PendingPartialWithdrawal."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        """Calculate SSZ merkle root for PendingPartialWithdrawal."""
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        """Get merkle proof for field at index."""
        from ..merkle.proof import get_proof
        return get_proof(self.merkle_tree(), index)


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
    pending_partial_withdrawals: List[PendingPartialWithdrawal] = None  # Electra field

    def __post_init__(self):
        """Initialize default values for optional fields."""
        if self.pending_partial_withdrawals is None:
            self.pending_partial_withdrawals = []

    def serialize(self, prev_cycle_block_root: bytes, prev_cycle_state_root: bytes, is_electra: bool = False) -> List[bytes]:
        """Serialize BeaconState fields to list of 32-byte chunks."""
        from ..merkle.core import merkle_root_basic
        from ..merkle.encoding import (
            encode_validators_leaf_list,
            encode_balances,
            encode_block_roots,
            encode_randao_mixes,
            encode_slashings,
            encode_pending_partial_withdrawals_leaf_list,
        )
        
        roots = []
        roots.append(self.genesis_validators_root)
        roots.append(merkle_root_basic(self.slot, "uint64"))
        roots.append(self.fork.merkle_root())
        
        # Reset state root for merkleization
        self.latest_block_header.state_root = int(0).to_bytes(32)
        roots.append(self.latest_block_header.merkle_root())
        
        # Reset state root and block root fields to prev cycle
        # NOTE: Using fixed index 2 to match original implementation
        # TODO: Verify if this should be slot % BERACHAIN_VECTOR
        self.state_roots[2] = prev_cycle_state_root
        self.block_roots[2] = prev_cycle_block_root
        
        roots.append(encode_block_roots(self.block_roots))
        roots.append(encode_block_roots(self.state_roots))
        roots.append(self.eth1_data.merkle_root())
        roots.append(merkle_root_basic(self.eth1_deposit_index, "uint64"))
        roots.append(self.latest_execution_payload_header.merkle_root())
        roots.append(encode_validators_leaf_list([v.merkle_root() for v in self.validators]))
        roots.append(encode_balances(self.balances))
        roots.append(encode_randao_mixes(self.randao_mixes))
        roots.append(merkle_root_basic(self.next_withdrawal_index, "uint64"))
        roots.append(merkle_root_basic(self.next_withdrawal_validator_index, "uint64"))
        roots.append(encode_slashings(self.slashings))
        roots.append(merkle_root_basic(self.total_slashing, "uint64"))
        
        if is_electra and self.pending_partial_withdrawals:
            roots.append(
                encode_pending_partial_withdrawals_leaf_list(
                    [p.merkle_root() for p in self.pending_partial_withdrawals]
                )
            )
            # pad to 32 leaves with zero-hash
            roots += [b"\x00" * 32] * 15
        
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        """Build complete merkle tree for BeaconState."""
        from ..merkle.core import build_merkle_tree
        return build_merkle_tree(self.serialize())

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