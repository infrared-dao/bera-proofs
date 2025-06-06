from typing import List, Dict, Any
import math
from dataclasses import dataclass
from merkleize import *


@dataclass
class Fork:
    previous_version: bytes  # bytes4
    current_version: bytes  # bytes4
    epoch: int  # uint64

    def serialize(self) -> List[bytes]:
        roots = []
        roots.append(merkle_root_basic(self.previous_version, "bytes4"))
        roots.append(merkle_root_basic(self.current_version, "bytes4"))
        roots.append(merkle_root_basic(self.epoch, "uint64"))
        # pad to 4 leaves with zero‐hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class BeaconBlockHeader:
    slot: int  # uint64
    proposer_index: int  # uint64
    parent_root: bytes  # bytes32
    state_root: bytes  # bytes32
    body_root: bytes  # bytes32

    def serialize(self) -> List[bytes]:
        roots = []
        roots.append(merkle_root_basic(self.slot, "uint64"))
        roots.append(merkle_root_basic(self.proposer_index, "uint64"))
        roots.append(self.parent_root)
        roots.append(self.state_root)
        roots.append(self.body_root)
        # pad to 8 leaves (2³) with zero‐hash
        roots += [b"\x00" * 32] * 3
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class Eth1Data:
    deposit_root: bytes  # bytes32
    deposit_count: int  # uint64
    block_hash: bytes  # bytes32

    def serialize(self) -> List[bytes]:
        roots = []
        roots.append(self.deposit_root)
        roots.append(merkle_root_basic(self.deposit_count, "uint64"))
        roots.append(self.block_hash)
        # pad to 4 leaves with zero‐hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class ExecutionPayloadHeader:
    parent_hash: bytes  # bytes32
    fee_recipient: bytes  # bytes20
    state_root: bytes  # bytes32
    receipts_root: bytes  # bytes32
    logs_bloom: bytes  # bytes256
    prev_randao: bytes  # bytes32
    block_number: int  # uint64
    gas_limit: int  # uint64
    gas_used: int  # uint64
    timestamp: int  # uint64
    extra_data: bytes  # ByteList[32]
    base_fee_per_gas: int  # uint256
    block_hash: bytes  # bytes32
    transactions_root: bytes  # bytes32
    withdrawals_root: bytes  # bytes32
    blob_gas_used: int  # uint64
    excess_blob_gas: int  # uint64

    def serialize(self) -> List[bytes]:
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
        # pad to 32 leaves with zero‐hash
        roots += [b"\x00" * 32] * 15
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class Validator:
    pubkey: bytes  # bytes48
    withdrawal_credentials: bytes  # bytes32
    effective_balance: int  # uint64
    slashed: bool  # Boolean
    activation_eligibility_epoch: int  # uint64
    activation_epoch: int  # uint64
    exit_epoch: int  # uint64
    withdrawable_epoch: int  # uint64

    def serialize(self) -> List[bytes]:
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
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class PendingPartialWithdrawal:
    validator_index: int  # uint64
    amount: int  # uint64
    withdrawable_epoch: int  # uint64

    def serialize(self) -> List[bytes]:
        roots = []
        roots.append(merkle_root_basic(self.validator_index, "uint64"))
        roots.append(merkle_root_basic(self.amount, "uint64"))
        roots.append(merkle_root_basic(self.withdrawable_epoch, "uint64"))
        # pad to 4 leaves with zero‐hash
        roots += [b"\x00" * 32]
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)


@dataclass
class BeaconState:
    genesis_validators_root: bytes
    slot: int
    fork: "Fork"
    latest_block_header: "BeaconBlockHeader"
    block_roots: List[
        bytes
    ]  # note all lists and vectors are treated the same i.e. merkleize as extreme vector then add list len component
    state_roots: List[bytes]
    eth1_data: "Eth1Data"
    eth1_deposit_index: int
    latest_execution_payload_header: "ExecutionPayloadHeader"
    validators: List["Validator"]
    balances: List[int]
    randao_mixes: List[bytes]
    next_withdrawal_index: int
    next_withdrawal_validator_index: int
    slashings: List[int]
    total_slashing: int  # new field from bera
    pending_partial_withdrawals: List[
        "PendingPartialWithdrawal"
    ]  # electra only new field from bera

    def serialize(
        self,
        prev_cycle_block_root: bytes,
        prev_cycle_state_root: bytes,
        isElectra: bool = False,
    ) -> List[bytes]:
        roots = []
        roots.append(self.genesis_validators_root)
        roots.append(merkle_root_basic(self.slot, "uint64"))
        roots.append(self.fork.merkle_root())
        # reset state root for merkleization
        self.latest_block_header.state_root = int(0).to_bytes(32)
        roots.append(self.latest_block_header.merkle_root())
        # reset state root and block root fields to prev cycle
        self.state_roots[self.slot % BERACHAIN_VECTOR] = prev_cycle_state_root
        self.block_roots[self.slot % BERACHAIN_VECTOR] = prev_cycle_block_root
        roots.append(encode_block_roots(self.block_roots))
        roots.append(encode_block_roots(self.state_roots))
        roots.append(self.eth1_data.merkle_root())
        roots.append(merkle_root_basic(self.eth1_deposit_index, "uint64"))
        roots.append(self.latest_execution_payload_header.merkle_root())
        roots.append(
            encode_validators_leaf_list([v.merkle_root() for v in self.validators])
        )
        roots.append(encode_balances(self.balances))  # note balances are packed
        roots.append(encode_randao_mixes(self.randao_mixes))
        roots.append(merkle_root_basic(self.next_withdrawal_index, "uint64"))
        roots.append(merkle_root_basic(self.next_withdrawal_validator_index, "uint64"))
        roots.append(encode_slashings(state.slashings))
        roots.append(merkle_root_basic(state.total_slashing, "uint64"))
        if isElectra:
            roots.append(
                encode_pending_partial_withdrawals_leaf_list(
                    [p.merkle_root() for p in self.pending_partial_withdrawals]
                )
            )
            # pad to 32 leaves with zero‐hash
            roots += [b"\x00" * 32] * 15
        return roots

    def merkle_tree(self) -> List[List[bytes]]:
        return build_merkle_tree(self.serialize())

    def merkle_root(self) -> bytes:
        return self.merkle_tree()[-1][0]

    def get_proof(self, index: int) -> List[bytes]:
        return get_proof(self.merkle_tree(), index)

    # def merkle_root(self) -> bytes:
    #     fields = [
    #         ("genesis_validators_root", "bytes32"),
    #         ("slot", "uint64"),
    #         ("fork", "Fork"),
    #         ("latest_block_header", "BeaconBlockHeader"),
    #         ("block_roots", f"Vector[bytes32, {SLOTS_PER_HISTORICAL_ROOT}]"),
    #         ("state_roots", f"Vector[bytes32, {SLOTS_PER_HISTORICAL_ROOT}]"),
    #         ("eth1_data", "Eth1Data"),
    #         ("eth1_deposit_index", "uint64"),
    #         ("latest_execution_payload_header", "ExecutionPayloadHeader"),
    #         ("validators", f"List[Validator, {VALIDATOR_REGISTRY_LIMIT}]"),
    #         ("balances", f"List[uint64, {VALIDATOR_REGISTRY_LIMIT}]"),
    #         ("randao_mixes", f"Vector[bytes32, {EPOCHS_PER_HISTORICAL_VECTOR}]"),
    #         ("next_withdrawal_index", "uint64"),
    #         ("next_withdrawal_validator_index", "uint64"),
    #         ("slashings", f"Vector[uint64, {EPOCHS_PER_SLASHINGS_VECTOR}]"),
    #         ("total_slashing", "uint64"),
    #     ]
    #     return merkle_root_container(self, fields)
