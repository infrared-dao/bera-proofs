"""
Container Utilities

This module provides utility functions for working with SSZ containers,
including JSON conversion and data loading functions.
"""

from typing import Any, Dict, List, Union, Type, TYPE_CHECKING
import json
import re

if TYPE_CHECKING:
    from .beacon import BeaconState


def camel_to_snake(name: str) -> str:
    name = re.sub("(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub("([a-z0-9])([A-Z])", r"\1_\2", name).lower()


def normalize_hex(hex_str, expected_bytes=None):
    if not isinstance(hex_str, str) or not hex_str.startswith("0x"):
        return hex_str
    hex_part = hex_str[2:]
    if not all(c in "0123456789abcdefABCDEF" for c in hex_part):
        raise ValueError(f"Invalid hex string: {hex_str}")
    # Pad to even length
    if len(hex_part) % 2 == 1:
        hex_part = "0" + hex_part
    return "0x" + hex_part


def json_to_class(data: Any, cls: type) -> Any:
    from .beacon import Fork, BeaconBlockHeader, Eth1Data, ExecutionPayloadHeader, Validator, BeaconState, PendingPartialWithdrawal
    
    if isinstance(data, dict):
        # Convert keys to snake_case and adjust data types
        processed = {}
        for key, value in data.items():
            new_key = camel_to_snake(key)
            if new_key == "parent_block_root":
                new_key = "parent_root"
            if isinstance(value, str) and value.startswith("0x"):
                value = normalize_hex(value)
                if new_key in {
                    "pubkey",
                    "withdrawal_credentials",
                    "genesis_validators_root",
                    "parent_root",
                    "state_root",
                    "body_root",
                    "deposit_root",
                    "block_hash",
                    "parent_hash",
                    "fee_recipient",
                    "receipts_root",
                    "logs_bloom",
                    "prev_randao",
                    "transactions_root",
                    "withdrawals_root",
                    "extra_data",
                    "previous_version",
                    "current_version",
                }:
                    processed[new_key] = bytes.fromhex(value[2:])
                elif new_key in {
                    "slot",
                    "effective_balance",
                    "activation_eligibility_epoch",
                    "activation_epoch",
                    "exit_epoch",
                    "withdrawable_epoch",
                    "proposer_index",
                    "epoch",
                    "deposit_count",
                    "block_number",
                    "gas_limit",
                    "gas_used",
                    "timestamp",
                    "blob_gas_used",
                    "excess_blob_gas",
                    "next_withdrawal_validator_index",
                    "validator_index",
                    "amount",
                }:
                    processed[new_key] = (
                        int(value, 16) if isinstance(value, str) else value
                    )
            elif isinstance(value, str):
                processed[new_key] = int(value)
            else:
                processed[new_key] = value

        if cls == Fork:
            return Fork(**processed)
        elif cls == BeaconBlockHeader:
            return BeaconBlockHeader(**processed)
        elif cls == Eth1Data:
            return Eth1Data(**processed)
        elif cls == ExecutionPayloadHeader:
            return ExecutionPayloadHeader(**processed)
        elif cls == Validator:
            return Validator(**processed)
        elif cls == PendingPartialWithdrawal:
            return PendingPartialWithdrawal(**processed)
        if cls == BeaconState:
            # Provide default values for missing fields
            processed["next_withdrawal_index"] = processed.get(
                "next_withdrawal_index", 0
            )
            processed["next_withdrawal_validator_index"] = processed.get(
                "next_withdrawal_validator_index", 0
            )
            processed["slashings"] = processed.get("slashings", [])
            processed["total_slashing"] = processed.get("total_slashing", 0)
            processed["pending_partial_withdrawals"] = processed.get("pending_partial_withdrawals", [])
            # Process nested structures
            processed["fork"] = json_to_class(processed["fork"], Fork)
            processed["latest_block_header"] = json_to_class(
                processed["latest_block_header"], BeaconBlockHeader
            )
            processed["eth1_data"] = json_to_class(processed["eth1_data"], Eth1Data)
            processed["latest_execution_payload_header"] = json_to_class(
                processed["latest_execution_payload_header"], ExecutionPayloadHeader
            )
            processed["validators"] = [
                json_to_class(v, Validator) for v in processed["validators"]
            ]
            processed["pending_partial_withdrawals"] = [
                json_to_class(w, PendingPartialWithdrawal) for w in processed.get("pending_partial_withdrawals", [])
            ]
            processed["block_roots"] = [
                bytes.fromhex(br[2:]) for br in processed["block_roots"]
            ]
            processed["state_roots"] = [
                bytes.fromhex(sr[2:]) for sr in processed["state_roots"]
            ]
            processed["randao_mixes"] = [
                bytes.fromhex(rm[2:]) for rm in processed["randao_mixes"]
            ]

            return BeaconState(**processed)
    elif isinstance(data, list):
        return [json_to_class(item, cls) for item in data]
    return data


def load_and_process_state(state_file: str) -> 'BeaconState':
    from .beacon import BeaconState
    
    with open(state_file, "r") as f:
        state_data = json.load(f)["data"]
    return json_to_class(state_data, BeaconState) 