import json
import re

# from sha3 import sha3_256
from hashlib import sha256
from typing import List, Dict, Any
import math
from dataclasses import dataclass

# Constants for SSZ limits
# SLOTS_PER_HISTORICAL_ROOT = 8192  # For block_roots, state_roots
# EPOCHS_PER_HISTORICAL_VECTOR = 65536  # For randao_mixes
# MAX_VALIDATORS = 1099511627776  # For validators, balances, slashings
# EPOCHS_PER_SLASHINGS_VECTOR = 8192  # For slashings
SLOTS_PER_HISTORICAL_ROOT = 8  # For block_roots, state_roots
EPOCHS_PER_HISTORICAL_VECTOR = 8  # For randao_mixes
MAX_VALIDATORS = 69  # For validators, balances, slashings
EPOCHS_PER_SLASHINGS_VECTOR = 8  # For slashings

BYTES_PER_LOGS_BLOOM = 256


# Precompute zero node hashes for up to 40 levels
ZERO_HASHES = [b"\0" * 32]
for _ in range(40):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())

# Define basic serialization functions
def serialize_uint64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def serialize_uint256(value: int) -> bytes:
    return value.to_bytes(32, "little")


def serialize_bool(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


def serialize_bytes(value: bytes, length: int) -> bytes:
    assert len(value) == length, f"Expected {length} bytes, got {len(value)}"
    return value


# Utility function to convert camel case to snake case
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


# Define container classes with Merkleization
@dataclass
class Fork:
    previous_version: bytes
    current_version: bytes
    epoch: int

    def merkle_root(self) -> bytes:
        fields = [
            ("previous_version", "bytes4"),
            ("current_version", "bytes4"),
            ("epoch", "uint64"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class BeaconBlockHeader:
    slot: int
    proposer_index: int
    parent_root: bytes
    state_root: bytes
    body_root: bytes

    def merkle_root(self) -> bytes:
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
    deposit_root: bytes
    deposit_count: int
    block_hash: bytes

    def merkle_root(self) -> bytes:
        fields = [
            ("deposit_root", "bytes32"),
            ("deposit_count", "uint64"),
            ("block_hash", "bytes32"),
        ]
        return merkle_root_container(self, fields)


@dataclass
class ExecutionPayloadHeader:
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
    pubkey: bytes
    withdrawal_credentials: bytes
    effective_balance: int
    slashed: bool
    activation_eligibility_epoch: int
    activation_epoch: int
    exit_epoch: int
    withdrawable_epoch: int

    def merkle_root(self) -> bytes:
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
    genesis_validators_root: bytes
    slot: int
    fork: "Fork"
    latest_block_header: "BeaconBlockHeader"
    block_roots: List[bytes]
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
    total_slashing: int

    def merkle_root(self) -> bytes:
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
            ("validators", f"List[Validator, {MAX_VALIDATORS}]"),
            ("balances", f"List[uint64, {MAX_VALIDATORS}]"),
            ("randao_mixes", f"Vector[bytes32, {EPOCHS_PER_HISTORICAL_VECTOR}]"),
            ("next_withdrawal_index", "uint64"),
            ("next_withdrawal_validator_index", "uint64"),
            ("slashings", f"List[uint64, {MAX_VALIDATORS}]"),
            ("total_slashing", "uint64"),
        ]
        return merkle_root_container(self, fields)


# Function to convert JSON data to class instances
def json_to_class(data: Any, cls: type) -> Any:
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
        if cls == BeaconState:
            # Provide default values for missing fields
            processed["next_withdrawal_index"] = processed.get(
                "next_withdrawal_index", 0
            )
            processed["slashings"] = processed.get("slashings", [])
            processed["total_slashing"] = processed.get("total_slashing", 0)
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


# Load and process state from JSON into BeaconState instance
def load_and_process_state(state_file: str) -> BeaconState:
    with open(state_file, "r") as f:
        state_data = json.load(f)["data"]
    return json_to_class(state_data, BeaconState)


def merkle_root_basic(value: Any, type_str: str) -> bytes:
    if type_str.startswith("bytes") and isinstance(value, str):
        if value.startswith("0x"):
            value = bytes.fromhex(value[2:])
        else:
            value = bytes.fromhex(value)
    if type_str == "bytes32":
        return serialize_bytes(value, 32)  # Already 32 bytes, return directly
    elif type_str == "uint64":
        serialized = serialize_uint64(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "uint256":
        serialized = serialize_uint256(value)
        return serialized  # Already 32 bytes, no hash
    elif type_str == "Boolean":
        serialized = serialize_bool(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes48":
        chunk1 = value[0:32]
        chunk2 = value[32:48] + b"\0" * 16
        return sha256(chunk1 + chunk2).digest()  # >32 bytes, hash required
    elif type_str == "bytes20":
        serialized = serialize_bytes(value, 20)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes256":
        chunks = [value[i : i + 32] for i in range(0, 256, 32)]
        return merkle_root_list(chunks)  # Fixed-size, Merkleize chunks
    elif type_str == "bytes4":
        serialized = serialize_bytes(value, 4)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes":
        # extra data is the only case, type is actually ByteList[32] but bytes is a shortcut for processing
        # Validate length
        max_length = 32  # MAX_EXTRA_DATA_BYTES
        if len(value) > max_length:
            raise ValueError(
                f"ExtraData length {len(value)} exceeds maximum {max_length}"
            )

        # Form single chunk
        if len(value) == 0:
            chunks_root = b"\0" * 32
        else:
            chunk = value + b"\0" * (32 - len(value))  # Pad to 32 bytes
            chunks_root = chunk  # Single chunk, no Merkle tree needed

        # Mix in length
        length_packed = len(value).to_bytes(32, "little")
        return sha256(chunks_root + length_packed).digest()

    else:
        raise ValueError(f"Unsupported basic type: {type_str}")


def merkle_root_byte_list(value: bytes, max_length: int) -> bytes:
    assert len(value) <= max_length
    chunks = [value[i : i + 32] for i in range(0, len(value), 32)]
    if len(chunks[-1]) < 32:
        chunks[-1] += b"\0" * (32 - len(chunks[-1]))
    chunks_root = merkle_root_list(chunks)  # Merkle root of chunks
    length_packed = len(value).to_bytes(32, "little")
    return sha256(chunks_root + length_packed).digest()


# Updated Merkle root for containers
def merkle_root_container(obj: Any, fields: List[tuple]) -> bytes:
    field_roots = []
    for field_name, field_type in fields:
        field_value = getattr(obj, field_name)
        # print(f"field_name: {field_name}, field_type: {field_type}, field_value: {field_value}")
        if field_type in {
            "Fork",
            "BeaconBlockHeader",
            "Eth1Data",
            "ExecutionPayloadHeader",
            "Validator",
        }:
            root = field_value.merkle_root()
        elif field_type.startswith("List["):
            elem_type = field_type.split("[")[1].split(",")[0]
            limit = int(field_type.split(",")[1].strip("]"))
            root = merkle_root_ssz_list(field_value, elem_type, limit)
        elif field_type.startswith("Vector["):
            elem_type = field_type.split("[")[1].split(",")[0]
            limit = int(field_type.split(",")[1].strip("]"))
            root = merkle_root_vector(field_value, elem_type, limit)
        else:
            root = merkle_root_basic(field_value, field_type)
        field_roots.append(root)
    return merkle_root_list(field_roots)


# Helper functions (unchanged)
def merkle_root_element(value: Any, elem_type: str) -> bytes:
    if elem_type in {
        "Fork",
        "BeaconBlockHeader",
        "Eth1Data",
        "ExecutionPayloadHeader",
        "Validator",
    }:
        return value.merkle_root()
    else:
        return merkle_root_basic(value, elem_type)


def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    tree = [leaves]
    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else b"\0" * 32
            parent = sha256(left + right).digest()
            next_level.append(parent)
        tree.append(next_level)
        current = next_level
    return tree


def merkle_root_list(roots: List[bytes]) -> bytes:
    if not roots:
        return b"\0" * 32
    # Pad to next power of two
    n = len(roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)
    return build_merkle_tree(padded)[-1][0]


def merkle_list_tree(roots: List[bytes]) -> bytes:
    if not roots:
        return b"\0" * 32
    # Pad to next power of two
    n = len(roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)
    return build_merkle_tree(padded)


def merkle_root_vector(values: List[Any], elem_type: str, limit: int) -> bytes:
    elements_roots = [merkle_root_element(v, elem_type) for v in values]
    # Pad to the fixed limit
    elements_roots += [b"\0" * 32] * (limit - len(elements_roots))
    return merkle_root_list(elements_roots)


def merkle_root_ssz_list(values: List[Any], elem_type: str, limit: int) -> bytes:
    if not values:
        chunks_root = b"\0" * 32
    else:
        elements_roots = [merkle_root_element(v, elem_type) for v in values]
        chunks_root = merkle_root_list(elements_roots)
    length_packed = len(values).to_bytes(32, "little")
    return sha256(chunks_root + length_packed).digest()


def get_proof(tree: List[List[bytes]], index: int) -> List[bytes]:
    proof = []
    level = 0
    i = index
    while level < len(tree) - 1:
        sibling_i = i ^ 1
        sibling = tree[level][sibling_i] if sibling_i < len(tree[level]) else b"\0" * 32
        proof.append(sibling)
        i //= 2
        level += 1
    return proof


def verify_merkle_proof(
    leaf: bytes, proof: List[bytes], index: int, root: bytes
) -> bool:
    current = leaf
    for sibling in proof:
        if index % 2 == 0:
            current = sha256(current + sibling).digest()  # Leaf is left
        else:
            current = sha256(sibling + current).digest()  # Leaf is right
        index //= 2  # Move up the tree
    return current == root


# Updated generate_merkle_witness
def generate_merkle_witness(
    state_file: str, validator_index: int
) -> tuple[List[bytes], bytes]:
    # Load state as BeaconState instance
    state = load_and_process_state(state_file)

    # reset state root for merkle
    state.latest_block_header.state_root = int(0).to_bytes(32)

    # Compute validator roots
    # validator_roots = [v.merkle_root() for v in state.validators]
    # validators_tree = build_merkle_tree(validator_roots)
    # validators_root = validators_tree[-1][0]
    validators_root = merkle_root_ssz_list(
        state.validators, "Validator", MAX_VALIDATORS
    )
    validators_tree = build_merkle_tree([v.merkle_root() for v in state.validators])
    print(validators_root.hex())

    # Compute state root
    state_root = state.merkle_root()

    # Generate proofs
    proof_list = get_proof(validators_tree, validator_index)

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
        merkle_root_vector(state.block_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
        # Field (5): state_roots
        merkle_root_vector(state.state_roots, "bytes32", SLOTS_PER_HISTORICAL_ROOT),
        # Field (6): eth1_data
        state.eth1_data.merkle_root(),
        # Field (7): eth1_deposit_index
        merkle_root_basic(state.eth1_deposit_index, "uint64"),
        # Field (8): latest_execution_payload_header
        state.latest_execution_payload_header.merkle_root(),
        # Field (9): validators
        validators_root,
        # Field (10): balances
        merkle_root_ssz_list(state.balances, "uint64", MAX_VALIDATORS),
        # Field (11): randao_mixes
        merkle_root_vector(state.randao_mixes, "bytes32", EPOCHS_PER_HISTORICAL_VECTOR),
        # Field (12): next_withdrawal_index
        merkle_root_basic(state.next_withdrawal_index, "uint64"),
        # Field (13): next_withdrawal_validator_index
        merkle_root_basic(state.next_withdrawal_validator_index, "uint64"),
        # Field (14): slashings
        merkle_root_vector(state.slashings, "uint64", EPOCHS_PER_SLASHINGS_VECTOR),
        # Field (15): total_slashing
        merkle_root_basic(state.total_slashing, "uint64"),
    ]
    # Pad to next power of two
    n = len(state_fields)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = state_fields + [b"\0" * 32] * (num_leaves - n)

    proof_state = get_proof(
        build_merkle_tree(padded),
        9,
    )  # validators at index 9

    # Combine proofs
    full_proof = proof_list + proof_state
    return full_proof, state_root


# Example usage
if __name__ == "__main__":
    proof, state_root = generate_merkle_witness("test/data/state.json", 39)
    print("Merkle Witness (hex):")
    for i, h in enumerate(proof):
        print(f"Step {i}: {h.hex()}")
    print(f"State Root: {state_root.hex()}")
