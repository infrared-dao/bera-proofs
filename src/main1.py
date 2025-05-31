import json
import re
from sha3 import sha3_256
from typing import List, Dict, Any
import math

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


# Function to recursively convert keys and adjust data formats
def process_json_data(data: Any) -> Any:
    if isinstance(data, dict):
        new_dict = {}
        for key, value in data.items():
            new_key = camel_to_snake(key)
            if new_key == "parent_block_root":
                new_key = "parent_root"
            new_value = process_json_data(value)

            # Handle specific field conversions based on expected type
            if new_key in {
                "pubkey",
                "withdrawal_credentials",
                "genesis_validators_root",
                "parent_block_root",
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
            }:
                if isinstance(new_value, str) and new_value.startswith("0x"):
                    new_value = bytes.fromhex(new_value[2:])
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
                "base_fee_per_gas",
                "blob_gas_used",
                "excess_blob_gas",
                "next_withdrawal_validator_index",
            }:
                if isinstance(new_value, str):
                    new_value = (
                        int(new_value, 16)
                        if new_value.startswith("0x")
                        else int(new_value)
                    )

            new_dict[new_key] = new_value
        return new_dict
    elif isinstance(data, list):
        return [process_json_data(item) for item in data]
    else:
        return data


# Example function to load and process the state file
def load_and_process_state(state_file: str) -> dict:
    with open(state_file, "r") as f:
        state = json.load(f)["data"]
    return process_json_data(state)


def get_element_type(field_type):
    if field_type.startswith(("List[", "Vector[")):
        # Extract the part between '[' and ','
        return field_type.split("[")[1].split(",")[0].strip()
    return field_type  # For non-list types, return as is


# Define Merkle root computation for basic types
def merkle_root_basic(value: Any, type_str: str) -> bytes:
    # print(f"type_str: {type_str}, value: {value}")
    # Convert hex string to bytes for 'bytes*' types
    if type_str.startswith("bytes") and isinstance(value, str):
        if value.startswith("0x"):
            value = bytes.fromhex(value[2:])  # Remove '0x' prefix and convert
        else:
            value = bytes.fromhex(value)  # Assume hex string without prefix
    if type_str == "bytes32":
        return serialize_bytes(value, 32)
    elif type_str == "uint64":
        serialized = serialize_uint64(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return sha3_256(padded).digest()
    elif type_str == "uint256":
        serialized = serialize_uint256(value)
        return sha3_256(serialized).digest()
    elif type_str == "Boolean":
        serialized = serialize_bool(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return sha3_256(padded).digest()
    elif type_str == "bytes48":
        chunk1 = value[0:32]
        chunk2 = value[32:48] + b"\0" * 16
        return sha3_256(chunk1 + chunk2).digest()
    elif type_str == "bytes20":
        serialized = serialize_bytes(value, 20)
        padded = serialized + b"\0" * (32 - len(serialized))
        return sha3_256(padded).digest()
    elif type_str == "bytes256":
        chunks = [value[i : i + 32] for i in range(0, 256, 32)]
        return merkle_root_list(chunks)
    elif type_str == "bytes4":
        serialized = serialize_bytes(value, 4)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded
    elif type_str == "bytes":
        # Split into 32-byte chunks
        chunks = [value[i : i + 32] for i in range(0, len(value), 32)]
        if len(chunks) == 0:
            chunks_root = b"\0" * 32  # Empty bytes case
        else:
            # Pad the last chunk if necessary
            if len(chunks[-1]) < 32:
                chunks[-1] += b"\0" * (32 - len(chunks[-1]))
            # Compute hash of each chunk
            chunk_hashes = [sha3_256(chunk).digest() for chunk in chunks]
            # Compute Merkle root of the chunk hashes
            chunks_root = merkle_root_list(chunk_hashes)
        # Pack the length as 32-byte little-endian
        length_packed = len(value).to_bytes(32, "little")
        # Hash the chunks root with the length
        return sha3_256(chunks_root + length_packed).digest()
    else:
        raise ValueError(f"Unsupported basic type: {type_str}")


# Define container field types
CONTAINER_TYPES = {
    "Fork": [
        ("previous_version", "bytes4"),
        ("current_version", "bytes4"),
        ("epoch", "uint64"),
    ],
    "BeaconBlockHeader": [
        ("slot", "uint64"),
        ("proposer_index", "uint64"),
        ("parent_root", "bytes32"),
        ("state_root", "bytes32"),
        ("body_root", "bytes32"),
    ],
    "Eth1Data": [
        ("deposit_root", "bytes32"),
        ("deposit_count", "uint64"),
        ("block_hash", "bytes32"),
    ],
    "ExecutionPayloadHeader": [
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
    ],
    "Validator": [
        ("pubkey", "bytes48"),
        ("withdrawal_credentials", "bytes32"),
        ("effective_balance", "uint64"),
        ("slashed", "Boolean"),
        ("activation_eligibility_epoch", "uint64"),
        ("activation_epoch", "uint64"),
        ("exit_epoch", "uint64"),
        ("withdrawable_epoch", "uint64"),
    ],
    "BeaconState": [
        ("genesis_validators_root", "bytes32"),
        ("slot", "uint64"),
        ("fork", "Fork"),
        ("latest_block_header", "BeaconBlockHeader"),
        ("block_roots", "Vector[bytes32, 8]"),
        ("state_roots", "Vector[bytes32, 8]"),
        ("eth1_data", "Eth1Data"),
        ("eth1_deposit_index", "uint64"),
        ("latest_execution_payload_header", "ExecutionPayloadHeader"),
        ("validators", "List[Validator, 1099511627776]"),
        ("balances", "List[uint64, 1099511627776]"),
        ("randao_mixes", "Vector[bytes32, 8]"),
        ("next_withdrawal_index", "uint64"),
        ("next_withdrawal_validator_index", "uint64"),
        ("slashings", "Vector[uint64, 8]"),
        ("total_slashing", "uint64"),
    ],
}


def handle_missing_fields(data: dict) -> tuple:
    """
    Handles missing fields in a data dictionary by assigning default values.

    Args:
        data (dict): The input data dictionary containing (or missing) the fields.

    Returns:
        tuple: (next_withdrawal_index, slashings, total_slashing) with defaults applied.
    """
    # Handle next_withdrawal_index
    next_withdrawal_index_value = data.get("next_withdrawal_index", 0)
    try:
        next_withdrawal_index = int(next_withdrawal_index_value)
    except (ValueError, TypeError):
        next_withdrawal_index = 0  # Use 0 if conversion fails

    # Handle slashings
    slashings_value = data.get("slashings", [])
    if not isinstance(slashings_value, list):
        slashings = []  # Use empty list if not a list
    else:
        slashings = slashings_value

    # Handle total_slashing
    total_slashing_value = data.get("total_slashing", 0)
    try:
        total_slashing = int(total_slashing_value)
    except (ValueError, TypeError):
        total_slashing = 0  # Use 0 if conversion fails

    return next_withdrawal_index, slashings, total_slashing


# Compute Merkle root for containers
def merkle_root_container(data: Dict[str, Any], type_name: str) -> bytes:
    # print(f"Type: {type_name}, Data: {data}")
    fields = CONTAINER_TYPES[type_name]
    field_roots = []
    for field_name, field_type in fields:
        field_value = data[field_name]
        # print(f"field_name: {field_name}, field_type: {field_type}, field_value: {field_value}")
        if field_type in CONTAINER_TYPES:
            root = merkle_root_container(field_value, field_type)
        # elif field_type.startswith('Vector[') or field_type.startswith('List['):
        #     # Extract element type and limit
        #     parts = field_type.split('[')
        #     elem_type = parts[1].split(',')[0]
        #     root = merkle_root_list([merkle_root_element(v, elem_type) for v in field_value])
        elif field_type.startswith("List["):
            elem_type = field_type.split("[")[1].split(",")[0]
            root = merkle_root_ssz_list(field_value, elem_type)
        elif field_type.startswith("Vector["):
            elem_type = field_type.split("[")[1].split(",")[0]
            root = merkle_root_list(
                [merkle_root_element(v, elem_type) for v in field_value]
            )
        else:
            root = merkle_root_basic(field_value, field_type)
        field_roots.append(root)
    return merkle_root_list(field_roots)


# Compute Merkle root for list/vector elements
def merkle_root_element(value: Any, elem_type: str) -> bytes:
    if elem_type in CONTAINER_TYPES:
        return merkle_root_container(value, elem_type)
    else:
        return merkle_root_basic(value, elem_type)


# Build Merkle root for a list of roots
def merkle_root_list(roots: List[bytes]) -> bytes:
    if not roots:
        return b"\0" * 32
    n = len(roots)
    # Pad to next power of two
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)
    return build_merkle_tree(padded)[-1][0]


# Build Merkle tree and return all levels
def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    tree = [leaves]
    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else b"\0" * 32
            parent = sha3_256(left + right).digest()
            next_level.append(parent)
        tree.append(next_level)
        current = next_level
    return tree


def merkle_root_ssz_list(values: List[Any], elem_type: str) -> bytes:
    elements_roots = [merkle_root_element(v, elem_type) for v in values]
    elements_root = merkle_root_list(elements_roots)
    length_packed = len(values).to_bytes(32, "little")
    return sha3_256(elements_root + length_packed).digest()


# Generate Merkle proof for a leaf at index
def get_proof(tree: List[List[bytes]], index: int) -> List[bytes]:
    proof = []
    level = 0
    i = index
    while level < len(tree) - 1:
        sibling_i = i ^ 1  # XOR to get sibling index
        sibling = tree[level][sibling_i] if sibling_i < len(tree[level]) else b"\0" * 32
        proof.append(sibling)
        i //= 2
        level += 1
    return proof


# Main function to generate Merkle witness
def generate_merkle_witness(state_file: str, validator_index: int) -> List[bytes]:
    # Load state from JSON
    state = load_and_process_state(state_file)
    next_idx, slashes, total = handle_missing_fields(state)
    state.update(
        {
            "next_withdrawal_index": next_idx,
            "slashings": slashes,
            "total_slashing": total,
        }
    )

    # Compute validator roots
    validator_roots = [
        merkle_root_container(v, "Validator") for v in state["validators"]
    ]
    validators_tree = build_merkle_tree(validator_roots)
    validators_root = validators_tree[-1][0]
    print(validators_root)

    # # Compute all field roots for BeaconState
    # field_roots = []
    # for field_name, field_type in CONTAINER_TYPES['BeaconState']:
    #     value = state[field_name]
    #     if field_type in CONTAINER_TYPES:
    #         root = merkle_root_container(value, field_type)
    #     elif field_type.startswith('Vector[') or field_type.startswith('List['):
    #         parts = field_type.split('[')
    #         elem_type = parts[1].split(',')[0]
    #         if field_name == 'validators':
    #             root = validators_root
    #         else:
    #             root = merkle_root_list([merkle_root_element(v, elem_type) for v in value])
    #     else:
    #         root = merkle_root_basic(value, field_type)
    #     field_roots.append(root)

    field_roots = [
        merkle_root_container(
            {fn: state[fn] for fn, _ in CONTAINER_TYPES["BeaconState"]}, "BeaconState"
        )
        if ft in CONTAINER_TYPES
        else merkle_root_ssz_list(state[fn], ft.split("[")[1].split(",")[0])
        if ft.startswith("List[")
        else merkle_root_list(
            [merkle_root_element(v, ft.split("[")[1].split(",")[0]) for v in state[fn]]
        )
        if ft.startswith("Vector[")
        else merkle_root_basic(state[fn], ft)
        for fn, ft in CONTAINER_TYPES["BeaconState"]
    ]

    # Build state tree
    state_tree = build_merkle_tree(field_roots)
    state_root = state_tree[-1][0]

    # Generate proofs
    proof_list = get_proof(validators_tree, validator_index)
    proof_state = get_proof(state_tree, 9)  # 'validators' is at index 9

    # Combine proofs
    full_proof = proof_list + proof_state
    return full_proof, state_root


# Example usage
if __name__ == "__main__":
    # Assume state.json is the input file
    proof, state_root = generate_merkle_witness("test/data/state.json", 39)
    print("Merkle Witness (hex):")
    for i, h in enumerate(proof):
        print(f"Step {i}: {h.hex()}")
    print(f"State Root: {state_root.hex()}")
