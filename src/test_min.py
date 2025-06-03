import json
import math
from hashlib import sha256

# ------------------------------------------------------------------------------
# 1) COPY IN YOUR EXISTING SSZ HELPERS (or import them if in a module)
# ------------------------------------------------------------------------------


def serialize_uint64_to_32(value: int) -> bytes:
    """uint64 → 8 bytes little‐endian, then pad to 32 bytes."""
    return value.to_bytes(8, "little") + b"\x00" * 24


def merkle_root_vector_uint64_fixed(values: list[int], vector_length: int) -> bytes:
    """
    Compute Merkle root of Vector[uint64, vector_length]:
      • Build exactly `vector_length` 32‐byte leaves (serialize_uint64_to_32).
      • Pad with zero‐leaves up to vector_length.
      • Pad that list to next power of two (e.g. 69→128) with zero‐leaves.
      • Hash up the tree pairwise with sha256(left||right).
    """
    # 1) Build `vector_length` leaves
    leaves: list[bytes] = [serialize_uint64_to_32(v) for v in values]
    leaves += [b"\x00" * 32] * (vector_length - len(leaves))

    # 2) Pad to next power of two
    n = len(leaves)  # now == vector_length
    k = math.ceil(math.log2(n))
    num_leaves = 1 << k
    leaves += [b"\x00" * 32] * (num_leaves - n)

    # 3) Merkle‐tree
    current = leaves
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            nxt.append(sha256(current[i] + current[i + 1]).digest())
        current = nxt
    return current[0]


def merkle_root_vector_bytes32(leaves: list[bytes], vector_length: int) -> bytes:
    """
    Compute Merkle root of Vector[bytes32, vector_length]:
      • Each leaf in `leaves` is already 32 bytes.
      • Pad with zero‐leaves up to vector_length.
      • Pad that list to next power of two (e.g. 8→8, 9→16, etc.) with zero‐leaves.
      • Hash up the tree pairwise with sha256(left||right).
    """
    arr = leaves.copy()
    arr += [b"\x00" * 32] * (vector_length - len(arr))

    n = len(arr)
    k = math.ceil(math.log2(n))
    num_leaves = 1 << k
    arr += [b"\x00" * 32] * (num_leaves - n)

    current = arr
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            nxt.append(sha256(current[i] + current[i + 1]).digest())
        current = nxt
    return current[0]


# ------------------------------------------------------------------------------
# 2) LOAD state2.json AND EXTRACT balances & randao_mixes
# ------------------------------------------------------------------------------

# Replace with the correct relative path to your JSON file:
state_path = "test/data/state2.json"

with open(state_path, "r") as f:
    state_data = json.load(f)["data"]

# balances are strings (hex) or integers in the JSON; convert to Python int list
# randao_mixes are hex strings; convert each to 32‐byte.
balances = state_data["balances"]
randao_raw = state_data["randao_mixes"]

# Convert balances elements (hex) → int
# balances: list[int] = [
#     int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)
#     for x in balances_raw
# ]

# Convert randao_mixes (hex) → bytes32
randao_mixes: list[bytes] = [
    bytes.fromhex(x[2:]) if x.startswith("0x") else bytes.fromhex(x) for x in randao_raw
]

print(f"Loaded {len(balances)} balances and {len(randao_mixes)} randao entries.\n")


# ------------------------------------------------------------------------------
# 3) COMPUTE Berachain‐style roots for those two fields
# ------------------------------------------------------------------------------

# 3a) Balances root as Vector[uint64, 69]:
validator_set_cap = 69  # from Berachain config

balances_root = merkle_root_vector_uint64_fixed(balances, validator_set_cap)
print("Computed balances_root:", balances_root.hex())

# 3b) randao_mixes root as Vector[bytes32, 8]:
epochs_per_historical_vector = 8  # from Berachain config
randao_root = merkle_root_vector_bytes32(randao_mixes, epochs_per_historical_vector)
print("Computed randao_mixes_root:", randao_root.hex())


# ------------------------------------------------------------------------------
# 4) COMPUTE THE PARENT = sha256(balances_root ∥ randao_root)
# ------------------------------------------------------------------------------

parent_hash = sha256(balances_root + randao_root).digest()
print("Combined parent (balances||randao):", parent_hash.hex())

# If you have the Berachain “reference” for this parent (the sibling in level 1 of state),
# compare it below:
expected_parent = "e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e"
print("Expected parent from Berachain:", expected_parent)
print("Match? →", parent_hash.hex() == expected_parent)
