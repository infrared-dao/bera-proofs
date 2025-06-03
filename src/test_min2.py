import json
import math
from hashlib import sha256

# —————————————————————————————————————————————————
# (1) Helpers from your existing SSZ code
# —————————————————————————————————————————————————


def serialize_uint64_to_32(value: int) -> bytes:
    """uint64 → 8 little-endian bytes, padded to 32."""
    return value.to_bytes(8, "little") + b"\x00" * 24


def merkle_root_list(roots: list[bytes]) -> bytes:
    """Merkle over 32-byte leaves—pad to next power of two."""
    if not roots:
        return b"\x00" * 32
    n = len(roots)
    k = math.ceil(math.log2(n))
    num_leaves = 1 << k
    padded = roots + [b"\x00" * 32] * (num_leaves - n)
    current = padded
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            nxt.append(sha256(current[i] + current[i + 1]).digest())
        current = nxt
    return current[0]


def merkle_root_vector_uint64_list(values: list[int], list_length: int) -> bytes:
    """
    Treat `values` as an SSZ List[uint64, list_length]:
      1. Build exactly list_length leaves (serialize_uint64_to_32).
      2. Merklize those leaves to get chunks_root (pad to next power of two).
      3. Mix in length = list_length via sha256(chunks_root || length_bytes).
    """
    # (a) Build exactly `list_length` leaves
    leaves = [serialize_uint64_to_32(v) for v in values]
    leaves += [b"\x00" * 32] * (list_length - len(leaves))
    # (b) Merklize them:
    chunks_root = merkle_root_list(leaves)
    # (c) Mix in length:
    length_bytes = list_length.to_bytes(32, "little")
    return sha256(chunks_root + length_bytes).digest()


def merkle_root_vector_bytes32(leaves: list[bytes], vector_length: int) -> bytes:
    """
    Treat `leaves` as Vector[bytes32, vector_length]:
      1. Pad to vector_length.
      2. Pad to next power of two.
      3. Merklize pairwise.
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


# —————————————————————————————————————————————————
# (2) Zero-subtree hashes up to 4 levels (for “grow to 16 leaves”)
# —————————————————————————————————————————————————

ZERO = [b"\x00" * 32]
for _ in range(4):
    ZERO.append(sha256(ZERO[-1] + ZERO[-1]).digest())
# Now ZERO[i] = root of a 2^i-leaf all-zero subtree.
# We will need up to level=4, since 16 = 2^4.

# —————————————————————————————————————————————————
# (3) Load state2.json and extract balances & randao_mixes
# —————————————————————————————————————————————————

state_path = "test/data/state2.json"  # adjust as needed
with open(state_path, "r") as f:
    data = json.load(f)["data"]

# Convert balances (hex strings) → int list
balances_raw = data["balances"]
balances = [
    int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)
    for x in balances_raw
]

# Convert randao_mixes (hex) → bytes32 list
randao_raw = data["randao_mixes"]
randao_mixes = [bytes.fromhex(x[2:] if x.startswith("0x") else x) for x in randao_raw]

# Sanity
assert len(balances) == 69
assert len(randao_mixes) == 8

# —————————————————————————————————————————————————
# (4) Compute balances_list_root as SSZ List[uint64, 69]
# —————————————————————————————————————————————————

validator_set_cap = 69
balances_list_root = merkle_root_vector_uint64_list(balances, validator_set_cap)
print("balances_list_root:", balances_list_root.hex())

# —————————————————————————————————————————————————
# (5) Compute the “raw” 8→root for randao_mixes
# —————————————————————————————————————————————————

randao_root_8 = merkle_root_vector_bytes32(randao_mixes, 8)
print("randao_root_8  :", randao_root_8.hex())

# —————————————————————————————————————————————————
# (6) “Grow” that 8→root into a 16-leaf padded subtree
#     (i.e. treat the 8th-leaf position upward as ZERO)
# —————————————————————————————————————————————————

# Level 0 of this “randao subtree”: [randao_root_8,  ZERO[0],  ZERO[0],  ZERO[0], ... x 8]
# Actually, we only need to combine up 4 levels in total:
#
#   level 0 (2 leaves):   H(randao_root_8  ∥ ZERO[0])
#   level 1 (4 leaves):   H( H(...) ∥ ZERO[1] )
#   level 2 (8 leaves):   H( H(...) ∥ ZERO[2] )
#   level 3 (16 leaves):  H( H(...) ∥ ZERO[3] )   ← final “randao_subtree_root”
#
# (Because 2^4 = 16, and we only had 1 real value at index 0 of that 16-leaf tree.)

# r = randao_root_8
# for lvl in range(4):
#     r = sha256(r + ZERO[lvl]).digest()

randao_subtree_root = sha256(randao_root_8 + ZERO[3]).digest()
print("randao_subtree_root (16-leaf):", randao_subtree_root.hex())

# —————————————————————————————————————————————————
# (7) Finally combine (balances_list_root ∥ randao_subtree_root)
# —————————————————————————————————————————————————

combined = sha256(balances_list_root + randao_subtree_root).digest()
print("Combined parent (balances||randao_subtree):", combined.hex())

# —————————————————————————————————————————————————
# (8) Compare to Berachain’s expected sibling
# —————————————————————————————————————————————————

expected = "e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e"
print("Expected from Berachain:", expected)
print("Match? →", combined.hex() == expected)
