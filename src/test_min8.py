import math
import struct
import json
from hashlib import sha256

# ─────────────────────────────────────────────────────────────────────
# STEP 1: Precompute the zero-subtree hashes (up to 8 zero-leaf subtree)
# ─────────────────────────────────────────────────────────────────────
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())

print("ZERO_HASHES[3] (8-zero-leaf root) = ", ZERO_HASHES[3].hex())
# Must be exactly:
#   0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

# ─────────────────────────────────────────────────────────────────────
# STEP 2: Load and parse balances & randao_mixes from state2.json
# ─────────────────────────────────────────────────────────────────────
with open("test/data/state2.json", "r") as f:
    data = json.load(f)["data"]

# Parse balances correctly as integers
balances = data["balances"]

# Quick sanity‐check prints:
print("balances[0..3] =", balances[0], balances[1], balances[2], balances[3])
print("balances[-1]   =", balances[-1])

# Load randao_mix hex strings
randao_hexes = [x for x in data["randao_mixes"]]

# ─────────────────────────────────────────────────────────────────────
# STEP 3: Build the 552‐byte buffer of 69 × 8 bytes (little‐endian)
# ─────────────────────────────────────────────────────────────────────
buf = b"".join(struct.pack("<Q", b) for b in balances)
print("Buffer length (bytes)   =", len(buf))  # Must be 552
print("Buffer[0:32]            :", buf[0:32].hex())
print("Buffer[-8:]             :", buf[-8:].hex())

# Slice into 32‐byte chunks (18 chunks)
chunks = [buf[i : i + 32] for i in range(0, len(buf), 32)]
if len(chunks[-1]) < 32:
    chunks[-1] = chunks[-1] + b"\x00" * (32 - len(chunks[-1]))

print("Number of 32‐byte chunks:", len(chunks))  # Must be 18
print("chunk[0]                :", chunks[0].hex())
print("chunk[17]               :", chunks[17].hex())

# ─────────────────────────────────────────────────────────────────────
# STEP 4: Merkleize those 18 chunks (pad to 32 leaves) → chunks_root
# ─────────────────────────────────────────────────────────────────────
def merkle_root_list(chunks: list[bytes]) -> bytes:
    if not chunks:
        return b"\x00" * 32
    n = len(chunks)
    k = math.ceil(math.log2(n))
    leaf_count = 1 << k
    padded = chunks + [b"\x00" * 32] * (leaf_count - n)
    layer = padded
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(sha256(layer[i] + layer[i + 1]).digest())
        layer = nxt
    return layer[0]


chunks_root = merkle_root_list(chunks)
print("Chunks root               :", chunks_root.hex())
# Must be:
#   8b3ad9f42d000a261c0870cce9a5a4f2f364ce690694d3b6a2c04e5bc3fdf42b

# ─────────────────────────────────────────────────────────────────────
# STEP 5: Mix in length=69 to get Balances List root
# ─────────────────────────────────────────────────────────────────────
length_bytes = len(balances).to_bytes(32, "little")
balances_list_root = sha256(chunks_root + length_bytes).digest()
print("Balances List root        :", balances_list_root.hex())
# Must be:
#   1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

# ─────────────────────────────────────────────────────────────────────
# STEP 6: Compute the 8-leaf RandaoMix root
# ─────────────────────────────────────────────────────────────────────
randao_leaves = [
    bytes.fromhex(h[2:] if h.startswith("0x") else h) for h in randao_hexes
]
while len(randao_leaves) < 8:
    randao_leaves.append(b"\x00" * 32)
randao_root_8 = merkle_root_list(randao_leaves)
print("Randao 8-leaf root        :", randao_root_8.hex())
# Must be:
#   4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

# ─────────────────────────────────────────────────────────────────────
# STEP 7: Grow 8-leaf Randao to 16-leaf subtree
# ─────────────────────────────────────────────────────────────────────
randao_subtree_root = sha256(randao_root_8 + ZERO_HASHES[3]).digest()
print("Randao 16-leaf root       :", randao_subtree_root.hex())
# Must be:
#   0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

# ─────────────────────────────────────────────────────────────────────
# STEP 8: Final parent = sha256(balances_list_root ∥ randao_subtree_root)
# ─────────────────────────────────────────────────────────────────────
parent = sha256(balances_list_root + randao_subtree_root).digest()
print("Parent combo              :", parent.hex())
# Must be:
#   e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
