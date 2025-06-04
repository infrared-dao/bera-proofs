import math
import struct
import json
from hashlib import sha256

# ──────── STEP 1: Precompute ZERO_HASHES up to 8‐leaf zero subtree ────────
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())

print("ZERO_HASHES[3] (8-zero-leaf root) =", ZERO_HASHES[3].hex())
# Should be: 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

# ──────── STEP 2: Load balances & randao_mixes from state2.json ────────
with open("test/data/state2.json", "r") as f:
    data = json.load(f)["data"]

balances = [
    int(x, 16) if isinstance(x, str) and x.startswith("0x") else int(x)
    for x in data["balances"]
]
randao_hexes = [x for x in data["randao_mixes"]]

# ──────── STEP 3: Build 552-byte buffer of 69*8 bytes ────────
buf = b"".join(struct.pack("<Q", b) for b in balances)
print("1) Total buffer length:", len(buf), "bytes")  # → 552

first32 = buf[0:32]
last8 = buf[544:552]
print("2) First 32 bytes (chunk 0)   :", first32.hex())
print("3) Last  8 bytes of buffer     :", last8.hex())

# ──────── STEP 4: Slice into 18 chunks of 32 bytes ────────
chunks = [buf[i : i + 32] for i in range(0, len(buf), 32)]
if len(chunks[-1]) < 32:
    chunks[-1] = chunks[-1] + b"\x00" * (32 - len(chunks[-1]))

print("4) Number of chunks (should be 18):", len(chunks))
print("   chunk[0]  :", chunks[0].hex())
print("   chunk[17] :", chunks[17].hex())

# ──────── STEP 5: Merkle‐root those 18 chunks ────────
def merkle_root_list(chunks: list[bytes]) -> bytes:
    if not chunks:
        return b"\x00" * 32
    n = len(chunks)
    k = math.ceil(math.log2(n))
    leaf_count = 1 << k
    padded = chunks + [b"\x00" * 32] * (leaf_count - n)
    layer = padded
    while len(layer) > 1:
        next_level = []
        for i in range(0, len(layer), 2):
            next_level.append(sha256(layer[i] + layer[i + 1]).digest())
        layer = next_level
    return layer[0]


chunks_root = merkle_root_list(chunks)
print("5) Chunks root:", chunks_root.hex())
# Should be: 8b3ad9f42d000a261c0870cce9a5a4f2f364ce690694d3b6a2c04e5bc3fdf42b

# ──────── STEP 6: Mix in length=69 to get Balances List root ────────
length_bytes = len(balances).to_bytes(32, "little")
balances_list_root = sha256(chunks_root + length_bytes).digest()
print("6) Balances List root:", balances_list_root.hex())
# Should be: 1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

# ──────── STEP 7: Compute Randao 8-leaf root ────────
randao_leaves = [
    bytes.fromhex(h[2:] if h.startswith("0x") else h) for h in randao_hexes
]
while len(randao_leaves) < 8:
    randao_leaves.append(b"\x00" * 32)
randao_root_8 = merkle_root_list(randao_leaves)
print("7) Randao 8-leaf root:", randao_root_8.hex())
# Should be: 4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

# ──────── STEP 8: Grow to 16-leaf randao subtree ────────
randao_subtree_root = sha256(randao_root_8 + ZERO_HASHES[3]).digest()
print("8) Randao 16-leaf root:", randao_subtree_root.hex())
# Should be: 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

# ──────── STEP 9: Final parent = sha256(balances_list_root ∥ randao_subtree_root) ────────
parent = sha256(balances_list_root + randao_subtree_root).digest()
print("9) Parent combo       :", parent.hex())
# Should be: e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
