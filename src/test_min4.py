import math
from hashlib import sha256
import struct

# —————————————————————————————————————————————————
# 1) Precompute “zero‐subtree” hashes for up to 3 levels (8→16)
# —————————————————————————————————————————————————
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())
# ZERO_HASHES[3] is the root of an 8‐leaf all‐zero subtree.


# —————————————————————————————————————————————————
# 2) SSZ List[uint64, 69] ⇒ “pad to next pow2 of 69” ⇒ mix length
# —————————————————————————————————————————————————
def merkle_root_list(chunks: list[bytes]) -> bytes:
    """
    Given a list of 32-byte chunks (length N), pad out to the next power of two
    with zero‐chunks, then Merkle‐hash bottom‐up.
    """
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


def compute_balances_list_root(balances: list[int]) -> bytes:
    """
    Treat `balances` as an SSZ List[uint64, 69]:
      1) Serialize each uint64 to 8 bytes LE, then pad to 32 bytes → chunk.
      2) Merkleize those M chunks by padding to next power of two → chunks_root.
      3) Mix in length M by doing sha256(chunks_root ∥ (M as 32‐byte LE)).
      That produces the SSZ List root.
    """
    # (A) Step 1: Build exactly M = len(balances) chunks of 32 bytes
    chunks = []
    for b in balances:
        # 8-byte little endian, then pad to 32 bytes
        leaf = b.to_bytes(8, "little") + b"\x00" * 24
        chunks.append(leaf)

    # (B) Step 2: Merkleize M chunks (pad to next power of two)
    chunks_root = merkle_root_list(chunks)

    # (C) Step 3: Mix in M (number of balances) as a 32‐byte little‐endian integer
    length_bytes = len(balances).to_bytes(32, "little")
    return sha256(chunks_root + length_bytes).digest()


# —————————————————————————————————————————————————
# 3) “Raw” 8‐leaf Merkle root of randao_mixes (Vector[bytes32, 8])
# —————————————————————————————————————————————————
def compute_randao_root_8(randao_hexes: list[str]) -> bytes:
    """
    Treat `randao_hexes` as exactly 8 bytes32 values. Pad to 8 if fewer.
    Then Merkleize those 8 leaves (8 is already a power of two).
    """
    leaves = []
    for h in randao_hexes:
        b32 = bytes.fromhex(h[2:] if h.startswith("0x") else h)
        leaves.append(b32)
    while len(leaves) < 8:
        leaves.append(b"\x00" * 32)
    return merkle_root_list(leaves)  # 8 → root


# —————————————————————————————————————————————————
# 4) Grow that 8‐leaf randao_root to a 16‐leaf subtree
# —————————————————————————————————————————————————
def compute_randao_subtree_root(randao_root_8: bytes) -> bytes:
    """
    Given randao_root_8 = Merkle root of 8 real leaves,
    pair it with an 8‐leaf all‐zero sibling (ZERO_HASHES[3]) to get
    the 16‐leaf subtree root.
    """
    return sha256(randao_root_8 + ZERO_HASHES[3]).digest()


# ——————————————————————————————————————————————
# 5) Put it all together on real Berachain data
# ——————————————————————————————————————————————
if __name__ == "__main__":
    import json

    # Load the same state2.json you’ve been using
    with open("test/data/state2.json", "r") as f:
        s = json.load(f)["data"]

    # Extract & parse the 69 Balances (hex → int)
    balances = s["balances"]

    # Extract the 8 RandaoMix entries (hex strings)
    randao_raw = s["randao_mixes"]
    randao_hexes = [x for x in randao_raw]

    # 1) Compute SSZ List root of Balances (should be 1b81e0b…)
    balances_list_root = compute_balances_list_root(balances)
    print("Balances List root:", balances_list_root.hex())
    # → 1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

    # 2) Compute raw 8-leaf randao root (should be 4c13…)
    randao_root_8 = compute_randao_root_8(randao_hexes)
    print("Randao 8-leaf root:", randao_root_8.hex())
    # → 4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

    # 3) Grow to 16-leaf subtree (should be 0199…)
    randao_subtree_root = compute_randao_subtree_root(randao_root_8)
    print("Randao 16-leaf root:", randao_subtree_root.hex())
    # → 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

    # 4) Final parent = sha256(balances_list_root ∥ randao_subtree_root)
    parent = sha256(balances_list_root + randao_subtree_root).digest()
    print("Parent combo       :", parent.hex())
    # → e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
