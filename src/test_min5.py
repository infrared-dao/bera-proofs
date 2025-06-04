import math
import struct
import json
from hashlib import sha256

# ——————————————————————————————————————————————————————————————
# 1) Precompute ZERO_HASHES up through level 3 (8 zero leaves → 16 total)
# ——————————————————————————————————————————————————————————————
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())
# Now ZERO_HASHES[3] is the root of an 8-leaf all-zero subtree:
#    ZERO_HASHES[3].hex() → "0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff"


# ——————————————————————————————————————————————————————————————
# 2) Generic helper: Merkleize a list of 32-byte chunks (pad to next power of 2)
# ——————————————————————————————————————————————————————————————
def merkle_root_list(chunks: list[bytes]) -> bytes:
    """
    Given 32-byte chunks (length N), pad to next power of two with zero-chunks,
    then hash bottom-up with sha256(left||right). Returns a single 32-byte root.
    """
    if not chunks:
        return b"\x00" * 32
    n = len(chunks)
    k = math.ceil(math.log2(n))
    leaf_count = 1 << k
    padded = chunks + [b"\x00" * 32] * (leaf_count - n)
    layer = padded
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(sha256(layer[i] + layer[i + 1]).digest())
        layer = next_layer
    return layer[0]


# ——————————————————————————————————————————————————————————————
# 3) Compute SSZ List[uint64, 69] “balances” root
# ——————————————————————————————————————————————————————————————
def compute_balances_list_root(balances: list[int]) -> bytes:
    """
    Treat `balances` as an SSZ List[uint64, 69]:
      • Step 1: Serialize all 69 balances (8 bytes LE each) into one buffer (552 bytes).
      • Step 2: Break that 552 bytes into 32-byte chunks (18 chunks), pad last to 32.
      • Step 3: Merkleize those 18 chunks → chunks_root.
      • Step 4: Mix in length=69 via sha256(chunks_root ∥ (69 as 32-byte LE)).
    """
    # (A) Step 1: build a single serialized buffer of 69×8 bytes
    buf = b"".join(struct.pack("<Q", b) for b in balances)  # 552 bytes total

    # (B) Step 2: slice into 32-byte chunks, pad the last chunk
    chunks = [buf[i : i + 32] for i in range(0, len(buf), 32)]
    if len(chunks[-1]) < 32:
        chunks[-1] = chunks[-1] + b"\x00" * (32 - len(chunks[-1]))
    # Now len(chunks) == 18

    # (C) Step 3: Merkleize those 18 chunks
    chunks_root = merkle_root_list(chunks)

    # (D) Step 4: mix in length=69 as 32-byte LE
    length_bytes = len(balances).to_bytes(32, "little")  # 32-byte little endian
    return sha256(chunks_root + length_bytes).digest()


# ——————————————————————————————————————————————————————————————
# 4) Compute raw 8-leaf “randao” root as Vector[bytes32, 8]
# ——————————————————————————————————————————————————————————————
def compute_randao_root_8(randao_hexes: list[str]) -> bytes:
    """
    Treat `randao_hexes` as exactly 8 hex strings → 32 bytes each. If fewer, pad with zeros.
    Then Merkleize those 8 32-byte leaves (8 is already a power of two).
    """
    leaves = [bytes.fromhex(h[2:] if h.startswith("0x") else h) for h in randao_hexes]
    while len(leaves) < 8:
        leaves.append(b"\x00" * 32)
    return merkle_root_list(leaves)


# ——————————————————————————————————————————————————————————————
# 5) Grow 8-leaf “randao_root_8” into a 16-leaf subtree
# ——————————————————————————————————————————————————————————————
def compute_randao_subtree_root(randao_root_8: bytes) -> bytes:
    """
    Pair the 8-leaf real subtree with the 8-leaf all-zero subtree (ZERO_HASHES[3]),
    then do one sha256 to get the 16-leaf subtree root.
    """
    return sha256(randao_root_8 + ZERO_HASHES[3]).digest()


# ——————————————————————————————————————————————————————————————
# 6) Load state2.json and run everything
# ——————————————————————————————————————————————————————————————
if __name__ == "__main__":
    with open("test/data/state2.json", "r") as f:
        data = json.load(f)["data"]

    # (i) Parse balances (69 entries) from hex → int
    balances = data["balances"]

    # (ii) Parse 8 randao_mixes (hex strings)
    randao_hexes = [x for x in data["randao_mixes"]]

    # ——————————————————————————————————————————————
    # A) Compute SSZ List[uint64, 69] balances root
    # ——————————————————————————————————————————————
    balances_list_root = compute_balances_list_root(balances)
    print("Balances List root:", balances_list_root.hex())
    # → MUST be: 1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

    # ——————————————————————————————————————————————
    # B) Compute raw 8-leaf randao root (Vector[bytes32, 8])
    # ——————————————————————————————————————————————
    randao_root_8 = compute_randao_root_8(randao_hexes)
    print("Randao 8-leaf root:", randao_root_8.hex())
    # → MUST be: 4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

    # ——————————————————————————————————————————————
    # C) Grow 8-leaf randao → 16-leaf subtree
    # ——————————————————————————————————————————————
    randao_subtree_root = compute_randao_subtree_root(randao_root_8)
    print("Randao 16-leaf root:", randao_subtree_root.hex())
    # → MUST be: 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

    # ——————————————————————————————————————————————
    # D) Combine balances_list_root ∥ randao_subtree_root
    # ——————————————————————————————————————————————
    parent = sha256(balances_list_root + randao_subtree_root).digest()
    print("Parent combo       :", parent.hex())
    # → MUST be: e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
