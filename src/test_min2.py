import math
from hashlib import sha256

# (1) Precompute zero-subtree hashes up to level 3 (8-leaf subtrees)
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())
# Now ZERO_HASHES[0] = hash of a single zero leaf
#     ZERO_HASHES[1] = root of a 2-leaf zero subtree
#     ZERO_HASHES[2] = root of a 4-leaf zero subtree
#     ZERO_HASHES[3] = root of an 8-leaf zero subtree


def merkle_root_vector(leaves: list[bytes], vector_len: int) -> bytes:
    """
    Merkle root of a fixed Vector:
      • pad leaves to vector_len with zero-leaves,
      • then pad that to next power of two and hash pairwise.
    """
    # pad up to vector_len
    arr = leaves.copy()
    while len(arr) < vector_len:
        arr.append(b"\x00" * 32)
    # pad to next power of two
    n = len(arr)
    k = math.ceil(math.log2(n))
    num_leaves = 1 << k
    arr += [b"\x00" * 32] * (num_leaves - n)
    # build Merkle tree bottom-up
    layer = arr
    while len(layer) > 1:
        nxt = []
        for i in range(0, len(layer), 2):
            nxt.append(sha256(layer[i] + layer[i + 1]).digest())
        layer = nxt
    return layer[0]


# (2) Compute balances_root as Vector[uint64, 69]
def compute_balances_root(balances: list[int]) -> bytes:
    leaves = []
    for bal in balances:
        leaves.append(bal.to_bytes(8, "little") + b"\x00" * 24)
    while len(leaves) < 69:
        leaves.append(b"\x00" * 32)
    return merkle_root_vector(leaves, 69)


# (3) Compute raw 8-leaf randao_root_8 as Vector[bytes32, 8]
def compute_randao_root_8(randao_hexes: list[str]) -> bytes:
    leaves = [bytes.fromhex(h[2:] if h.startswith("0x") else h) for h in randao_hexes]
    while len(leaves) < 8:
        leaves.append(b"\x00" * 32)
    return merkle_root_vector(leaves, 8)


# (4) “Grow” randao_root_8 into a 16-leaf subtree:
def compute_randao_subtree_root(randao_root_8: bytes) -> bytes:
    # pair randao_root_8 (an 8-leaf subtree) with the zero 8-leaf subtree
    return sha256(randao_root_8 + ZERO_HASHES[3]).digest()


# ——————————————————————————————
# Example usage:
# ——————————————————————————————
if __name__ == "__main__":
    import json

    # Load the same state2.json you’ve been using
    with open("test/data/state2.json", "r") as f:
        s = json.load(f)["data"]

    balances = s["balances"]
    randao_raw = s["randao_mixes"]

    # Convert randao → list of hex strings (32 bytes each)
    randao_hexes = [x for x in randao_raw]

    # 1) balances_root:
    balances_root = compute_balances_root(balances)
    print("Balances root:", balances_root.hex())
    # should print:
    # 1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

    # 2) raw 8-leaf randao_root_8:
    randao_root_8 = compute_randao_root_8(randao_hexes)
    print("Randao root 8-leaf:", randao_root_8.hex())
    # should print:
    # 4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

    # 3) grow to 16-leaf subtree:
    randao_subtree_root = compute_randao_subtree_root(randao_root_8)
    print("Randao 16-leaf root  :", randao_subtree_root.hex())
    # should print:
    # 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

    # 4) final parent = sha256(balances_root ∥ randao_subtree_root)
    parent = sha256(balances_root + randao_subtree_root).digest()
    print("Parent combo         :", parent.hex())
    # should print:
    # e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
