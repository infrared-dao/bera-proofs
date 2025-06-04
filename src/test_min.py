import math
from hashlib import sha256

# 1) Precompute zero subtrees (up to 40 levels)
ZERO_HASHES = [b"\x00" * 32]
for _ in range(40):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())


def merkle_root_list_fixed(chunks: list[bytes], limit: int) -> bytes:
    """
    Merkle‐root a list of 32‐byte chunks, exactly out to 'limit' leaves
    (limit must be a power of two). Leaves beyond len(chunks) are zeros.
    """
    n = len(chunks)
    assert (limit & (limit - 1)) == 0, "limit must be a power of two"
    assert n <= limit, f"Too many leaves: {n} > {limit}"

    # Step A: pad the first n chunks up to m = next_pow2(n)
    if n == 0:
        m = 1
    else:
        m = 1 << ((n - 1).bit_length())  # next power of two ≥ n

    # Build bottom‐level nodes
    node_list = []
    for i in range(m):
        if i < n:
            node_list.append(chunks[i])
        else:
            node_list.append(ZERO_HASHES[0])

    # Step B: climb up from m leaves → subtree_root_of_size_m
    levels_m = int(math.log2(m))
    for lvl in range(levels_m):
        next_level = []
        for i in range(0, len(node_list), 2):
            next_level.append(sha256(node_list[i] + node_list[i + 1]).digest())
        node_list = next_level

    subtree_root = node_list[0]  # root over m leaves

    # Step C: keep doubling m → m * 2, hashing (subtree_root || ZERO_HASHES[lvl]) each time,
    # until we reach 'limit'.
    current_size = m
    lvl = levels_m
    while current_size < limit:
        subtree_root = sha256(subtree_root + ZERO_HASHES[lvl]).digest()
        current_size *= 2
        lvl += 1

    return subtree_root


# 2) Balances as SSZ List[uint64, 2^40]
def compute_balances_root(balances: list[int]) -> bytes:
    # 2A) serialize each uint64 → 32‐byte chunk
    chunks = []
    for bal in balances:
        packed = bal.to_bytes(8, "little")  # 8 bytes LE
        padded = packed + b"\x00" * 24  # pad to 32 bytes
        chunks.append(padded)
    # pad to capacity = 2^40
    data_root = merkle_root_list_fixed(chunks, 1 << 40)
    # mix in length
    length_bytes = len(balances).to_bytes(32, "little")
    return sha256(data_root + length_bytes).digest()


# 3) RandaoMixes as SSZ List[Bytes32, 2^16]
def compute_randao_root(randao_hexes: list[str]) -> bytes:
    # 3A) parse each hex → 32 bytes
    chunks = []
    for h in randao_hexes:
        payload = bytes.fromhex(h[2:] if h.startswith("0x") else h)
        assert len(payload) == 32
        chunks.append(payload)
    # pad to capacity = 2^16 = 65536
    data_root = merkle_root_list_fixed(chunks, 1 << 16)
    # mix in length
    length_bytes = len(randao_hexes).to_bytes(32, "little")
    return sha256(data_root + length_bytes).digest()


# ——————————————————————————————————————————————
# Example: load your state2.json and test these two fields
# ——————————————————————————————————————————————

import json

state_path = "test/data/state2.json"
with open(state_path, "r") as f:
    s = json.load(f)["data"]

balances = s["balances"]
randao_raw = s["randao_mixes"]

randao_hexes = [x for x in randao_raw]

bal_root = compute_balances_root(balances)
rand_root = compute_randao_root(randao_hexes)

print("Balances root:", bal_root.hex())
print("Randao root :", rand_root.hex())

# Check the parent = sha256(bal_root ∥ rand_root)
parent = sha256(bal_root + rand_root).digest()
print("Parent combo:", parent.hex())
# Should match Berachain’s sibling (e.g. 'e77e818a42fa...').
