import math
import struct
from hashlib import sha256

# Paste merkle_root_vector exactly here:
def merkle_root_vector(leaves: list[bytes], vector_len: int) -> bytes:
    arr = leaves.copy()
    while len(arr) < vector_len:
        arr.append(b"\x00" * 32)
    n = len(arr)
    k = math.ceil(math.log2(n))
    num_leaves = 1 << k
    arr += [b"\x00" * 32] * (num_leaves - n)
    layer = arr
    while len(layer) > 1:
        next_layer = []
        for i in range(0, len(layer), 2):
            next_layer.append(sha256(layer[i] + layer[i + 1]).digest())
        layer = next_layer
    return layer[0]


# (A) Hard-coded expected balances from state2.json:
expected_balances = [
    500000000000000,
    500000000000000,
    250000000000000,
    250000000000000,
    250000000000000,
    547445850000000,
    500000000000000,
    250000000000000,
    250000000000000,
    250000000000000,
    566533320000000,
    250000000000000,
    250000000000000,
    262500000000000,
    500000000000000,
    250000000000000,
    1166332100000000,
    250000000000000,
    750000000000000,
    750000000000000,
    262475000000000,
    3603496857000000,
    592666660000000,
    250000000000000,
    250000000000000,
    250000000000000,
    250000000000000,
    262475000000000,
    500000000000000,
    250000000000000,
    410000000000000,
    560065099000000,
    250000000000000,
    250000000000000,
    10000000000000000,
    250000000000000,
    250000000000000,
    10000000000000000,
    5000000000000000,
    9790000000000000,
    10000000000000000,
    10000000000000,
    10000000000000000,
    10000000000000000,
    5830000000000000,
    8550000000000000,
    3841259006528675,
    10000000000000000,
    10000000000000000,
    10000000000000000,
    3766657000000000,
    8938523570000000,
    797737774661999,
    475284694300000,
    8029997000000000,
    5328261000000000,
    831667080000000,
    2022498989400000,
    10000000000000000,
    10000000000000000,
    10000000000000000,
    666663989399894,
    10000000000000000,
    10000000000000,
    10000000000000,
    2350000000000000,
    10000000000000,
    5934426930679472,
    997000000000000,
]

# (B) Build 69 leaves of 32 bytes each:
leaves = []
for bal in expected_balances:
    # (i) 8-byte little-endian
    packed = struct.pack("<Q", bal)
    # (ii) pad to 32 bytes
    leaf = packed + b"\x00" * 24
    leaves.append(leaf)

# (C) Compute the Merkle root as Vector[uint64, 69]:
balances_root = merkle_root_vector(leaves, 69)
print("Computed balances_root:", balances_root.hex())

# It MUST print exactly:
#   1b81e0b4a423109d788d9c57f95de87f83def9b7da2101a97562701d8a7ca57a

# (D) Now test RandaoMixes → 8→root and 16→subtree root
randao_hexes = [
    "970f4e852916ed31b95239de091029f83e86ba5359e2345691e70dc87bb109d6",
    "bc82b96e84829ffd3a0e790225b6594384740dcdea41ed42ce96af68cbb76b71",
    "9acedf527f50725cd9f2bfe400a0c859ac8b2975f0e7a55801a8f5cc9178e7b1",
    "aa3b19dd65d9f8348de6f5c28fa9e954e673c79f03e77d38082bcfa0df83293b",
    "d570ee0d2fa7174de211298b3ed60c80a6c9905f9955bf7f0e3ef3335fb8e026",
    "8ef9de00a9dcf36918147c87be4e3f970f26c3b786ae38bb7e41d17722ccd8c1",
    "7742784e94df30f1190d885fcac0b2954e02867f7181de4495890fc4c9749caa",
    "b31c73df03727b66274e077a07e280b1c920c0dc846fc721ba4a6de0d7ae18ee",
]

# (i) Build 8 leaves (each exactly 32 bytes):
rand_leaves = [bytes.fromhex(h[2:] if h.startswith("0x") else h) for h in randao_hexes]
# (ii) Merkleize as Vector[bytes32,8]:
randao_root_8 = merkle_root_vector(rand_leaves, 8)
print("Randao root 8-leaf:", randao_root_8.hex())
# should be: 4c1394e7bb95932f48b57d79bb6dcf2ed92ed72d42db22acbd3f2dc8af184b10

# (iii) Grow 8→root to 16→subtree:
#      precompute ZERO_HASHES[3] = root of 8 zero leaves:
ZERO_HASHES = [b"\x00" * 32]
for _ in range(3):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())
randao_subtree_root = sha256(randao_root_8 + ZERO_HASHES[3]).digest()
print("Randao 16-leaf root:", randao_subtree_root.hex())
# should be: 0199f309f6b682477eabf73f37a509f09adb3b6909c9b8ec58db85b79fd4a0ff

# (E) Final parent = sha256(balances_root ∥ randao_subtree_root)
parent = sha256(balances_root + randao_subtree_root).digest()
print("Parent combo:", parent.hex())
# should be: e77e818a42faeab9d38056fd218bd82bc9a9b145010a22cf8106eebb8a3fac3e
