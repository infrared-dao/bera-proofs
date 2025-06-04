from hashlib import sha256
import math

ZERO_HASHES = [b"\x00" * 32]
for _ in range(40):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())


def _pad_to_power_of_two(chunks):
    """Pad a list of 32-byte chunks to a power-of-two length with zero chunks."""
    n = len(chunks)
    if n == 0:
        return [b"\x00" * 32]
    # Next power-of-two ≥ n
    m = 1 << (n - 1).bit_length()
    return chunks + [b"\x00" * 32] * (m - n)


def merkle_root_from_chunks(chunks):
    """Compute Merkle root (SHA-256) of a list of 32-byte chunks."""
    chunks = _pad_to_power_of_two(chunks)
    while len(chunks) > 1:
        paired = []
        for i in range(0, len(chunks), 2):
            left, right = chunks[i], chunks[i + 1]
            paired.append(sha256(left + right).digest())
        chunks = paired
    return chunks[0]


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


def pack_vector_uint64(values, vector_length):
    """SSZ-pack a list of uint64 (little-endian) into 32-byte chunks for a fixed-length vector."""
    # Pad the list to fixed length with zeros
    vals = list(values) + [0] * (vector_length - len(values))
    # Serialize to little-endian bytes
    data = b"".join(v.to_bytes(8, "little") for v in vals)
    # Right-pad to 32-byte multiple
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    # Split into 32-byte chunks
    return [data[i : i + 32] for i in range(0, len(data), 32)]


def pack_vector_bytes32(values, vector_length):
    """SSZ-pack a list of 32-byte items (given as bytes or hex strings) into 32-byte chunks."""
    # Pad the list to fixed length with zero-bytes32
    vals = list(values) + [b"\x00" * 32] * (vector_length - len(values))
    # Convert each entry to bytes (if hex string, strip 0x)
    data = b""
    for v in vals:
        if isinstance(v, str):
            h = v[2:] if v.startswith("0x") else v
            v = bytes.fromhex(h)
        if len(v) != 32:
            raise ValueError("Each bytes32 entry must be 32 bytes")
        data += v
    # (Length is already a multiple of 32, but for safety:)
    if len(data) % 32 != 0:
        data += b"\x00" * (32 - (len(data) % 32))
    return [data[i : i + 32] for i in range(0, len(data), 32)]


# Example usage:
balances = [
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
randao_mixes = [
    "970f4e852916ed31b95239de091029f83e86ba5359e2345691e70dc87bb109d6",
    "bc82b96e84829ffd3a0e790225b6594384740dcdea41ed42ce96af68cbb76b71",
    "9acedf527f50725cd9f2bfe400a0c859ac8b2975f0e7a55801a8f5cc9178e7b1",
    "aa3b19dd65d9f8348de6f5c28fa9e954e673c79f03e77d38082bcfa0df83293b",
    "d570ee0d2fa7174de211298b3ed60c80a6c9905f9955bf7f0e3ef3335fb8e026",
    "8ef9de00a9dcf36918147c87be4e3f970f26c3b786ae38bb7e41d17722ccd8c1",
    "7742784e94df30f1190d885fcac0b2954e02867f7181de4495890fc4c9749caa",
    "b31c73df03727b66274e077a07e280b1c920c0dc846fc721ba4a6de0d7ae18ee",
]
# Pack into chunks
bal_chunks = pack_vector_uint64(balances, 69)
randao_chunks = pack_vector_bytes32(randao_mixes, 8)
# Compute Merkle roots
limit = (1099511627776 * 8 + 31) // 32  # Ceiling division for chunks
balances_root = merkle_root_list_fixed(bal_chunks, limit)
balances_root = sha256(balances_root + len(balances).to_bytes(32, "little")).digest()

randao_root = merkle_root_list_fixed(randao_chunks, 65536)
randao_root = sha256(randao_root + len(randao_mixes).to_bytes(32, "little")).digest()
# randao_root = merkle_root_from_chunks(randao_chunks)
# Combine for parent root
parent_root = sha256(balances_root + randao_root).digest()
print("Balances root:", balances_root.hex())
print("Randao   root:", randao_root.hex())
print("Parent   root:", parent_root.hex())
