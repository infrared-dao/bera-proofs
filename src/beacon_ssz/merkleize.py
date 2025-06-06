from hashlib import sha256
from config import *

# Define basic serialization functions
def serialize_uint64(value: int) -> bytes:
    return value.to_bytes(8, "little")


def serialize_uint256(value: int) -> bytes:
    return value.to_bytes(32, "little")


def serialize_bool(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


def serialize_bytes(value: bytes, length: int) -> bytes:
    assert len(value) == length, f"Expected {length} bytes, got {len(value)}"
    return value


def merkle_root_basic(value: Any, type_str: str) -> bytes:
    """
    Serialize and pad basic types
    """
    if type_str.startswith("bytes") and isinstance(value, str):
        if value.startswith("0x"):
            value = bytes.fromhex(value[2:])
        else:
            value = bytes.fromhex(value)
    if type_str == "bytes32":
        return serialize_bytes(value, 32)  # Already 32 bytes, return directly
    elif type_str == "uint64":
        serialized = serialize_uint64(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "uint256":
        serialized = serialize_uint256(value)
        return serialized  # Already 32 bytes, no hash
    elif type_str == "Boolean":
        serialized = serialize_bool(value)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes48":
        chunk1 = value[0:32]
        chunk2 = value[32:48] + b"\0" * 16
        return sha256(chunk1 + chunk2).digest()  # >32 bytes, hash required
    elif type_str == "bytes20":
        serialized = serialize_bytes(value, 20)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes256":
        chunks = [value[i : i + 32] for i in range(0, 256, 32)]
        return merkle_root_list(chunks)  # Fixed-size, Merkleize chunks
    elif type_str == "bytes4":
        serialized = serialize_bytes(value, 4)
        padded = serialized + b"\0" * (32 - len(serialized))
        return padded  # Return padded value, no hash
    elif type_str == "bytes":
        # extra data is the only case, type is actually ByteList[32] but bytes is a shortcut for processing
        # Validate length
        max_length = 32  # MAX_EXTRA_DATA_BYTES
        if len(value) > max_length:
            raise ValueError(
                f"ExtraData length {len(value)} exceeds maximum {max_length}"
            )

        # Form single chunk
        if len(value) == 0:
            chunks_root = b"\0" * 32
        else:
            chunk = value + b"\0" * (32 - len(value))  # Pad to 32 bytes
            chunks_root = chunk  # Single chunk, no Merkle tree needed

        # Mix in length
        length_packed = len(value).to_bytes(32, "little")
        return sha256(chunks_root + length_packed).digest()

    else:
        raise ValueError(f"Unsupported basic type: {type_str}")


def merkle_root_list(roots: List[bytes]) -> bytes:
    if not roots:
        return b"\0" * 32
    # Pad to next power of two
    n = len(roots)
    k = math.ceil(math.log2(max(n, 1)))
    num_leaves = 1 << k
    padded = roots + [b"\0" * 32] * (num_leaves - n)
    return build_merkle_tree(padded)[-1][0]


def build_merkle_tree(leaves: List[bytes]) -> List[List[bytes]]:
    tree = [leaves]
    current = leaves
    while len(current) > 1:
        next_level = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else b"\0" * 32
            parent = sha256(left + right).digest()
            next_level.append(parent)
        tree.append(next_level)
        current = next_level
    return tree


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


def get_proof(tree: List[List[bytes]], index: int) -> List[bytes]:
    proof = []
    level = 0
    i = index
    while level < len(tree) - 1:
        sibling_i = i ^ 1
        sibling = tree[level][sibling_i] if sibling_i < len(tree[level]) else b"\0" * 32
        proof.append(sibling)
        i //= 2
        level += 1
    return proof


def verify_merkle_proof(
    leaf: bytes, proof: List[bytes], index: int, root: bytes
) -> bool:
    current = leaf
    for sibling in proof:
        if index % 2 == 0:
            current = sha256(current + sibling).digest()  # Leaf is left
        else:
            current = sha256(sibling + current).digest()  # Leaf is right
        index //= 2  # Move up the tree
    return current == root


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


def encode_pending_partial_withdrawals_leaf_list(ppw_list_leaves: List[bytes]) -> bytes:
    """
    Note assumed ppw structs are already merkleized into list of leaves
    """
    if len(ppw_list_leaves) > MAX_VALIDATORS:
        raise ValueError(
            f"Validators list too large: {len(ppw_list_leaves)} > {MAX_BALANCES}"
        )

    # Calculate limit for Merkleization
    ppw_list_root = merkle_root_list_fixed(
        ppw_list_leaves, PENDING_PARTIAL_WITHDRAWALS_LIMIT
    )
    ppw_list_root = sha256(
        ppw_list_root + len(ppw_list_leaves).to_bytes(32, "little")
    ).digest()

    return ppw_list_root


def encode_validators_leaf_list(validator_list_leaves: List[bytes]) -> bytes:
    """
    Note assumed validator structs are already merkleized into list of leaves
    """
    if len(validator_list_leaves) > VALIDATOR_REGISTRY_LIMIT:
        raise ValueError(
            f"Validators list too large: {len(validator_list_leaves)} > {VALIDATOR_REGISTRY_LIMIT}"
        )

    # Calculate limit for Merkleization
    validator_list_root = merkle_root_list_fixed(
        validator_list_leaves, VALIDATOR_REGISTRY_LIMIT
    )
    validator_list_root = sha256(
        validator_list_root + len(validator_list_leaves).to_bytes(32, "little")
    ).digest()

    return validator_list_root


def encode_balances(balances: List[int]) -> bytes:
    if len(balances) > MAX_VALIDATORS:
        raise ValueError(f"Balances list too large: {len(balances)} > {MAX_BALANCES}")

    bal_chunks = pack_vector_uint64(balances, MAX_VALIDATORS)

    # Calculate limit for Merkleization
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    balances_root = merkle_root_list_fixed(bal_chunks, limit)
    balances_root = sha256(
        balances_root + len(balances).to_bytes(32, "little")
    ).digest()

    return balances_root


def encode_randao_mixes(randao_mixes: List[bytes]) -> bytes:
    if len(randao_mixes) > EPOCHS_PER_HISTORICAL_VECTOR:
        raise ValueError(
            f"RandaoMixes list too large: {len(randao_mixes)} > {EPOCHS_PER_HISTORICAL_VECTOR}"
        )

    randao_chunks = pack_vector_bytes32(randao_mixes, 8)

    randao_root = merkle_root_list_fixed(randao_chunks, EPOCHS_PER_HISTORICAL_VECTOR)
    randao_root = sha256(
        randao_root + len(randao_mixes).to_bytes(32, "little")
    ).digest()

    return randao_root


def encode_block_roots(block_roots: List[bytes]) -> bytes:
    if len(block_roots) > SLOTS_PER_HISTORICAL_ROOT:
        raise ValueError(
            f"Block roots list too large: {len(block_roots)} > {SLOTS_PER_HISTORICAL_ROOT}"
        )

    # br_chunks = pack_vector_bytes32(block_roots, 8)

    br_root = merkle_root_list_fixed(block_roots, SLOTS_PER_HISTORICAL_ROOT)
    br_root = sha256(br_root + len(block_roots).to_bytes(32, "little")).digest()

    return br_root


def encode_slashings(slashings: List[bytes]) -> bytes:
    if len(slashings) > EPOCHS_PER_HISTORICAL_VECTOR:
        raise ValueError(
            f"Slashings list too large: {len(slashings)} > {EPOCHS_PER_HISTORICAL_VECTOR}"
        )

    slash_chunks = pack_vector_bytes32(slashings, 8)
    limit = (VALIDATOR_REGISTRY_LIMIT * 8 + 31) // 32  # Ceiling division for chunks
    slash_root = merkle_root_list_fixed(slash_chunks, limit)
    slash_root = sha256(slash_root + len(slashings).to_bytes(32, "little")).digest()

    return slash_root
