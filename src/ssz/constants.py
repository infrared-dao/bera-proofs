"""
SSZ Constants and Limits

This module contains all constants and limits used in the SSZ (Simple Serialize) 
implementation for Ethereum beacon chain data structures.

References:
- Ethereum Consensus Specification: https://github.com/ethereum/consensus-specs
- SSZ Specification: https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md
"""

from hashlib import sha256

# ====================
# Historical Data Limits
# ====================

# Number of slots to maintain in historical root vectors
# This determines the size of block_roots and state_roots vectors in BeaconState
SLOTS_PER_HISTORICAL_ROOT = 8192

# Number of epochs to maintain in historical vectors
# Used for randao_mixes vector in BeaconState
EPOCHS_PER_HISTORICAL_VECTOR = 65536

# Number of epochs to maintain slashing data
# Used for slashings vector in BeaconState
EPOCHS_PER_SLASHINGS_VECTOR = 8

# ====================
# Berachain Specific Constants
# ====================

# Berachain uses smaller vector size for state/block roots
BERACHAIN_VECTOR = 8

# ====================
# Validator Limits
# ====================

# Maximum number of validators that can be registered
# Used for validators and balances lists in BeaconState
MAX_VALIDATORS = (
    69  # Note: This appears to be a test value, production would be much higher
)

# Maximum capacity for the validator registry
# Production limit from the Ethereum specification
VALIDATOR_REGISTRY_LIMIT = 1099511627776

# Maximum pending partial withdrawals (Electra)
PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728  # 2^27

# ====================
# Execution Layer Constants
# ====================

# Size of the logs bloom filter in execution payload headers
BYTES_PER_LOGS_BLOOM = 256

# ====================
# Cryptographic Constants
# ====================

# Precomputed zero node hashes for Merkle tree padding
# These are used to efficiently pad Merkle trees without recomputing zero hashes
# Each level i contains: SHA256(ZERO_HASHES[i-1] || ZERO_HASHES[i-1])
ZERO_HASHES = [b"\0" * 32]
for _ in range(40):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())

# ====================
# SSZ Type Constants
# ====================

# Standard hash output size (32 bytes for SHA256)
HASH_SIZE = 32

# Standard sizes for fixed-width types
UINT64_SIZE = 8
UINT256_SIZE = 32
BOOL_SIZE = 1

# Ethereum address size
ETH_ADDRESS_SIZE = 20

# BLS public key size
BLS_PUBKEY_SIZE = 48

# Standard root size (same as hash size)
ROOT_SIZE = 32
