# Constants for SSZ limits
SLOTS_PER_HISTORICAL_ROOT = 8192  # For block_roots, state_roots
# EPOCHS_PER_HISTORICAL_VECTOR = 65536  # For randao_mixes
# MAX_VALIDATORS = 1099511627776  # For validators, balances, slashings
# EPOCHS_PER_SLASHINGS_VECTOR = 8192  # For slashings
# SLOTS_PER_HISTORICAL_ROOT = 8  # For block_roots, state_roots
# EPOCHS_PER_HISTORICAL_VECTOR = 8  # For randao_mixes
EPOCHS_PER_HISTORICAL_VECTOR = 65536  # For randao_mixes
EPOCHS_PER_SLASHINGS_VECTOR = 8  # For slashings
VALIDATOR_REGISTRY_LIMIT = 1099511627776
BYTES_PER_LOGS_BLOOM = 256
PENDING_PARTIAL_WITHDRAWALS_LIMIT = 134217728

BERACHAIN_VECTOR = 8
MAX_VALIDATORS = 69  # For validators, balances, slashings

# Precompute zero node hashes for up to 40 levels
ZERO_HASHES = [b"\0" * 32]
for _ in range(40):
    ZERO_HASHES.append(sha256(ZERO_HASHES[-1] + ZERO_HASHES[-1]).digest())
