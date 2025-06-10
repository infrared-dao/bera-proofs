# Changes Made to Address PR Comments

## Summary of Changes

Based on the PR feedback from your coworker, the following changes were made to properly implement dynamic historical root indexing according to the ETH2 specification:

### 1. BeaconState Container (`src/ssz/containers/beacon.py`)
- Changed from hardcoded index 2 to dynamic `self.slot % BERACHAIN_VECTOR` for historical roots:
  ```python
  # Before:
  self.state_roots[2] = prev_cycle_state_root
  self.block_roots[2] = prev_cycle_block_root
  
  # After:
  self.state_roots[self.slot % BERACHAIN_VECTOR] = prev_cycle_state_root
  self.block_roots[self.slot % BERACHAIN_VECTOR] = prev_cycle_block_root
  ```

### 2. Main Module (`src/main.py`)
- Updated all occurrences of hardcoded index 2 to use `state.slot % 8`:
  - In `generate_validator_proof()`
  - In `generate_balance_proof()`
  - In `_compute_state_root()`
  - In `generate_merkle_witness()`

### 3. CLI Module (`src/cli.py`)
- Updated `extract_historical_roots_from_file()` to use dynamic indexing:
  ```python
  # Before:
  state_root = f"0x{state.state_roots[2].hex()}"
  block_root = f"0x{state.block_roots[2].hex()}"
  
  # After:
  state_root = f"0x{state.state_roots[state.slot % 8].hex()}"
  block_root = f"0x{state.block_roots[state.slot % 8].hex()}"
  ```

### 4. Test Updates
- Updated expected state root in tests from `12c3b9e21f...` to `37dbbe22dd...` to reflect the correct behavior with dynamic indexing
- All tests now pass with the proper ETH2 spec-compliant implementation

## Rationale

As per the ETH2 specification (https://eth2book.info/capella/part3/transition/), historical roots should be stored at index `slot % SLOTS_PER_HISTORICAL_ROOT`. In Berachain's implementation, this is `slot % 8` (where 8 is the `BERACHAIN_VECTOR` constant).

The previous hardcoded index 2 was only correct for specific slot values where `slot % 8 == 2`. This change ensures the code works correctly for any slot value, following the specification exactly.

## Impact

- The state root calculation now correctly follows the ETH2 specification
- The code is more robust and works correctly regardless of the slot value
- Test expectations were updated to match the correct behavior