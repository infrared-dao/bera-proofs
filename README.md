# bera-proofs

**Berachain Merkle Proof Generator** - A standalone library for generating merkle proofs from BeaconState JSON data provided by Berachain's beacon node API endpoint `bkit/v1/proof/block_proposer/:timestamp_id`.

## 🎯 Purpose

Sufficient discrepancies exist between Berachain's beacon-kit implementation and the ETH2 specification that this standalone library was needed to generate compatible merkle proofs. This library ensures accurate proof generation that matches Berachain's specific SSZ implementation.

## 🔧 Installation & Setup

### Prerequisites
- Python 3.8+
- Poetry (recommended) or pip

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd bera-proofs

# Install dependencies with Poetry (recommended)
poetry install

# Or with pip
pip install -r requirements.txt

# Run tests to verify installation
poetry run python tests/run_tests.py
```

## 🚀 Quick Start

### Generate a Merkle Proof

```bash
# Using Poetry
poetry run python src/main.py

# Direct Python execution
python3 src/main.py
```

## 🌳 Merkle Tree Visualization

The library includes powerful visualization tools to help understand the proof structure and tree navigation.

```bash
# View complete merkle proof visualization
python3 src/visualize_merkle.py
```

This comprehensive visualization includes:
- **Tree Structure Diagram**: Visual representation of the Merkle tree hierarchy
- **ASCII Proof Path**: Step-by-step visualization of the 45-step proof
- **Proof Structure Analysis**: Breakdown of validator navigation, BeaconState fields, and root computation
- **ETH2 vs Berachain Comparison**: Side-by-side comparison of implementation differences
- **Interactive Examples**: Demonstrations with different validator indices


## 🔍 Berachain BeaconState Differences

Berachain's beacon-kit implementation differs significantly from the ETH2 specification:

### Field Differences
- **Removed**: ~15 ETH2 standard fields have been dropped
- **Added**: 
  - One new field for Deneb upgrade compatibility
  - One new field for Electra upgrade compatibility

### SSZ Implementation Differences

#### 1. **List Merkleization Behavior**
```
ETH2 Spec: Lists are merkleized as variable-length structures
Berachain: ALL lists are merkleized as fixed vectors using original ETH2 parameters,
           then little-endian list length is appended
```

#### 2. **Pre-Merkleization State Modifications**
Before generating merkle proofs, the following modifications are applied:

```python
# Reset latest block header state root
latest_block_header.state_root = int(0).to_bytes(32)

# Update state roots with previous cycle data
state.state_roots[slot % 8] = state_root_from_previous_cycle(slot - 8)

# Update block roots with previous cycle data  
state.block_roots[slot % 8] = block_root_from_previous_cycle(slot - 8)
```

### 3. **Merkle Tree Structure**
The library generates a 45-step merkle witness that navigates through:
- Validator list proof (variable steps based on validator count)
- BeaconState container field proofs
- Root hash computations

## 🌳 BeaconState Merkle Tree Structure

```
                           🏁 STATE ROOT
                                │
                ┌───────────────┴───────────────┐
                │                               │
        🌿 BEACON STATE                    OTHER FIELDS
           (16 fields)                          │
                │                               │
    ┌───────────┼───────────┐                  ...
    │           │           │
 FIELD_0     FIELD_9      FIELD_15
(genesis)  (validators) (total_slashing)
    │           │            │
    │     ┌─────┼─────┐      │
    │     │     │     │      │
    │   VAL_0 VAL_1 VAL_N    │
    │     │     │     │      │
    └─────┼─────┼─────┼──────┘
          │     │     │
        🎯 TARGET VALIDATOR
           (Index N)
```

**BeaconState Fields (16 total):**
```
 0. genesis_validators_root    8. latest_execution_payload_header
 1. slot                       9. validators ← TARGET FIELD
 2. fork                      10. balances
 3. latest_block_header       11. randao_mixes
 4. block_roots               12. next_withdrawal_index
 5. state_roots               13. next_withdrawal_validator_index
 6. eth1_data                 14. slashings
 7. eth1_deposit_index        15. total_slashing
```

**Proof Path (45 steps):**
1. Start at target validator leaf
2. Navigate up validator list tree (~10 steps)
3. Combine validator field with other 15 BeaconState fields (~25 steps)
4. Compute final state root (~10 steps)

## 📁 Project Structure

```
bera-proofs/
├── src/
│   ├── main.py                 # Main proof generation
│   ├── visualize_merkle.py     # Merkle tree visualization
│   └── ssz/                    # Modular SSZ library
│       ├── __init__.py
│       ├── constants.py        # SSZ constants and limits
│       ├── encoding/           # Field encoding functions
│       ├── merkle/            # Merkle tree operations
│       └── containers/        # SSZ container classes
├── test/
│   └── data/
│       └── state.json         # Test BeaconState data
├── tests/                     # Comprehensive test suite
│   ├── test_refactored_compatibility.py
│   ├── test_integration.py
│   └── run_tests.py
└── README.md
```

## 📄 License

MIT

## 🔗 Related Resources

- [Berachain Documentation](https://docs.berachain.com/)
- [ETH2 SSZ Specification](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)
- [Beacon Kit Implementation](https://github.com/berachain/beacon-kit)