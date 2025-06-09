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

## 🌐 REST API Server

Bera Proofs includes a REST API server for generating Merkle proofs via HTTP endpoints.

### Starting the API Server

```bash
# Start server on localhost:8000
poetry run python -m src.cli serve

# Custom host and port
poetry run python -m src.cli serve --host 0.0.0.0 --port 8080
```

### API Endpoints

#### **Health Check**
```bash
GET /health
```

#### **Proof Generation**
All proof endpoints return the same JSON structure with proof steps, root hash, and metadata.

```bash
# Generate validator proof
GET /proofs/validator/{validator_index}?slot=head&json_file=path/to/state.json

# Generate balance proof  
GET /proofs/balance/{validator_index}?slot=head&json_file=path/to/state.json

# Generate proposer proof
GET /proofs/proposer/{validator_index}?slot=head&json_file=path/to/state.json

# 🆕 With explicit historical roots
GET /proofs/validator/{validator_index}?slot=head&json_file=path/to/state.json&prev_state_root=0x...&prev_block_root=0x...

# 🆕 With auto-fetching from beacon API
GET /proofs/validator/{validator_index}?slot=head&json_file=path/to/state.json&auto_fetch_historical=true
```

**Query Parameters:**
- `slot`: Beacon chain slot (default: "head")
- `json_file`: Path to BeaconState JSON file
- `prev_state_root`: *(optional)* Previous state root for historical data (32-byte hex)
- `prev_block_root`: *(optional)* Previous block root for historical data (32-byte hex)  
- `auto_fetch_historical`: *(optional)* Auto-fetch historical roots from beacon API (boolean)

**Response Format:**
```json
{
  "proof": ["0x...", "0x...", ...],
  "root": "0xe0aaed9422b2e3fa8c56a0114289ef05155e1ace9faa970c8c9bfc9fb46f97e0",
  "validator_index": 0,
  "slot": "head", 
  "proof_type": "validator|balance|proposer",
  "metadata": { "proof_length": 45, "..." }
}
```

### Configuration

Configure via `.env` file:
```bash
BEACON_RPC_URL=http://35.246.217.85:3500
API_HOST=0.0.0.0
API_PORT=8000
```

## 🖥️ Command Line Interface

### Basic Usage

```bash
# Generate proofs (returns JSON)
poetry run python -m src.cli validator 0 --json-file test/data/state.json
poetry run python -m src.cli balance 0 --json-file test/data/state.json  
poetry run python -m src.cli proposer 0 --json-file test/data/state.json

# Inspect beacon state
poetry run python -m src.cli inspect test/data/state.json

# Start API server
poetry run python -m src.cli serve
```

### 🆕 Historical Data Parameters

All proof generation commands now support optional historical data parameters for dynamic root handling:

```bash
# Generate proofs with explicit historical roots
poetry run python -m src.cli validator 0 \
  --json-file test/data/state.json \
  --prev-state-root 0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8 \
  --prev-block-root 0x28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74

# Auto-fetch historical data from beacon API (requires BEACON_RPC_URL)
poetry run python -m src.cli validator 0 \
  --json-file test/data/state.json \
  --auto-fetch

# Same options available for balance and proposer commands
poetry run python -m src.cli balance 0 --json-file test/data/state.json --auto-fetch
poetry run python -m src.cli proposer 0 --json-file test/data/state.json --auto-fetch
```

**Historical Data Options:**
- `--prev-state-root`: Explicit previous state root (32-byte hex, with or without 0x prefix)
- `--prev-block-root`: Explicit previous block root (32-byte hex, with or without 0x prefix)
- `--auto-fetch`: Automatically fetch historical roots from beacon API using the current slot

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

# 🆕 Dynamic historical data handling (configurable via parameters)
# Update state roots with previous cycle data
state.state_roots[slot % 8] = prev_state_root or state_root_from_previous_cycle(slot - 8)

# Update block roots with previous cycle data  
state.block_roots[slot % 8] = prev_block_root or block_root_from_previous_cycle(slot - 8)
```

**Historical Data Sources** *(in priority order)*:
1. **Explicit Parameters**: User-provided `prev_state_root` and `prev_block_root` values
2. **Beacon API**: Auto-fetched from beacon client when `auto_fetch_historical=true`
3. **Test Defaults**: Fallback values for testing and development environments

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