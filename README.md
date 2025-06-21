# bera-proofs

**Berachain Merkle Proof Generator** - Generate cryptographic proofs for validator existence and balances on Berachain's beacon-kit implementation.

## 🎯 Purpose

This library generates Merkle proofs that are compatible with Berachain's specific SSZ implementation. Due to significant differences between Berachain's beacon-kit and the ETH2 specification, standard tools don't work - this library bridges that gap.

## 🚀 Quick Example

```bash
# Install and setup
git clone <repository-url>
cd bera-proofs
poetry install

# Generate proofs with CLI
poetry run python -m bera_proofs.cli validator 5 \
  --json-file test/data/state.json \
  --historical-state-file test/data/state-8.json

poetry run python -m bera_proofs.cli balance 5 \
  --json-file test/data/state.json \
  --historical-state-file test/data/state-8.json
```

**Response Example:**
```json
{
  "proof": ["0x86ed...", "0x129a...", "0x4aae...", ...],
  "root": "0x12c3b9e21f6636e8f81bf4a501c00e5bdd789b561ae7e1455807dca558117992",
  "metadata": {
    "validator_index": 5,
    "balance": "547445850000000",
    "effective_balance": "540000000000000",
    "proof_type": "balance_proof"
  }
}
```

## 💡 Use Cases

- **🌉 Cross-chain Bridges**: Verify validator states on other blockchains
- **💡 Light Clients**: Prove validator participation without downloading full state
- **🏦 Staking Protocols**: Cryptographically verify validator balances and status
- **📊 Analytics & Auditing**: Generate tamper-proof proofs for validator data
- **🔐 Zero-Knowledge Applications**: Use as inputs for ZK circuits requiring validator data

## 🏗️ Architecture

```
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│     CLI     │────▶│ Proof Gen   │────▶│ SSZ Library  │
└─────────────┘     └─────────────┘     └──────────────┘
        │                    │                     │
        ▼                    ▼                     ▼
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│ JSON Files  │     │ Test Data   │     │ Merkle Trees │
└─────────────┘     └─────────────┘     └──────────────┘
```

## 🔧 Installation

```bash
git clone <repository-url>
cd bera-proofs
poetry install
```

## 🖥️ CLI Usage

The CLI works with local JSON files and provides reliable, offline proof generation.

### Basic Commands
```bash
# Get help
poetry run python -m bera_proofs.cli --help
poetry run python -m bera_proofs.cli validator --help
poetry run python -m bera_proofs.cli balance --help

# Generate validator proof
poetry run python -m bera_proofs.cli validator 5 \
  --json-file current_state.json \
  --historical-state-file historical_state.json

# Generate balance proof  
poetry run python -m bera_proofs.cli balance 5 \
  --json-file current_state.json \
  --historical-state-file historical_state.json
```

### Using Test Data
```bash
# Quick test with included test data
poetry run python -m bera_proofs.cli validator 5 \
  --json-file test/data/state.json \
  --historical-state-file test/data/state-8.json

poetry run python -m bera_proofs.cli balance 5 \
  --json-file test/data/state.json \
  --historical-state-file test/data/state-8.json
```

## 🕰️ Historical Data Requirements

Berachain requires historical state data from 8 slots ago for proof generation. The CLI handles this through:

### 📁 Historical State Files (Recommended)
Use two state files - current and historical:
```bash
poetry run python -m bera_proofs.cli validator 0 \
  --json-file current_state.json \
  --historical-state-file historical_state.json
```

### ⚙️ Manual Historical Roots
Provide specific historical roots if you don't have historical state files:
```bash
poetry run python -m bera_proofs.cli validator 0 \
  --json-file current_state.json \
  --prev-state-root 0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8 \
  --prev-block-root 0x28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74
```

### 🧪 Test Mode
When using test data, the CLI automatically uses appropriate test defaults:
```bash
# CLI uses test defaults automatically
poetry run python -m bera_proofs.cli validator 0 --json-file test/data/state.json
```

## 🧪 Testing

```bash
# Run all tests
poetry run python tests/run_tests.py

# Test specific components
poetry run python -m pytest tests/test_integration.py
```

## 🔍 Berachain vs ETH2 Differences

### Key Implementation Differences
- **🗂️ BeaconState Fields**: ~15 ETH2 fields removed, 2 new fields added
- **📦 List Merkleization**: All lists treated as fixed vectors with appended length
- **🔄 State Modifications**: Historical data injection before proof generation

### Proof Structure
- **45-step Merkle witness** navigating through validator lists and BeaconState fields
- **Fixed capacity proofs** using ETH2 registry limits
- **Compatible roots** that match Berachain's beacon-kit implementation

## 🌳 Visualization Tools

Explore proof structure with built-in visualization:

```bash
# Interactive proof visualization
python src/visualize_merkle.py

# Features:
# - Tree structure diagrams
# - Step-by-step proof paths  
# - ETH2 vs Berachain comparisons
# - Performance metrics
```

## 📊 Data Formats

### Input Requirements
- **Current State**: BeaconState JSON from current slot
- **Historical State**: BeaconState JSON from 8 slots ago (preferred)
- **OR Historical Roots**: Manual `prev_state_root` and `prev_block_root` values

### Output Format
All proofs return:
- **proof**: Array of 32-byte hex strings (merkle siblings)
- **root**: Final state root for verification  
- **metadata**: Rich information including validator details, balances, and proof statistics

## 📁 Project Structure

```
bera-proofs/
├── src/
│   ├── main.py                 # Core proof generation
│   ├── cli.py                  # Command-line interface
│   ├── visualize_merkle.py     # Visualization tools
│   └── ssz/                    # Modular SSZ library
├── test/data/                  # Test state files
│   ├── state.json             # Current state example
│   └── state-8.json           # Historical state example
├── tests/                      # Test suite
└── README.md
```

## 🛠️ Development Status

- ✅ **CLI**: Fully functional and tested
- ✅ **Proof Generation**: Working with Berachain SSZ
- ✅ **Test Suite**: Comprehensive coverage
- ✅ **Visualization**: Interactive proof exploration
- 🚧 **API**: Under development

## 📄 License

MIT

## 🔗 Resources

- [Berachain Documentation](https://docs.berachain.com/)
- [ETH2 SSZ Specification](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)
- [Beacon Kit Implementation](https://github.com/berachain/beacon-kit)
