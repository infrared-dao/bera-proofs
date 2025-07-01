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

# Option 1: Generate proofs with CLI
poetry run python -m src.cli validator 5 \
  --json-file test/data/state.json \
  --historical-state-file test/data/state-8.json

# Option 2: Start the API server
poetry run python -m src.cli serve

# Option 3: Use the API
curl -X POST http://localhost:8000/proofs/validator \
  -H "Content-Type: application/json" \
  -d '{"identifier": "5", "slot": "head"}'
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
│   REST API  │────▶│ Proof       │────▶│ SSZ Library  │
└─────────────┘     │ Service     │     └──────────────┘
                    └─────────────┘              │
┌─────────────┐            │                     ▼
│     CLI     │────────────┘            ┌──────────────┐
└─────────────┘                         │ Merkle Trees │
        │                               └──────────────┘
        ▼                                        
┌─────────────┐     ┌─────────────┐     ┌──────────────┐
│ JSON Files  │     │ Beacon API  │     │  Test Data   │
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

## 🌐 REST API Usage

The REST API provides proof generation via HTTP endpoints with automatic beacon chain data fetching.

### Starting the API Server
```bash
# Start with default settings (port 8000)
poetry run python -m src.cli serve

# Custom port and host
poetry run python -m src.cli serve --port 8080 --host 0.0.0.0

# Enable development mode with auto-reload
poetry run python -m src.cli serve --dev
```

### API Configuration
Configure the API via environment variables. Copy `.env.example` to `.env` and update:
```bash
# Copy the example environment file
cp .env.example .env

# Edit .env to set your configuration
# - BEACON_NETWORK: Choose 'testnet' or 'mainnet'
# - BEACON_RPC_URL_TESTNET: Set testnet beacon URL
# - BEACON_RPC_URL_MAINNET: Set mainnet beacon URL
```

### Making API Requests

#### Validator Proof
```bash
# Using validator index
curl -X POST http://localhost:8000/proofs/validator \
  -H "Content-Type: application/json" \
  -d '{"identifier": "5", "slot": "head"}'

# Using validator pubkey
curl -X POST http://localhost:8000/proofs/validator \
  -H "Content-Type: application/json" \
  -d '{"identifier": "0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b"}'
```

#### Balance Proof
```bash
# GET request (convenient for simple integrations)
curl http://localhost:8000/proofs/balance/5?slot=head

# POST request with full options
curl -X POST http://localhost:8000/proofs/balance \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "5",
    "slot": "head",
    "prev_state_root": "0x01ef6767...",
    "prev_block_root": "0x28925c02..."
  }'
```

### API Features
- **🔍 Validator Identification**: Support for both index and pubkey
- **🔄 Auto-fetch**: Automatically retrieves beacon chain data
- **📝 OpenAPI Docs**: Interactive documentation at `/docs`
- **🌍 CORS Enabled**: Ready for cross-origin requests
- **📊 Health Checks**: Monitor API and beacon node status

### API Documentation
Visit `http://localhost:8000/docs` for interactive OpenAPI documentation.

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
│   ├── api/                    # REST API implementation
│   │   ├── rest_api.py        # FastAPI endpoints
│   │   ├── proof_service.py   # Proof generation service
│   │   └── beacon_client.py   # Beacon chain integration
│   ├── models/                 # Data models
│   │   └── api_models.py      # Request/response models
│   └── ssz/                    # Modular SSZ library
├── test/data/                  # Test state files
│   ├── state.json             # Current state example
│   └── state-8.json           # Historical state example
├── tests/                      # Test suite
├── @ai_docs/                   # API documentation
└── README.md
```

## 🛠️ Development Status

- ✅ **CLI**: Fully functional and tested
- ✅ **Proof Generation**: Working with Berachain SSZ
- ✅ **Test Suite**: Comprehensive coverage
- ✅ **Visualization**: Interactive proof exploration
- ✅ **REST API**: Production-ready with validator identification by index or pubkey
- ✅ **Beacon Integration**: Supports both testnet and mainnet

## 📄 License

MIT

## 🔗 Resources

- [Berachain Documentation](https://docs.berachain.com/)
- [ETH2 SSZ Specification](https://github.com/ethereum/consensus-specs/blob/dev/ssz/simple-serialize.md)
- [Beacon Kit Implementation](https://github.com/berachain/beacon-kit)
