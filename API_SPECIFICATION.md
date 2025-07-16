# Bera-Proofs REST API Specification

## Overview

The Bera-Proofs API provides an HTTP endpoint for generating combined Merkle proofs that verify both validator existence and balances on the Berachain blockchain. The API automatically fetches data from the beacon chain and generates cryptographic proofs compatible with Berachain's SSZ implementation.

### Important: Timestamp Field

All proof responses include a `timestamp` field in the metadata that represents the Unix timestamp of the block used for proof generation. This timestamp is critical for smart contract validation to prevent stale proofs. The API also provides:
- `age_seconds`: How old the proof is (current time - timestamp)
- `slot`: The actual slot number used for the proof

**Base URL**: `http://localhost:8000` (configurable)

**API Version**: `1.0.0`

## Quick Start

```bash
# Start the API server
poetry run python -m bera_proofs.cli serve

# Generate a combined proof
curl -X POST http://localhost:8000/proofs/combined \
  -H "Content-Type: application/json" \
  -d '{"identifier": "0"}'
```

## Authentication

No authentication is required for the current version.

## Common Headers

| Header | Value | Description |
|--------|-------|-------------|
| Content-Type | `application/json` | Required for POST requests |
| Accept | `application/json` | Recommended for all requests |

## Endpoints

### 1. Health Check

Check API and beacon node connectivity status.

**Endpoint**: `GET /health`

**Response**:
```json
{
  "status": "healthy",
  "beacon_api": true,
  "version": "1.0.0"
}
```

### 2. Generate Combined Proof

Generate both validator and balance proofs in a single call.

**Endpoint**: `POST /proofs/combined`

**Request Body**:
```json
{
  "identifier": "string",  // Validator index ("0", "123") or pubkey ("0x...")
  "slot": "string",        // "head", "finalized", "recent", or slot number (default: "head")
  "prev_state_root": "string",  // Optional: Historical state root (hex)
  "prev_block_root": "string"   // Optional: Historical block root (hex)
}
```

**Validator Identifier Format**:
- **Index**: String number, e.g., `"0"`, `"123"`, `"45678"`
- **Pubkey**: 48-byte hex string with 0x prefix, e.g., `"0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b"`

**Slot Values**:
- **"head"**: Use the latest block
- **"finalized"**: Use the latest finalized block  
- **"recent"**: Use head - 2 blocks (recommended for proof submission to avoid staleness)
- **Number**: Use specific slot number, e.g., `"123456"`

**Response**:
```json
{
  "balance_proof": [
    "0x00a031a95fe3000000a031a95fe3000000a031a95fe3000000a031a95fe30000",
    "0x40cd968af8740d35fb1aaef2eea860d3a9e7656b5f4c57da86c9544181e1d855",
    // ... more balance proof steps
  ],
  "validator_proof": [
    "0x6decdeb9989e54d6fcbec24976587c27c49f68d266fd8b90586ff92259298305",
    "0xff724f5b951a816510f12ea3da762ca9b2af34731cc550471f4da7d3e80ff714",
    // ... more validator proof steps
  ],
  "state_root": "0x911cca93152ba17e43d50fe79c9cb567dc4a1aef1e65086735e596c054018970",
  "balance_leaf": "0x00a031a95fe3000000a031a95fe3000000a031a95fe3000000a031a95fe30000",
  "balances_root": "0x3de12dad73160717c99e9f126dcb610c615103ac8895cf10e4dc8c91dad58338",
  "validator_index": 5,
  "header": {
    "slot": 6186303,
    "proposer_index": 5,
    "parent_root": "0x9831e495c546743e59a096333b8b84f5bde733c1ed3a1106ee0757b9cd4f59aa",
    "state_root": "0x911cca93152ba17e43d50fe79c9cb567dc4a1aef1e65086735e596c054018970",
    "body_root": "0x3eb5294a2e0866ad936a6d8367bda20575848f93b4da56d50bbf48155ab6a0f6"
  },
  "validator_data": {
    "pubkey": "0x8f51e63d9921a461be29e73dca1c2385e1adc5943fbb36ded4ba96025ee8a783184d1118da08171f6ea831153c878a6d",
    "withdrawal_credentials": "0x0100000000000000000000000cf32c7c003bd9fdbd5ba635daedcb1070e77de0",
    "effective_balance": 250000000000000,
    "slashed": false,
    "activation_eligibility_epoch": 0,
    "activation_epoch": 0,
    "exit_epoch": 18446744073709551615,
    "withdrawable_epoch": 18446744073709551615
  },
  "metadata": {
    "balance_proof_length": 44,
    "validator_proof_length": 46,
    "balance": "250000000000000",
    "effective_balance": "250000000000000",
    "timestamp": 1751553133,
    "block_number": 6186303,
    "age_seconds": 3,
    "slot": 6186303
  }
}
```

**Response Fields**:
- `balance_proof`: Array of hex strings representing the balance Merkle proof steps
- `validator_proof`: Array of hex strings representing the validator existence proof steps
- `state_root`: The computed state root for verification
- `balance_leaf`: The actual balance data leaf in the Merkle tree
- `balances_root`: The root of the balances subtree
- `validator_index`: The numeric index of the validator
- `header`: Block header information including slot, proposer, and roots
- `validator_data`: Complete validator information including pubkey, balances, and status
- `metadata`: Additional information including timestamps and proof metadata

### 3. GET Endpoint (Convenience)

For simple integrations, a GET endpoint is available:

**Combined Proof**: `GET /proofs/combined/{identifier}`

**Query Parameters**:
- `slot`: Slot identifier - "head", "finalized", "recent", or number (optional, default: "head")
- `prev_state_root`: Historical state root (optional)
- `prev_block_root`: Historical block root (optional)

**Example**:
```bash
# Using index
curl "http://localhost:8000/proofs/combined/0?slot=head"

# Using pubkey
curl "http://localhost:8000/proofs/combined/0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b"

# Combined proof with recent slot (head - 2)
curl "http://localhost:8000/proofs/combined/67?slot=recent"
```

## Error Responses

All errors follow a consistent format:

```json
{
  "error": "string",     // Human-readable error message
  "code": "string",      // Error code for programmatic handling
  "details": {           // Additional error context (optional)
    "error_type": "string",
    // ... other details
  }
}
```

### Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_IDENTIFIER` | 400 | Invalid validator identifier format |
| `VALIDATOR_NOT_FOUND` | 400 | Validator not found in state |
| `PROOF_GENERATION_ERROR` | 400 | Failed to generate proof |
| `BEACON_API_ERROR` | 502 | Beacon node connection failed |
| `INTERNAL_ERROR` | 500 | Unexpected server error |

### Example Error Response

```json
{
  "error": "Validator with pubkey 0x123... not found",
  "code": "VALIDATOR_NOT_FOUND",
  "details": {
    "error_type": "ProofServiceError",
    "identifier": "0x123...",
    "validator_count": 100
  }
}
```

## Configuration

The API is configured via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BEACON_NETWORK` | Network to use: `testnet` or `mainnet` | `testnet` |
| `BEACON_RPC_URL_TESTNET` | Testnet beacon node URL | See `.env.example` |
| `BEACON_RPC_URL_MAINNET` | Mainnet beacon node URL | See `.env.example` |
| `API_HOST` | API server host | `0.0.0.0` |
| `API_PORT` | API server port | `8000` |
| `LOG_LEVEL` | Logging level | `INFO` |

**Note**: Copy `.env.example` to `.env` and configure the beacon RPC URLs with the appropriate values for your environment.

## Rate Limiting

Currently no rate limiting is implemented. For production deployments, consider adding rate limiting based on your requirements.

## CORS

CORS is enabled for all origins by default. For production, configure allowed origins via the API code.

## OpenAPI Documentation

Interactive API documentation is available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

## Client Examples

### Python
```python
import requests

# Generate combined proof
response = requests.post(
    "http://localhost:8000/proofs/combined",
    json={
        "identifier": "5",
        "slot": "head"
    }
)
proof_data = response.json()
print(f"State root: {proof_data['state_root']}")
print(f"Balance: {proof_data['metadata']['balance']}")
print(f"Timestamp: {proof_data['metadata']['timestamp']}")
```

### JavaScript/TypeScript
```javascript
// Using fetch API
const response = await fetch('http://localhost:8000/proofs/combined', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json'
    },
    body: JSON.stringify({
        identifier: '0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b',
        slot: 'head'
    })
});

const proofData = await response.json();
console.log(`Validator index: ${proofData.validator_index}`);
console.log(`State root: ${proofData.state_root}`);
```

### cURL
```bash
# Using validator index
curl -X POST http://localhost:8000/proofs/combined \
  -H "Content-Type: application/json" \
  -d '{"identifier": "5"}'

# Using validator pubkey
curl -X POST http://localhost:8000/proofs/combined \
  -H "Content-Type: application/json" \
  -d '{"identifier": "0x8f51e63d9921a461be29e73dca1c2385e1adc5943fbb36ded4ba96025ee8a783184d1118da08171f6ea831153c878a6d"}'

# Using specific slot
curl -X POST http://localhost:8000/proofs/combined \
  -H "Content-Type: application/json" \
  -d '{"identifier": "5", "slot": "recent"}'
```

## Performance Considerations

- The combined endpoint generates both proofs in a single operation, reducing latency compared to making separate calls
- Using `slot: "recent"` (head - 2) is recommended for production to avoid issues with chain reorganizations
- Proof generation typically takes 1-3 seconds depending on the beacon node response time
- The API caches beacon state data for 15 minutes to improve performance for repeated requests

## Security Notes

- Always validate the `timestamp` field in smart contracts to prevent replay attacks with old proofs
- The `age_seconds` field helps determine proof freshness without additional calculations
- Consider implementing additional validation in your smart contracts based on your security requirements

## Support

For issues or questions:
- GitHub Issues: [Repository Issues](https://github.com/berachain/bera-proofs/issues)
- Documentation: See `/docs` endpoint for interactive API documentation