# Bera-Proofs REST API Specification

## Overview

The Bera-Proofs API provides HTTP endpoints for generating Merkle proofs that verify validator existence and balances on the Berachain blockchain. The API automatically fetches data from the beacon chain and generates cryptographic proofs compatible with Berachain's SSZ implementation.

**Base URL**: `http://localhost:8000` (configurable)

**API Version**: `1.0.0`

## Quick Start

```bash
# Start the API server
poetry run python -m src.cli serve

# Generate a validator proof
curl -X POST http://localhost:8000/proofs/validator \
  -H "Content-Type: application/json" \
  -d '{"identifier": "0", "slot": "head"}'
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
  "version": "1.0.0",
  "timestamp": "2024-07-01T12:00:00Z"
}
```

### 2. Generate Validator Proof

Generate a Merkle proof that proves a validator exists in the beacon state.

**Endpoint**: `POST /proofs/validator`

**Request Body**:
```json
{
  "identifier": "string",  // Validator index ("0", "123") or pubkey ("0x...")
  "slot": "string",        // "head", "finalized", or slot number (default: "head")
  "prev_state_root": "string",  // Optional: Historical state root (hex)
  "prev_block_root": "string"   // Optional: Historical block root (hex)
}
```

**Validator Identifier Format**:
- **Index**: String number, e.g., `"0"`, `"123"`, `"45678"`
- **Pubkey**: 48-byte hex string with 0x prefix, e.g., `"0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b"`

**Response**:
```json
{
  "proof": [
    "0x86ed4e9fa6e12fb5ef49f404be37c2e0fb53c19f8c604b7e9575c2cb1b719b95",
    "0x129a592e9a3e52e27927e70d79bfa0ce1b3c1911e4bb38e2ab4bb6284764c47f",
    // ... more proof steps
  ],
  "root": "0x12c3b9e21f6636e8f81bf4a501c00e5bdd789b561ae7e1455807dca558117992",
  "validator_index": 0,
  "validator_pubkey": "0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b",
  "slot": "head",
  "proof_type": "validator",
  "metadata": {
    "proof_length": 45,
    "validator_count": 100,
    "validator": {
      "index": 0,
      "pubkey": "0x957004...",
      "effective_balance": "32000000000",
      "slashed": false,
      "activation_epoch": 0,
      "exit_epoch": 18446744073709551615
    }
  },
  "historical_data": {
    "prev_state_root": "0x01ef6767...",
    "prev_block_root": "0x28925c02...",
    "auto_fetched": true
  }
}
```

### 3. Generate Balance Proof

Generate a Merkle proof for a validator's balance.

**Endpoint**: `POST /proofs/balance`

**Request Body**: Same as validator proof

**Response**:
```json
{
  "proof": [
    "0x4aae6bcd95aa577ef69cf9368dc9503c15ca5e3ce5bb46d12a8311f0883e6d45",
    // ... more proof steps
  ],
  "root": "0x12c3b9e21f6636e8f81bf4a501c00e5bdd789b561ae7e1455807dca558117992",
  "validator_index": 0,
  "validator_pubkey": "0x957004...",
  "slot": "head",
  "proof_type": "balance",
  "metadata": {
    "proof_length": 44,
    "balance": "32123456789",
    "effective_balance": "32000000000",
    "balance_chunk_index": 0,
    "validators_in_chunk": [0, 1, 2, 3]
  },
  "historical_data": {
    "prev_state_root": "0x01ef6767...",
    "prev_block_root": "0x28925c02...",
    "auto_fetched": true
  }
}
```

### 4. GET Endpoints (Convenience)

For simple integrations, GET endpoints are available:

**Validator Proof**: `GET /proofs/validator/{identifier}`
**Balance Proof**: `GET /proofs/balance/{identifier}`

**Query Parameters**:
- `slot`: Slot identifier (optional, default: "head")
- `prev_state_root`: Historical state root (optional)
- `prev_block_root`: Historical block root (optional)

**Example**:
```bash
# Using index
curl "http://localhost:8000/proofs/validator/0?slot=head"

# Using pubkey
curl "http://localhost:8000/proofs/balance/0x957004733f0c4d7e51b4f1ac3f1c08247f9c5455d302b669c723eb80d8c286515b5623757a9053a5a7b8c17ee3feed4b"
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

# Generate validator proof
response = requests.post(
    "http://localhost:8000/proofs/validator",
    json={
        "identifier": "0",
        "slot": "head"
    }
)
proof_data = response.json()
print(f"Proof root: {proof_data['root']}")
```

### JavaScript/TypeScript
```javascript
// Using fetch API
const response = await fetch('http://localhost:8000/proofs/validator', {
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
```

### Go
```go
package main

import (
    "bytes"
    "encoding/json"
    "net/http"
)

type ProofRequest struct {
    Identifier string `json:"identifier"`
    Slot      string `json:"slot"`
}

func main() {
    reqBody, _ := json.Marshal(ProofRequest{
        Identifier: "0",
        Slot:      "head",
    })
    
    resp, err := http.Post(
        "http://localhost:8000/proofs/validator",
        "application/json",
        bytes.NewBuffer(reqBody),
    )
    // Handle response...
}
```

## Backward Compatibility

For backward compatibility, the API still accepts the deprecated `val_index` field in request bodies. However, developers should migrate to using `identifier` for future compatibility.

```json
{
  "val_index": 0,  // Deprecated, use "identifier": "0" instead
  "slot": "head"
}
```

## Network Requirements

The beacon node URLs are only accessible from specific IP addresses. Ensure your deployment environment has access to the beacon nodes.

## Support

For issues or questions:
- GitHub Issues: [Repository Issues](https://github.com/berachain/bera-proofs/issues)
- Documentation: See `/docs` endpoint for interactive API documentation