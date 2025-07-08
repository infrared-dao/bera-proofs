"""
REST API for Bera Proofs

This module provides a FastAPI-based REST API for generating Merkle proofs
for validators and balances with full OpenAPI documentation.
"""

import logging
import traceback
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

import json
import tempfile
import os
import time
from .beacon_client import BeaconAPIClient, BeaconAPIError
from ..main import ProofCombinedResult, generate_validator_and_balance_proofs
from ..models.api_models import (
    ErrorResponse, 
    HealthResponse,
    CombinedProofRequest,
    CombinedProofResponse
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Bera Proofs API",
    description="""
    Generate combined Merkle proofs for Berachain validators.
    
    This simplified API provides a single endpoint to generate both validator existence
    and balance proofs in one efficient call. The proofs can be verified against the
    beacon chain state root without requiring the full state data.
    
    ## Features
    - **Combined Proofs**: Both validator and balance proofs in a single API call
    - **Flexible Identification**: Use either validator index or public key
    - **Live Data**: Automatically fetches fresh data from beacon chain
    - **Timestamp Support**: Includes timestamp data for smart contract validation
    - **Slot Options**: Support for "head", "finalized", "recent", or specific slot numbers
    
    ## Validator Identification
    Validators can be identified by either:
    - **Index**: Numeric index as string (e.g., "0", "123", "456")
    - **Public Key**: 48-byte hex string with 0x prefix (e.g., "0x957004...")
    
    ## Usage
    Simply call the `/proofs/combined` endpoint with your validator identifier
    and optional slot specification. The API returns both proofs along with
    all necessary metadata for verification.
    """,
    version="2.0.0",
    contact={
        "name": "Bera Proofs Team",
        "url": "https://github.com/berachain/bera-proofs"
    },
    license_info={
        "name": "MIT",
        "url": "https://opensource.org/licenses/MIT"
    }
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global beacon client instance
beacon_client = None


def get_beacon_client() -> BeaconAPIClient:
    """Dependency to get the beacon client instance."""
    global beacon_client
    if beacon_client is None:
        beacon_client = BeaconAPIClient()
    return beacon_client


@app.exception_handler(ValueError)
async def value_error_handler(request, exc: ValueError):
    """Handle validation errors."""
    logger.error(f"Validation error: {exc}")
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error=str(exc),
            code="VALIDATION_ERROR",
            details={"error_type": "ValueError"}
        ).model_dump()
    )


@app.exception_handler(BeaconAPIError)
async def beacon_api_exception_handler(request, exc: BeaconAPIError):
    """Handle beacon API errors."""
    logger.error(f"Beacon API error: {exc}")
    return JSONResponse(
        status_code=502,
        content=ErrorResponse(
            error=str(exc),
            code="BEACON_API_ERROR", 
            details={"error_type": "BeaconAPIError"}
        ).model_dump()
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle unexpected errors."""
    logger.error(f"Unexpected error: {exc}\n{traceback.format_exc()}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            code="INTERNAL_ERROR",
            details={"error_type": type(exc).__name__}
        ).model_dump()
    )


@app.get("/", response_model=dict)
async def root():
    """API root endpoint with basic information."""
    return {
        "name": "Bera Proofs API",
        "version": "1.0.0",
        "description": "Generate Merkle proofs for Berachain beacon state",
        "docs": "/docs",
        "health": "/health"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check(client: BeaconAPIClient = Depends(get_beacon_client)):
    """
    Health check endpoint.
    
    Checks the status of the API and beacon chain connectivity.
    """
    try:
        # Check beacon API connectivity
        beacon_status = client.health_check()
        
        return HealthResponse(
            status="healthy",
            beacon_api=beacon_status,
            version="1.0.0"
        )
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
        return HealthResponse(
            status="degraded",
            beacon_api=False,
            version="1.0.0"
        )


@app.post("/proofs/combined", response_model=CombinedProofResponse)
async def generate_combined_proof(
    request: CombinedProofRequest,
    client: BeaconAPIClient = Depends(get_beacon_client)
):
    """
    Generate both validator and balance proofs in a single call.
    
    This endpoint generates both a validator existence proof and a balance proof
    for the specified validator. The response matches the format used by the CLI
    combine command, providing all necessary data for verification in one response.
    
    The validator can be identified by either:
    - Index: numeric index (e.g., "0", "123")
    - Public key: hex string with 0x prefix (e.g., "0x957004...")
    
    All data is automatically fetched from the beacon chain API.
    
    **Response Structure:**
    - `validator_proof`: Merkle proof for validator existence
    - `balance_proof`: Merkle proof for validator balance
    - `state_root`: The beacon state root
    - Additional metadata including timestamps for smart contract validation
    
    **Use Cases:**
    - Efficient proof generation when both proofs are needed
    - Smart contract integrations requiring both validator and balance verification
    - Reduced API calls for complete validator verification
    """
    try:
        # Resolve validator identifier
        state_response = client.get_beacon_state(request.slot)
        if 'data' in state_response:
            state_data = state_response['data']
        else:
            state_data = state_response
            
        validators = state_data.get('validators', [])
        
        # Ensure pending_partial_withdrawals is present as empty list if missing
        if 'pending_partial_withdrawals' not in state_data:
            state_data['pending_partial_withdrawals'] = []
        
        # Resolve identifier to index
        if request.identifier.startswith('0x') and len(request.identifier) == 98:
            # Search for validator by pubkey
            pubkey_lower = request.identifier.lower()
            validator_index = None
            for idx, validator in enumerate(validators):
                if validator.get('pubkey', '').lower() == pubkey_lower:
                    validator_index = idx
                    break
            if validator_index is None:
                raise ValueError(f"Validator with pubkey {request.identifier} not found")
        else:
            # Parse as integer index
            validator_index = int(request.identifier)
            if validator_index < 0 or validator_index >= len(validators):
                raise ValueError(f"Validator index {validator_index} out of range (0-{len(validators)-1})")
        
        # Save state to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"data": state_data}, f)
            temp_file = f.name
        
        try:
            # Generate combined proof using main.py
            logger.info(f"Generating proof for validator {validator_index} using temp file {temp_file}")
            result: ProofCombinedResult = generate_validator_and_balance_proofs(temp_file, validator_index)
            
            # Add timestamp information to metadata
            if 'timestamp' in result.metadata:
                result.metadata['age_seconds'] = int(time.time() - result.metadata['timestamp'])
            
            # Add actual slot number to metadata
            result.metadata['slot'] = result.header.get('slot', state_data.get('slot'))
            
            # Convert ProofCombinedResult to response format
            return CombinedProofResponse(
                balance_proof=[f"0x{step.hex()}" for step in result.balance_proof],
                validator_proof=[f"0x{step.hex()}" for step in result.validator_proof],
                state_root=result.header['state_root'],  # Already has 0x prefix
                balance_leaf=f"0x{result.balance_leaf.hex()}",
                balances_root=f"0x{result.balances_root.hex()}",
                validator_index=result.validator_index,
                header=result.header,
                header_root=f"0x{result.header_root.hex()}",
                validator_data=result.validator_data,
                metadata=result.metadata
            )
        finally:
            # Clean up temporary file
            os.unlink(temp_file)
            
    except ValueError:
        raise
    except BeaconAPIError:
        raise
    except Exception as e:
        logger.error(f"Error in combined proof endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proofs/combined/{identifier}")
async def generate_combined_proof_get(
    identifier: str,
    slot: str = "head",
    prev_state_root: Optional[str] = None,
    prev_block_root: Optional[str] = None,
    client: BeaconAPIClient = Depends(get_beacon_client)
):
    """
    Generate combined validator and balance proof via GET request (convenience endpoint).
    
    Same functionality as POST endpoint but accessible via GET for simple integrations.
    
    Args:
        identifier: Validator index (e.g., "0", "123") or pubkey (e.g., "0x...")
    """
    # Create request object and use the POST endpoint logic
    request = CombinedProofRequest(
        identifier=identifier,
        slot=slot,
        prev_state_root=prev_state_root,
        prev_block_root=prev_block_root
    )
    
    result = await generate_combined_proof(request, client)
    
    # Convert response to dict for GET endpoint
    return result.model_dump()


def run_server(host: str = "127.0.0.1", port: int = 8000, dev: bool = False):
    """
    Run the API server.
    
    Args:
        host: Host to bind to
        port: Port to bind to  
        dev: Enable development mode with auto-reload
    """
    logger.info(f"Starting Bera Proofs API server on {host}:{port}")
    uvicorn.run(
        "bera_proofs.api.rest_api:app" if not dev else app,
        host=host,
        port=port,
        reload=dev,
        log_level="info"
    )


if __name__ == "__main__":
    run_server(dev=True) 