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

from .proof_service import ProofService, ProofServiceError
from .beacon_client import BeaconAPIClient, BeaconAPIError
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

# Global proof service instance
proof_service = None


def get_proof_service() -> ProofService:
    """Dependency to get the proof service instance."""
    global proof_service
    if proof_service is None:
        proof_service = ProofService()
    return proof_service


@app.exception_handler(ProofServiceError)
async def proof_service_exception_handler(request, exc: ProofServiceError):
    """Handle proof service errors."""
    logger.error(f"Proof service error: {exc}")
    return JSONResponse(
        status_code=400,
        content=ErrorResponse(
            error=str(exc),
            code="PROOF_GENERATION_ERROR",
            details={"error_type": "ProofServiceError"}
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
async def health_check(service: ProofService = Depends(get_proof_service)):
    """
    Health check endpoint.
    
    Checks the status of the API and beacon chain connectivity.
    """
    try:
        # Check beacon API connectivity
        beacon_status = service.beacon_client.health_check()
        
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


# Removed individual validator and balance endpoints - using only combined endpoint


@app.post("/proofs/combined", response_model=CombinedProofResponse)
async def generate_combined_proof(
    request: CombinedProofRequest,
    service: ProofService = Depends(get_proof_service)
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
        result = service.get_combined_proof(
            identifier=request.identifier,
            prev_state_root=request.prev_state_root,
            prev_block_root=request.prev_block_root,
            slot=request.slot
        )
        
        return CombinedProofResponse(**result)
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in combined proof endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Removed individual GET endpoints - using only combined endpoint


@app.get("/proofs/combined/{identifier}")
async def generate_combined_proof_get(
    identifier: str,
    slot: str = "head",
    prev_state_root: Optional[str] = None,
    prev_block_root: Optional[str] = None,
    service: ProofService = Depends(get_proof_service)
):
    """
    Generate combined validator and balance proof via GET request (convenience endpoint).
    
    Same functionality as POST endpoint but accessible via GET for simple integrations.
    
    Args:
        identifier: Validator index (e.g., "0", "123") or pubkey (e.g., "0x...")
    """
    try:
        result = service.get_combined_proof(
            identifier=identifier,
            prev_state_root=prev_state_root,
            prev_block_root=prev_block_root,
            slot=slot
        )
        return result
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in combined proof GET endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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