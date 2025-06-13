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

from .proof_service import ProofService, ProofServiceError, ProofResult
from .beacon_client import BeaconAPIClient, BeaconAPIError
from ..models.api_models import (
    ProofRequest,
    ProofResponse,
    ErrorResponse,
    HealthResponse,
    ValidatorProofRequest,
    ValidatorProofResponse,
    BalanceProofRequest,
    BalanceProofResponse,
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Bera Proofs API",
    description="""
    Generate Merkle proofs for Berachain beacon state validators and balances.
    
    This API provides endpoints to generate cryptographic proofs that allow verification
    of specific validator data against the beacon chain state root without requiring
    the full state data.
    
    ## Features
    - **Validator Proofs**: Prove a validator exists in the state
    - **Balance Proofs**: Prove a validator's balance (both precise and effective)
    - **Live API Integration**: Automatically fetch fresh data from beacon chain
    - **Auto-fetch Historical**: Automatically retrieves required historical roots
    
    ## Proof Types
    All proof endpoints return a list of 32-byte merkle tree sibling hashes
    that can be used to reconstruct the root hash for verification.
    
    ## Data Sources
    The API exclusively uses live beacon chain data fetched via the standard
    Beacon API. For local file operations, use the CLI tool instead.
    """,
    version="1.0.0",
    contact={
        "name": "Bera Proofs Team",
        "url": "https://github.com/berachain/bera-proofs",
    },
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
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
            details={"error_type": "ProofServiceError"},
        ).model_dump(),
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
            details={"error_type": "BeaconAPIError"},
        ).model_dump(),
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
            details={"error_type": type(exc).__name__},
        ).model_dump(),
    )


@app.get("/", response_model=dict)
async def root():
    """API root endpoint with basic information."""
    return {
        "name": "Bera Proofs API",
        "version": "1.0.0",
        "description": "Generate Merkle proofs for Berachain beacon state",
        "docs": "/docs",
        "health": "/health",
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
            status="healthy", beacon_api=beacon_status, version="1.0.0"
        )
    except Exception as e:
        logger.warning(f"Health check failed: {e}")
        return HealthResponse(status="degraded", beacon_api=False, version="1.0.0")


@app.post("/proofs/validator", response_model=ValidatorProofResponse)
async def generate_validator_proof(
    request: ValidatorProofRequest, service: ProofService = Depends(get_proof_service)
):
    """
    Generate a validator existence proof.

    Generates a Merkle proof that proves a specific validator exists in the
    beacon state at the given slot. The proof can be verified against the
    state root to confirm the validator's presence.

    All data is automatically fetched from the beacon chain API.

    **Proof Structure:**
    - Validator proof within the validators list
    - State proof for the validators field

    **Use Cases:**
    - Verify validator registration
    - Prove validator participation in consensus
    - Validate validator data for external protocols
    """
    try:
        result = service.get_validator_proof(
            val_index=request.val_index,
            prev_state_root=request.prev_state_root,
            prev_block_root=request.prev_block_root,
            slot=request.slot,
        )

        return ValidatorProofResponse(
            proof=result["proof"],
            root=result["root"],
            validator_index=request.val_index,
            slot=request.slot,
            proof_type="validator",
            metadata=result["metadata"],
        )
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in validator proof endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/proofs/balance", response_model=BalanceProofResponse)
async def generate_balance_proof(
    request: BalanceProofRequest, service: ProofService = Depends(get_proof_service)
):
    """
    Generate a validator balance proof.

    Generates a Merkle proof that proves a validator's balance exists in the
    beacon state at the given slot. The proof includes both the precise balance
    and effective balance.

    All data is automatically fetched from the beacon chain API.

    **Proof Structure:**
    - Balance proof within the balances list
    - State proof for the balances field

    **Use Cases:**
    - Verify validator balance for external protocols
    - Prove staking rewards and penalties
    - Validate financial data for auditing
    """
    try:
        result = service.get_balances_proof(
            val_index=request.val_index,
            prev_state_root=request.prev_state_root,
            prev_block_root=request.prev_block_root,
            slot=request.slot,
        )

        return BalanceProofResponse(
            proof=result["proof"],
            root=result["root"],
            validator_index=request.val_index,
            slot=request.slot,
            proof_type="balance",
            metadata=result["metadata"],
        )
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in balance proof endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proofs/validator/{val_index}")
async def generate_validator_proof_get(
    val_index: int,
    slot: str = "head",
    prev_state_root: Optional[str] = None,
    prev_block_root: Optional[str] = None,
    service: ProofService = Depends(get_proof_service),
):
    """
    Generate validator proof via GET request (convenience endpoint).

    Same functionality as POST endpoint but accessible via GET for simple integrations.
    """
    try:
        result = service.get_validator_proof(
            val_index=val_index,
            prev_state_root=prev_state_root,
            prev_block_root=prev_block_root,
            slot=slot,
        )
        return result
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in validator proof GET endpoint: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/proofs/balance/{val_index}")
async def generate_balance_proof_get(
    val_index: int,
    slot: str = "head",
    prev_state_root: Optional[str] = None,
    prev_block_root: Optional[str] = None,
    service: ProofService = Depends(get_proof_service),
):
    """
    Generate balance proof via GET request (convenience endpoint).

    Same functionality as POST endpoint but accessible via GET for simple integrations.
    """
    try:
        result = service.get_balances_proof(
            val_index=val_index,
            prev_state_root=prev_state_root,
            prev_block_root=prev_block_root,
            slot=slot,
        )
        return result
    except ProofServiceError:
        raise
    except Exception as e:
        logger.error(f"Error in balance proof GET endpoint: {e}")
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
        "src.api.rest_api:app" if not dev else app,
        host=host,
        port=port,
        reload=dev,
        log_level="info",
    )


if __name__ == "__main__":
    run_server(dev=True)
