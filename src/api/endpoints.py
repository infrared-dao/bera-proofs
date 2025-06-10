import logging
from typing import Optional
from fastapi import FastAPI, HTTPException, Query
from .proof_service import ProofService, ProofServiceError

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Beacon Chain Proof Service",
    description="API for generating Merkle proofs for Beacon Chain state data",
    version="1.0.0"
)

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "beacon-proof-service"}

@app.get("/validator/{val_index}/proof")
async def get_validator_proof(
    val_index: int,
    prev_state_root: Optional[str] = Query(None, description="Previous state root from 8 slots ago (hex string, auto-fetched if not provided)"),
    prev_block_root: Optional[str] = Query(None, description="Previous block root from 8 slots ago (hex string, auto-fetched if not provided)"),
    json_file: Optional[str] = Query(None, description="Path to JSON state file"),
    slot: str = Query("head", description="Slot number"),
    auto_fetch_historical: bool = Query(True, description="Automatically fetch historical data if not provided")
):
    """Get validator proof for specified validator index."""
    try:
        proof_service = ProofService()
        result = proof_service.get_validator_proof(
            val_index, prev_state_root, prev_block_root, json_file, slot, auto_fetch_historical
        )
        return result
    except ProofServiceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/validator/{val_index}/balance/proof")
async def get_balance_proof(
    val_index: int,
    prev_state_root: Optional[str] = Query(None, description="Previous state root from 8 slots ago (hex string, auto-fetched if not provided)"),
    prev_block_root: Optional[str] = Query(None, description="Previous block root from 8 slots ago (hex string, auto-fetched if not provided)"),
    json_file: Optional[str] = Query(None, description="Path to JSON state file"),
    slot: str = Query("head", description="Slot number"),
    auto_fetch_historical: bool = Query(True, description="Automatically fetch historical data if not provided")
):
    """Get validator balance proof for specified validator index."""
    try:
        proof_service = ProofService()
        result = proof_service.get_balances_proof(
            val_index, prev_state_root, prev_block_root, json_file, slot, auto_fetch_historical
        )
        return result
    except ProofServiceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/validator/{val_index}/proposer/proof")
async def get_proposer_proof(
    val_index: int,
    prev_state_root: Optional[str] = Query(None, description="Previous state root from 8 slots ago (hex string, auto-fetched if not provided)"),
    prev_block_root: Optional[str] = Query(None, description="Previous block root from 8 slots ago (hex string, auto-fetched if not provided)"),
    json_file: Optional[str] = Query(None, description="Path to JSON state file"),
    slot: str = Query("head", description="Slot number"),
    auto_fetch_historical: bool = Query(True, description="Automatically fetch historical data if not provided")
):
    """Get block proposer proof for specified validator index."""
    try:
        proof_service = ProofService()
        result = proof_service.get_proposer_proof(
            val_index, prev_state_root, prev_block_root, json_file, slot, auto_fetch_historical
        )
        return result
    except ProofServiceError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 