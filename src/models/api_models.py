"""
API Models

This module defines Pydantic models for API request and response validation.
These models ensure proper data structure and type validation for the proof API.
"""

from typing import List, Optional, Union
from pydantic import BaseModel, Field, validator
from datetime import datetime


class ProofRequest(BaseModel):
    """
    Request model for proof generation endpoints.
    
    Attributes:
        val_index: Validator index for proof generation
        slot: Slot identifier ("head", "finalized", or specific slot number)
        prev_state_root: Optional previous state root from 8 slots ago (hex string)
        prev_block_root: Optional previous block root from 8 slots ago (hex string)
    """
    val_index: int = Field(..., ge=0, description="Validator index (must be >= 0)")
    slot: str = Field(default="head", description="Slot identifier")
    prev_state_root: Optional[str] = Field(default=None, description="Previous state root from 8 slots ago (hex string)")
    prev_block_root: Optional[str] = Field(default=None, description="Previous block root from 8 slots ago (hex string)")
    
    @validator('slot')
    def validate_slot(cls, v):
        """Validate slot parameter."""
        if v not in ["head", "finalized"] and not v.isdigit():
            raise ValueError("Slot must be 'head', 'finalized', or a valid number")
        return v
    
    @validator('prev_state_root')
    def validate_prev_state_root(cls, v):
        """Validate prev_state_root is proper hex string if provided."""
        if v is not None and (not v.startswith('0x') or len(v) != 66):
            raise ValueError("prev_state_root must be a 32-byte hex string starting with '0x'")
        return v
    
    @validator('prev_block_root')
    def validate_prev_block_root(cls, v):
        """Validate prev_block_root is proper hex string if provided."""
        if v is not None and (not v.startswith('0x') or len(v) != 66):
            raise ValueError("prev_block_root must be a 32-byte hex string starting with '0x'")
        return v


class ProofResponse(BaseModel):
    """
    Response model for successful proof generation.
    
    Attributes:
        proof: List of proof steps as hex strings
        root: Merkle root as hex string
        validator_index: Validator index used
        slot: Slot used for proof generation
        proof_type: Type of proof generated
        metadata: Additional metadata about the proof
    """
    proof: List[str] = Field(..., description="List of proof steps as hex strings")
    root: str = Field(..., description="Merkle root as hex string")
    validator_index: int = Field(..., description="Validator index used")
    slot: str = Field(..., description="Slot used for proof generation")
    proof_type: str = Field(..., description="Type of proof (validator/balance/proposer)")
    metadata: dict = Field(default_factory=dict, description="Additional proof metadata")
    
    @validator('proof')
    def validate_proof_format(cls, v):
        """Validate proof steps are proper hex strings."""
        for step in v:
            if not isinstance(step, str) or not step.startswith('0x'):
                raise ValueError("All proof steps must be hex strings starting with '0x'")
        return v
    
    @validator('root')
    def validate_root_format(cls, v):
        """Validate root is proper hex string."""
        if not v.startswith('0x') or len(v) != 66:  # 0x + 64 hex chars = 66
            raise ValueError("Root must be a 32-byte hex string")
        return v


class ErrorResponse(BaseModel):
    """
    Response model for API errors.
    
    Attributes:
        error: Error message
        code: Error code (string identifier)
        details: Additional error details
    """
    error: str = Field(..., description="Error message")
    code: str = Field(..., description="Error code")
    details: Optional[dict] = Field(default=None, description="Additional error details")


class HealthResponse(BaseModel):
    """
    Response model for health check endpoint.
    
    Attributes:
        status: Service status
        beacon_api: Beacon API connectivity status
        version: Service version
        timestamp: Response timestamp
    """
    status: str = Field(..., description="Service status")
    beacon_api: bool = Field(..., description="Beacon API connectivity")
    version: str = Field(default="0.1.0", description="Service version")
    timestamp: Optional[str] = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Response timestamp")


class ValidatorProofRequest(ProofRequest):
    """Request model specifically for validator proof generation."""
    pass


class BalanceProofRequest(ProofRequest):
    """Request model specifically for balance proof generation."""
    pass


class ValidatorProofResponse(ProofResponse):
    """Response model specifically for validator proofs."""
    proof_type: str = Field(default="validator", description="Proof type")
    
    class Config:
        schema_extra = {
            "example": {
                "proof": ["0x1234...", "0x5678..."],
                "root": "0xabcd...",
                "validator_index": 42,
                "slot": "head",
                "proof_type": "validator",
                "metadata": {
                    "proof_length": 45,
                    "validator_count": 100
                }
            }
        }


class BalanceProofResponse(ProofResponse):
    """Response model specifically for balance proofs."""
    proof_type: str = Field(default="balance", description="Proof type")
    
    class Config:
        schema_extra = {
            "example": {
                "proof": ["0x1234...", "0x5678..."],
                "root": "0xabcd...",
                "validator_index": 42,
                "slot": "head", 
                "proof_type": "balance",
                "metadata": {
                    "proof_length": 45,
                    "balance": "32000000000"
                }
            }
        } 