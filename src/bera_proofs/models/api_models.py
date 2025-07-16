"""
API Models

This module defines Pydantic models for API request and response validation.
These models ensure proper data structure and type validation for the proof API.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, validator
from datetime import datetime


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


class CombinedProofRequest(BaseModel):
    """
    Request model for combined validator and balance proof generation.
    
    Attributes:
        identifier: Validator identifier - either index (e.g., "0", "123") or pubkey (e.g., "0x...")
        slot: Slot identifier ("head", "finalized", or specific slot number)
        prev_state_root: Optional previous state root from 8 slots ago (hex string)
        prev_block_root: Optional previous block root from 8 slots ago (hex string)
    """
    identifier: str = Field(..., description="Validator index or pubkey (hex string with 0x prefix)")
    slot: str = Field(default="head", description="Slot identifier")
    prev_state_root: Optional[str] = Field(default=None, description="Previous state root from 8 slots ago (hex string)")
    prev_block_root: Optional[str] = Field(default=None, description="Previous block root from 8 slots ago (hex string)")
    
    @validator('identifier')
    def validate_identifier(cls, v):
        """Validate identifier is either a number or hex pubkey."""
        if not v:
            raise ValueError("Identifier cannot be empty")
        # Check if it's a pubkey (hex string)
        if v.startswith('0x'):
            if len(v) != 98:  # 0x + 96 hex chars
                raise ValueError("Pubkey must be 48 bytes (96 hex chars) with 0x prefix")
        else:
            # Must be a number
            try:
                int(v)
            except ValueError:
                raise ValueError("Identifier must be a number or hex pubkey starting with 0x")
        return v
    
    @validator('slot')
    def validate_slot(cls, v):
        """Validate slot parameter."""
        if v not in ["head", "finalized", "recent"] and not v.isdigit():
            raise ValueError("Slot must be 'head', 'finalized', 'recent', or a valid number")
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


class CombinedProofResponse(BaseModel):
    """
    Response model for combined validator and balance proofs.
    Matches the ProofCombinedResult from main.py for consistency.
    
    Attributes:
        balance_proof: List of balance proof steps as hex strings
        validator_proof: List of validator proof steps as hex strings
        state_root: State root as hex string
        balance_leaf: Balance leaf value as hex string
        balances_root: Balances merkle root as hex string
        validator_index: Validator index used
        header_root: Block header root as hex string
        header: Block header information
        validator_data: Validator data
        metadata: Additional metadata including timestamp
    """
    balance_proof: List[str] = Field(..., description="List of balance proof steps as hex strings")
    validator_proof: List[str] = Field(..., description="List of validator proof steps as hex strings")
    state_root: str = Field(..., description="State root as hex string")
    balance_leaf: str = Field(..., description="Balance leaf value as hex string")
    balances_root: str = Field(..., description="Balances merkle root as hex string")
    validator_index: int = Field(..., description="Validator index")
    header_root: str = Field(..., description="Block header root as hex string")
    header: dict = Field(..., description="Block header information")
    validator_data: dict = Field(..., description="Validator data")
    metadata: dict = Field(default_factory=dict, description="Additional proof metadata")
    
    @validator('balance_proof', 'validator_proof')
    def validate_proof_format(cls, v):
        """Validate proof steps are proper hex strings."""
        for step in v:
            if not isinstance(step, str) or not step.startswith('0x'):
                raise ValueError("All proof steps must be hex strings starting with '0x'")
        return v
    
    @validator('state_root', 'balance_leaf', 'balances_root', 'header_root')
    def validate_hex_format(cls, v):
        """Validate hex string format."""
        if not v.startswith('0x'):
            raise ValueError("Must be a hex string starting with '0x'")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "balance_proof": ["0x1234...", "0x5678..."],
                "validator_proof": ["0xabcd...", "0xef01..."],
                "state_root": "0x7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f",
                "balance_leaf": "0x00a0724e1809000000e038035059080000a0724e18090000b00e267154151500",
                "balances_root": "0x38c2283972c158ceadb3773bf85d4cf63c20b8ddcb8379213231edc9ad7d54a2",
                "validator_index": 67,
                "header_root": "0x7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f",
                "header": {
                    "slot": 5788402,
                    "proposer_index": 51,
                    "parent_root": "0x155f296b0f1125544889bf879fdcef2378af621cce314682da092ecc6adf8ec8",
                    "state_root": "0x7aac2bab3ed70e35ba9123b739f6375caed3b51c8c947703087b911d54b0cc9f",
                    "body_root": "0xea41d9a12d46e604dd4c8c52da906a1840635955cd105e5a8fbfa685964c593b"
                },
                "validator_data": {
                    "pubkey": "0xab2f79eeae163596276d5a56e52be4796df33377b157531a839a0174a68ca36e245bee122c4b5364176cf25ec2e0e8fc",
                    "withdrawal_credentials": "0x0100000000000000000000008c0e122960dc2e97dc0059c07d6901dce72818e1",
                    "effective_balance": 5930000000000000,
                    "slashed": False,
                    "activation_eligibility_epoch": 21945,
                    "activation_epoch": 21946,
                    "exit_epoch": 18446744073709551615,
                    "withdrawable_epoch": 18446744073709551615
                },
                "metadata": {
                    "timestamp": 1748773066,
                    "next_block_timestamp": 1748773078,
                    "age_seconds": 5,
                    "slot": 5788402,
                    "balance_proof_length": 44,
                    "validator_proof_length": 45,
                    "balance": "5934426930679472",
                    "effective_balance": "5930000000000000"
                }
            }
        } 