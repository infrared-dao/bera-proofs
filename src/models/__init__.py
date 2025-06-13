"""
API Models Package

This package contains request and response models for the beacon proof API.
It includes Pydantic models for validation and serialization of:

- Proof requests (validator index, slot, etc.)
- Proof responses (proof steps, roots, metadata)
- Error responses and status models

Usage:
    from src.models import ProofRequest, ProofResponse
    
    request = ProofRequest(val_index=42, slot="head")
"""

from .api_models import ProofRequest, ProofResponse, ErrorResponse, HealthResponse

__all__ = ["ProofRequest", "ProofResponse", "ErrorResponse", "HealthResponse"]
