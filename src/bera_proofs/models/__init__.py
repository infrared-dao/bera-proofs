"""
API Models Package

This package contains request and response models for the beacon proof API.
It includes Pydantic models for validation and serialization of:

- Proof requests (validator index, slot, etc.)
- Proof responses (proof steps, roots, metadata)
- Error responses and status models

Usage:
    from bera_proofs.models import CombinedProofRequest, CombinedProofResponse
    
    request = CombinedProofRequest(identifier="42", slot="head")
"""

from .api_models import (
    CombinedProofRequest,
    CombinedProofResponse, 
    ErrorResponse,
    HealthResponse
)

__all__ = [
    'CombinedProofRequest',
    'CombinedProofResponse',
    'ErrorResponse', 
    'HealthResponse'
] 