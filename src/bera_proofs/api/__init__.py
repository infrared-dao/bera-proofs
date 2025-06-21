"""
Beacon API Integration Package

This package provides beacon chain API integration for fetching live state data
and generating merkle proofs. It includes:

- BeaconAPIClient: HTTP client for beacon chain API calls
- ProofService: Core proof generation with beacon integration  
- Endpoints: FastAPI router with proof generation endpoints

Usage:
    from bera_proofs.api import BeaconAPIClient, ProofService
    
    client = BeaconAPIClient()
    state = client.get_beacon_state("head")
"""

from .beacon_client import BeaconAPIClient
from .proof_service import ProofService

__all__ = [
    'BeaconAPIClient',
    'ProofService'
] 