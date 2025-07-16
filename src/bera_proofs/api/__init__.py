"""
Beacon API Integration Package

This package provides beacon chain API integration for fetching live state data
and generating merkle proofs. It includes:

- BeaconAPIClient: HTTP client for beacon chain API calls

Usage:
    from bera_proofs.api import BeaconAPIClient
    
    client = BeaconAPIClient()
    state = client.get_beacon_state("head")
"""

from .beacon_client import BeaconAPIClient

__all__ = [
    'BeaconAPIClient'
] 