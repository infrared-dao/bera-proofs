"""
Proof Service Module

This module provides a service layer for generating various types of proofs
using the standardized functions from main.py.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from bera_proofs.main import generate_validator_proof, generate_balance_proof, ProofResult
from bera_proofs.ssz import load_and_process_state, BeaconState
from bera_proofs.api.beacon_client import BeaconAPIClient, BeaconAPIError

logger = logging.getLogger(__name__)


class ProofServiceError(Exception):
    """Custom exception for proof service operations."""
    pass


class ProofService:
    """Service for generating proofs for validators and balances."""
    
    def __init__(self, beacon_client: Optional[BeaconAPIClient] = None):
        """
        Initialize the proof service.
        
        Args:
            beacon_client: BeaconAPIClient instance. If None, a new client will
                         only be created when necessary for API calls.
        """
        self.beacon_client = beacon_client
    
    def get_validator_proof(
        self, 
        val_index: int,
        prev_state_root: Optional[str] = None,
        prev_block_root: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate a validator proof using auto-fetched beacon chain data.
        
        Args:
            val_index: Index of the validator to prove
            prev_state_root: Previous state root from 8 slots ago (hex string, optional)
            prev_block_root: Previous block root from 8 slots ago (hex string, optional)
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Initialize beacon client if not available
            if not self.beacon_client:
                self.beacon_client = BeaconAPIClient()
            
            # Fetch state from API and save to temp file
            import tempfile
            import os
            
            state_data = self.beacon_client.get_state(slot)
            current_slot = int(state_data.get('slot', '0'), 16 if isinstance(state_data.get('slot'), str) and state_data.get('slot').startswith('0x') else 10)
            
            # Auto-fetch historical data if not provided
            if prev_state_root is None or prev_block_root is None:
                fetched_state_root, fetched_block_root = self.beacon_client.get_historical_roots(current_slot)
                if prev_state_root is None:
                    prev_state_root = fetched_state_root
                if prev_block_root is None:
                    prev_block_root = fetched_block_root
                
                logger.info(f"Auto-fetched historical data: state_root={prev_state_root}, block_root={prev_block_root}")
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(state_data, f)
                temp_file = f.name
            
            try:
                # Generate proof using the temporary file
                result = generate_validator_proof(temp_file, val_index, prev_state_root, prev_block_root)
            finally:
                # Clean up temporary file
                os.unlink(temp_file)
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "validator_index": val_index,
                "slot": slot,
                "proof_type": "validator",
                "metadata": result.metadata,
                "historical_data": {
                    "prev_state_root": prev_state_root,
                    "prev_block_root": prev_block_root,
                    "auto_fetched": True
                }
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating validator proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except BeaconAPIError:
            # Re-raise BeaconAPIError to preserve improved error messages
            raise
        except Exception as e:
            logger.error(f"Error generating validator proof: {e}")
            raise ProofServiceError(f"Failed to generate validator proof: {e}")
    
    def get_balances_proof(
        self, 
        val_index: int,
        prev_state_root: Optional[str] = None,
        prev_block_root: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate a validator balance proof using auto-fetched beacon chain data.
        
        Args:
            val_index: Index of the validator balance to prove
            prev_state_root: Previous state root from 8 slots ago (hex string, optional)
            prev_block_root: Previous block root from 8 slots ago (hex string, optional)
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Initialize beacon client if not available
            if not self.beacon_client:
                self.beacon_client = BeaconAPIClient()
            
            # Fetch state from API and save to temp file
            import tempfile
            import os
            
            state_data = self.beacon_client.get_state(slot)
            current_slot = int(state_data.get('slot', '0'), 16 if isinstance(state_data.get('slot'), str) and state_data.get('slot').startswith('0x') else 10)
            
            # Auto-fetch historical data if not provided
            if prev_state_root is None or prev_block_root is None:
                fetched_state_root, fetched_block_root = self.beacon_client.get_historical_roots(current_slot)
                if prev_state_root is None:
                    prev_state_root = fetched_state_root
                if prev_block_root is None:
                    prev_block_root = fetched_block_root
                
                logger.info(f"Auto-fetched historical data: state_root={prev_state_root}, block_root={prev_block_root}")
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(state_data, f)
                temp_file = f.name
            
            try:
                # Generate proof using the temporary file
                result = generate_balance_proof(temp_file, val_index, prev_state_root, prev_block_root)
            finally:
                # Clean up temporary file
                os.unlink(temp_file)
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "validator_index": val_index,
                "slot": slot,
                "proof_type": "balance",
                "metadata": result.metadata,
                "historical_data": {
                    "prev_state_root": prev_state_root,
                    "prev_block_root": prev_block_root,
                    "auto_fetched": True
                }
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating balance proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except BeaconAPIError:
            # Re-raise BeaconAPIError to preserve improved error messages
            raise
        except Exception as e:
            logger.error(f"Error generating balance proof: {e}")
            raise ProofServiceError(f"Failed to generate balance proof: {e}") 