"""
Proof Service Module

This module provides a service layer for generating various types of proofs
using the standardized functions from main.py.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from src.main import generate_validator_proof, generate_balance_proof, generate_proposer_proof, ProofResult
from src.ssz import load_and_process_state, BeaconState
from src.api.beacon_client import BeaconAPIClient, BeaconAPIError

logger = logging.getLogger(__name__)


class ProofServiceError(Exception):
    """Custom exception for proof service operations."""
    pass


class ProofService:
    """Service for generating proofs for validators, balances, and proposers."""
    
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
        json_file: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate a validator existence proof.
        
        Args:
            val_index: Index of the validator to prove
            json_file: Optional path to local JSON state file
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # If no JSON file provided, fetch from API and save temporarily
            if not json_file:
                if not self.beacon_client:
                    self.beacon_client = BeaconAPIClient()
                
                # Fetch state from API and save to temp file
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    state_data = self.beacon_client.get_state(slot)
                    json.dump(state_data, f)
                    temp_file = f.name
                
                try:
                    # Generate proof using the temporary file
                    result = generate_validator_proof(temp_file, val_index)
                finally:
                    # Clean up temporary file
                    os.unlink(temp_file)
            else:
                # Use provided JSON file
                result = generate_validator_proof(json_file, val_index)
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "validator_index": val_index,
                "slot": slot,
                "proof_type": "validator",
                "metadata": result.metadata
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating validator proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating validator proof: {e}")
            raise ProofServiceError(f"Failed to generate validator proof: {e}")
    
    def get_balances_proof(
        self, 
        val_index: int,
        json_file: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate a validator balance proof.
        
        Args:
            val_index: Index of the validator balance to prove
            json_file: Optional path to local JSON state file
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # If no JSON file provided, fetch from API and save temporarily
            if not json_file:
                if not self.beacon_client:
                    self.beacon_client = BeaconAPIClient()
                
                # Fetch state from API and save to temp file
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    state_data = self.beacon_client.get_state(slot)
                    json.dump(state_data, f)
                    temp_file = f.name
                
                try:
                    # Generate proof using the temporary file
                    result = generate_balance_proof(temp_file, val_index)
                finally:
                    # Clean up temporary file
                    os.unlink(temp_file)
            else:
                # Use provided JSON file
                result = generate_balance_proof(json_file, val_index)
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "validator_index": val_index,
                "slot": slot,
                "proof_type": "balance",
                "metadata": result.metadata
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating balance proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating balance proof: {e}")
            raise ProofServiceError(f"Failed to generate balance proof: {e}")
    
    def get_proposer_proof(
        self, 
        val_index: int,
        json_file: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate a block proposer proof.
        
        Args:
            val_index: Index of the validator to prove as proposer
            json_file: Optional path to local JSON state file
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # If no JSON file provided, fetch from API and save temporarily
            if not json_file:
                if not self.beacon_client:
                    self.beacon_client = BeaconAPIClient()
                
                # Fetch state from API and save to temp file
                import tempfile
                import os
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    state_data = self.beacon_client.get_state(slot)
                    json.dump(state_data, f)
                    temp_file = f.name
                
                try:
                    # Generate proof using the temporary file
                    result = generate_proposer_proof(temp_file, val_index)
                finally:
                    # Clean up temporary file
                    os.unlink(temp_file)
            else:
                # Use provided JSON file
                result = generate_proposer_proof(json_file, val_index)
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "validator_index": val_index,
                "slot": slot,
                "proof_type": "proposer",
                "metadata": result.metadata
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating proposer proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating proposer proof: {e}")
            raise ProofServiceError(f"Failed to generate proposer proof: {e}") 