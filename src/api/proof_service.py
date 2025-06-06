"""
Proof Service Module

This module provides a service layer for generating various types of proofs
using the standardized functions from main.py.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from src.main import generate_validator_proof, generate_balance_proof, generate_proposer_proof
from ssz import load_and_process_state, BeaconState
from src.api.beacon_api import BeaconAPIClient, BeaconAPIError
from src.api.errors import ProofServiceError

logger = logging.getLogger(__name__)


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
        validator_index: int, 
        state_json_file: Optional[str] = None,
        slot: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate a validator existence proof.
        
        Args:
            validator_index: Index of the validator to prove
            state_json_file: Optional path to local JSON state file
            slot: Optional slot number for API queries (defaults to head)
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Load state data
            state, prev_state_root, prev_block_root = self._load_state_data(
                state_json_file, slot
            )
            
            # Generate proof using standardized function
            result = generate_validator_proof(
                state, validator_index, prev_state_root, prev_block_root
            )
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "validator_proof"
                }
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating validator proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating validator proof: {e}")
            raise ProofServiceError(f"Failed to generate validator proof: {e}")
    
    def get_balance_proof(
        self, 
        validator_index: int,
        state_json_file: Optional[str] = None,
        slot: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate a validator balance proof.
        
        Args:
            validator_index: Index of the validator balance to prove
            state_json_file: Optional path to local JSON state file
            slot: Optional slot number for API queries (defaults to head)
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Load state data
            state, prev_state_root, prev_block_root = self._load_state_data(
                state_json_file, slot
            )
            
            # Generate proof using standardized function
            result = generate_balance_proof(
                state, validator_index, prev_state_root, prev_block_root
            )
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "balance_proof"
                }
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating balance proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating balance proof: {e}")
            raise ProofServiceError(f"Failed to generate balance proof: {e}")
    
    def get_proposer_proof(
        self, 
        validator_index: int,
        state_json_file: Optional[str] = None,
        slot: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Generate a block proposer proof.
        
        Args:
            validator_index: Index of the validator to prove as proposer
            state_json_file: Optional path to local JSON state file
            slot: Optional slot number for API queries (defaults to head)
            
        Returns:
            Dictionary containing proof data with 0x prefix
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Load state data
            state, prev_state_root, prev_block_root = self._load_state_data(
                state_json_file, slot
            )
            
            # Generate proof using standardized function
            result = generate_proposer_proof(
                state, validator_index, prev_state_root, prev_block_root
            )
            
            # Format for JSON response with 0x prefix
            return {
                "proof": [f"0x{step.hex()}" for step in result.proof],
                "root": f"0x{result.root.hex()}",
                "metadata": {
                    **result.metadata,
                    "type": "proposer_proof"
                }
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating proposer proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except Exception as e:
            logger.error(f"Error generating proposer proof: {e}")
            raise ProofServiceError(f"Failed to generate proposer proof: {e}")
    
    def _load_state_data(
        self, 
        state_json_file: Optional[str] = None, 
        slot: Optional[int] = None
    ) -> tuple[BeaconState, Optional[bytes], Optional[bytes]]:
        """
        Load beacon state data either from JSON file or API.
        
        Args:
            state_json_file: Optional path to JSON state file
            slot: Optional slot number for API queries
            
        Returns:
            Tuple of (state, prev_state_root, prev_block_root)
            
        Raises:
            ProofServiceError: If data loading fails
        """
        try:
            # Try loading from JSON file first if provided
            if state_json_file:
                try:
                    state = load_and_process_state(state_json_file)
                    # When using local file, we use zero hashes for previous cycle
                    return state, None, None
                except Exception as e:
                    logger.warning(f"Failed to load state from JSON file {state_json_file}: {e}")
            
            # Fall back to API
            if self.beacon_client is None:
                self.beacon_client = BeaconAPIClient()
            
            # Get current state
            slot_id = slot if slot is not None else "head"
            state_response = self.beacon_client.get_state(slot_id)
            
            # Parse state JSON into BeaconState
            with open("temp_state.json", "w") as f:
                json.dump(state_response["data"], f)
            
            state = load_and_process_state("temp_state.json")
            
            # Get previous cycle data
            prev_state_root, prev_block_root = self._get_prev_cycle_data(state.slot)
            
            return state, prev_state_root, prev_block_root
            
        except BeaconAPIError as e:
            if state_json_file:
                # Try JSON fallback if API fails
                try:
                    state = load_and_process_state(state_json_file)
                    return state, None, None
                except Exception as fallback_error:
                    logger.error(f"Both API and JSON fallback failed: {e}, {fallback_error}")
                    raise ProofServiceError(f"Failed to load state: API error ({e}) and JSON fallback failed ({fallback_error})")
            else:
                raise ProofServiceError(f"Failed to fetch state from API: {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading state data: {e}")
            raise ProofServiceError(f"Failed to load state data: {e}")
    
    def _get_prev_cycle_data(self, slot: int) -> tuple[Optional[bytes], Optional[bytes]]:
        """
        Get previous cycle state and block roots.
        
        Args:
            slot: Current slot number
            
        Returns:
            Tuple of (prev_state_root, prev_block_root) or (None, None) if error
        """
        try:
            if self.beacon_client is None:
                self.beacon_client = BeaconAPIClient()
            
            # Calculate previous cycle slot (simplified - just subtract some slots)
            prev_slot = max(0, slot - 64)  # Go back ~64 slots
            
            prev_state = self.beacon_client.get_state(prev_slot)
            prev_block = self.beacon_client.get_block(prev_slot)
            
            prev_state_root = bytes.fromhex(prev_state["data"]["root"][2:])  # Remove 0x prefix
            prev_block_root = bytes.fromhex(prev_block["data"]["root"][2:])  # Remove 0x prefix
            
            return prev_state_root, prev_block_root
            
        except Exception as e:
            logger.warning(f"Failed to get previous cycle data: {e}. Using zero hashes.")
            return None, None 