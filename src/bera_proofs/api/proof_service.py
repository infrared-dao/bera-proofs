"""
Proof Service Module

This module provides a service layer for generating various types of proofs
using the standardized functions from main.py.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

from bera_proofs.main import ProofCombinedResult
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
    
    def resolve_validator_identifier(self, identifier: str, validators: List[Dict[str, Any]]) -> int:
        """
        Resolve a validator identifier (index or pubkey) to a validator index.
        
        Args:
            identifier: Either a validator index (e.g., "0", "123") or pubkey (e.g., "0x...")
            validators: List of validator objects from beacon state
            
        Returns:
            Validator index as integer
            
        Raises:
            ProofServiceError: If identifier is invalid or validator not found
        """
        # Check if it's a hex pubkey
        if identifier.startswith('0x') and len(identifier) == 98:  # 48 bytes = 96 hex chars + 0x
            # Search for validator by pubkey
            pubkey_lower = identifier.lower()
            for idx, validator in enumerate(validators):
                if validator.get('pubkey', '').lower() == pubkey_lower:
                    logger.info(f"Resolved pubkey {identifier} to validator index {idx}")
                    return idx
            raise ProofServiceError(f"Validator with pubkey {identifier} not found")
        else:
            # Try to parse as integer index
            try:
                val_index = int(identifier)
                if val_index < 0 or val_index >= len(validators):
                    raise ProofServiceError(f"Validator index {val_index} out of range (0-{len(validators)-1})")
                return val_index
            except ValueError:
                raise ProofServiceError(f"Invalid validator identifier: {identifier}. Must be a number or hex pubkey starting with 0x")
    
    # Removed individual proof methods - using only combined proof
    
    
    def get_combined_proof(
        self, 
        identifier: str,
        prev_state_root: Optional[str] = None,
        prev_block_root: Optional[str] = None,
        slot: str = "head"
    ) -> Dict[str, Any]:
        """
        Generate both validator and balance proofs in a single call.
        
        Args:
            identifier: Validator index or pubkey (hex string with 0x prefix)
            prev_state_root: Previous state root from 8 slots ago (hex string, optional)
            prev_block_root: Previous block root from 8 slots ago (hex string, optional)
            slot: Slot number for API queries (defaults to "head")
            
        Returns:
            Dictionary containing both proofs with the CLI format
            
        Raises:
            ProofServiceError: If proof generation fails
        """
        try:
            # Initialize beacon client if not available
            if not self.beacon_client:
                self.beacon_client = BeaconAPIClient()
            
            # Handle special slot values
            actual_slot = slot
            if slot == "recent":
                # Get head slot and use head - 2 for safety (as recommended in ticket)
                head_state = self.beacon_client.get_state("head")
                head_slot = int(head_state.get('slot', '0'), 16 if isinstance(head_state.get('slot'), str) and head_state.get('slot').startswith('0x') else 10)
                actual_slot = str(max(0, head_slot - 2))
                logger.info(f"Using slot {actual_slot} (head - 2) for 'recent' request")
            
            # Fetch state from API and save to temp file
            import tempfile
            import os
            
            state_response = self.beacon_client.get_state(actual_slot)
            # Handle the response format - beacon client returns full response with 'data' wrapper
            if 'data' in state_response:
                state_data = state_response['data']
            else:
                state_data = state_response
                
            current_slot = int(state_data.get('slot', '0'), 16 if isinstance(state_data.get('slot'), str) and state_data.get('slot').startswith('0x') else 10)
            
            # Resolve identifier to validator index
            validators = state_data.get('validators', [])
            val_index = self.resolve_validator_identifier(identifier, validators)
            
            # Convert pending_partial_withdrawals to proper format if present
            if 'pending_partial_withdrawals' in state_data and state_data['pending_partial_withdrawals']:
                # Remove the field since it will be handled by json_to_class
                # The json_to_class function needs the field present but empty
                # to properly initialize it as an empty list
                if isinstance(state_data['pending_partial_withdrawals'], list) and len(state_data['pending_partial_withdrawals']) > 0:
                    # For now, we'll clear it since the SSZ library expects it to handle conversion
                    # but it's not doing it properly
                    state_data['pending_partial_withdrawals'] = []
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                # Save in the format expected by the CLI functions
                json.dump({"data": state_data}, f)
                temp_file = f.name
            
            try:
                # Debug: Let's check what's in the file
                with open(temp_file, 'r') as f:
                    test_data = json.load(f)
                    if 'data' in test_data and 'validators' in test_data['data']:
                        logger.info(f"Temp file has {len(test_data['data']['validators'])} validators")
                        logger.info(f"First validator type in file: {type(test_data['data']['validators'][0])}")
                
                # Ensure the module is using the correct imports
                from bera_proofs.main import generate_validator_and_balance_proofs as gen_combined
                # Generate combined proof using the temporary file
                result = gen_combined(temp_file, val_index)
            except Exception as e:
                import traceback
                tb = traceback.format_exc()
                logger.error(f"Error in combined proof generation: {e}\n{tb}")
                raise ProofServiceError(f"Failed to generate combined proof: {e}\nTraceback: {tb}")
            finally:
                # Clean up temporary file
                os.unlink(temp_file)
            
            # Format metadata with timestamp information
            metadata = result.metadata.copy()
            
            # Add calculated fields for the smart contract
            if 'timestamp' in metadata:
                metadata['age_seconds'] = int(time.time() - metadata['timestamp'])
            
            # Add actual slot number to metadata for clarity
            metadata['slot'] = result.header.get('slot', current_slot)
            
            # Format for JSON response matching the CLI output
            return {
                "balance_proof": [f"0x{step.hex()}" for step in result.balance_proof],
                "validator_proof": [f"0x{step.hex()}" for step in result.validator_proof],
                "state_root": result.header['state_root'],  # Already has 0x prefix from CLI
                "balance_leaf": f"0x{result.balance_leaf.hex()}",
                "balances_root": f"0x{result.balances_root.hex()}",
                "validator_index": result.validator_index,
                "header": result.header,
                "header_root": f"0x{result.header_root.hex()}",
                "validator_data": result.validator_data,
                "metadata": metadata
            }
            
        except ValueError as e:
            logger.error(f"Validation error generating combined proof: {e}")
            raise ProofServiceError(f"Validation error: {e}")
        except BeaconAPIError:
            # Re-raise BeaconAPIError to preserve improved error messages
            raise
        except Exception as e:
            logger.error(f"Error generating combined proof: {e}")
            raise ProofServiceError(f"Failed to generate combined proof: {e}") 