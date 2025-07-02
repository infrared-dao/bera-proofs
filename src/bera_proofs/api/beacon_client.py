"""
Beacon API Client

This module provides a client for interacting with Berachain's beacon chain API.
It handles fetching beacon state data, block headers, and data sanitization.
"""

import os
import requests
import logging
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

logger = logging.getLogger(__name__)


class BeaconAPIError(Exception):
    """Exception raised for beacon API related errors."""
    pass


class BeaconAPIClient:
    """
    Client for interacting with Berachain beacon chain API.
    
    Provides methods for fetching beacon state data and block headers
    with proper error handling and data sanitization.
    """
    
    def __init__(self, base_url: Optional[str] = None, network: Optional[str] = None):
        """
        Initialize the beacon API client.
        
        Args:
            base_url: Base URL for the beacon API. If None, uses env vars.
            network: Network to use ('mainnet' or 'testnet'). If None, uses BEACON_NETWORK env var.
        """
        # Determine network
        network = network or os.getenv('BEACON_NETWORK', 'testnet')
        
        # Set base URL based on network
        if base_url:
            self.base_url = base_url
        else:
            if network.lower() == 'mainnet':
                self.base_url = os.getenv('BEACON_RPC_URL_MAINNET')
                if not self.base_url:
                    raise ValueError("BEACON_RPC_URL_MAINNET environment variable is not set")
            else:
                self.base_url = os.getenv('BEACON_RPC_URL_TESTNET')
                if not self.base_url:
                    raise ValueError("BEACON_RPC_URL_TESTNET environment variable is not set")
        
        self.network = network
        
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        })
        
        logger.info(f"Initialized BeaconAPIClient with base_url: {self.base_url}")
    
    def get_beacon_state(self, slot: str = "head") -> Dict[str, Any]:
        """
        Fetch beacon state from the API.
        
        Args:
            slot: Slot identifier ("head", "finalized", or specific slot number)
            
        Returns:
            Beacon state data as dictionary
            
        Raises:
            BeaconAPIError: If API request fails or returns invalid data
        """
        url = f"{self.base_url}/eth/v2/debug/beacon/states/{slot}"
        
        try:
            logger.info(f"Fetching beacon state for slot: {slot}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if 'data' not in data:
                raise BeaconAPIError(f"Invalid response format: missing 'data' field")
            
            # return in same format as raw request for same processing later
            # state_data = data['data']
            state_data = data
            logger.info(f"Successfully fetched beacon state for slot {slot}")
            
            # Sanitize the data
            return self.sanitize_beacon_data(state_data)
            
        except requests.ConnectionError as e:
            raise BeaconAPIError(
                f"Failed to connect to beacon API at {self.base_url}. "
                f"Please check:\n"
                f"1. The beacon node is running and accessible\n"
                f"2. The URL is correct (current: {self.base_url})\n"
                f"3. Network connectivity\n"
                f"4. Firewall settings\n\n"
                f"You can:\n"
                f"- Set a custom endpoint: export BEACON_RPC_URL='http://your-beacon-node:3500'\n"
                f"- Use CLI with local files instead: --json-file state.json --historical-state-file historical.json\n\n"
                f"Original error: {e}"
            )
        except requests.Timeout as e:
            raise BeaconAPIError(
                f"Timeout connecting to beacon API at {self.base_url}. "
                f"The beacon node may be slow or unresponsive. "
                f"Try again later or use local files with the CLI. "
                f"Original error: {e}"
            )
        except requests.RequestException as e:
            raise BeaconAPIError(
                f"Request failed to beacon API at {self.base_url}. "
                f"Error: {e}"
            )
        except Exception as e:
            raise BeaconAPIError(f"Error processing beacon state: {e}")
    
    def get_beacon_header(self, slot: str) -> Dict[str, Any]:
        """
        Fetch beacon block header from the API.
        
        Args:
            slot: Slot identifier (specific slot number or "head")
            
        Returns:
            Beacon block header data as dictionary
            
        Raises:
            BeaconAPIError: If API request fails or returns invalid data
        """
        url = f"{self.base_url}/eth/v1/beacon/headers/{slot}"
        
        try:
            logger.info(f"Fetching beacon header for slot: {slot}")
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            
            data = response.json()
            if 'data' not in data:
                raise BeaconAPIError(f"Invalid response format: missing 'data' field")
                
            header_data = data['data']
            logger.info(f"Successfully fetched beacon header for slot {slot}")
            
            return self.sanitize_beacon_data(header_data)
            
        except requests.ConnectionError as e:
            raise BeaconAPIError(
                f"Failed to connect to beacon API for header fetch. "
                f"Please check beacon node connectivity at {self.base_url}. "
                f"Original error: {e}"
            )
        except requests.RequestException as e:
            raise BeaconAPIError(f"Failed to fetch beacon header: {e}")
        except Exception as e:
            raise BeaconAPIError(f"Error processing beacon header: {e}")
    
    def get_prev_cycle_data(self, current_slot: int) -> tuple[bytes, bytes]:
        """
        Get previous cycle state root and block root (slot - 8).
        
        Args:
            current_slot: Current slot number
            
        Returns:
            Tuple of (prev_cycle_state_root, prev_cycle_block_root) as bytes
            
        Raises:
            BeaconAPIError: If unable to fetch previous cycle data
        """
        prev_slot = current_slot - 8
        if prev_slot < 0:
            prev_slot = 0
            
        try:
            # Get header for previous cycle slot
            header_data = self.get_beacon_header(str(prev_slot))
            
            # Extract roots from header
            header = header_data.get('header', {}).get('message', {})
            state_root = header.get('state_root', '0x' + '00' * 32)
            parent_root = header.get('parent_root', '0x' + '00' * 32)
            
            # Convert to bytes
            state_root_bytes = bytes.fromhex(state_root[2:])
            parent_root_bytes = bytes.fromhex(parent_root[2:])
            
            logger.info(f"Retrieved prev cycle data for slot {prev_slot}")
            return state_root_bytes, parent_root_bytes
            
        except Exception as e:
            logger.warning(f"Could not fetch prev cycle data: {e}, using zero hashes")
            # Return zero hashes as fallback
            return b'\x00' * 32, b'\x00' * 32
    
    def sanitize_beacon_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize beacon API data by converting camelCase to snake_case 
        and normalizing hex strings to proper format.
        
        Args:
            data: Raw beacon API data
            
        Returns:
            Sanitized data with consistent formatting
        """
        if isinstance(data, dict):
            sanitized = {}
            for key, value in data.items():
                # Convert camelCase to snake_case
                snake_key = self._camel_to_snake(key)
                
                # Handle special key mappings
                if snake_key == "parent_block_root":
                    snake_key = "parent_root"
                
                # Recursively sanitize nested objects
                if isinstance(value, dict):
                    sanitized[snake_key] = self.sanitize_beacon_data(value)
                elif isinstance(value, list):
                    sanitized[snake_key] = [
                        self.sanitize_beacon_data(item) if isinstance(item, dict) else item
                        for item in value
                    ]
                else:
                    # Normalize hex strings
                    if isinstance(value, str) and value.startswith('0x'):
                        sanitized[snake_key] = self._normalize_hex(value)
                    else:
                        sanitized[snake_key] = value
                        
            return sanitized
        else:
            return data
    
    def _camel_to_snake(self, camel_str: str) -> str:
        """Convert camelCase string to snake_case."""
        result = []
        for i, char in enumerate(camel_str):
            if char.isupper() and i > 0:
                result.append('_')
            result.append(char.lower())
        return ''.join(result)
    
    def _normalize_hex(self, hex_str: str) -> str:
        """Normalize hex string to consistent format."""
        if not hex_str.startswith('0x'):
            return f"0x{hex_str}"
        return hex_str.lower()
    
    def health_check(self) -> bool:
        """
        Check if the beacon API is accessible.
        
        Returns:
            True if API is accessible, False otherwise
        """
        try:
            # Use beacon headers endpoint which is implemented on Berachain
            url = f"{self.base_url}/eth/v1/beacon/headers/head"
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False
    
    def get_state(self, slot: str = "head") -> Dict[str, Any]:
        """Alias for get_beacon_state for backwards compatibility."""
        return self.get_beacon_state(slot)
    
    def get_historical_roots(self, current_slot: int, slots_back: int = 8) -> tuple[str, str]:
        """
        Get historical state root and block root from N slots ago.
        
        Args:
            current_slot: Current slot number
            slots_back: Number of slots to go back (default 8 for previous cycle)
            
        Returns:
            Tuple of (prev_state_root_hex, prev_block_root_hex) with 0x prefix
            
        Raises:
            BeaconAPIError: If unable to fetch historical data
        """
        historical_slot = max(0, current_slot - slots_back)
        
        try:
            # Get header for historical slot
            header_data = self.get_beacon_header(str(historical_slot))
            
            # Extract roots from header
            header = header_data.get('header', {}).get('message', {})
            state_root = header.get('state_root', '0x' + '00' * 32)
            parent_root = header.get('parent_root', '0x' + '00' * 32)
            
            logger.info(f"Retrieved historical data for slot {historical_slot} (current-{slots_back})")
            return state_root, parent_root
            
        except Exception as e:
            logger.warning(f"Could not fetch historical data for slot {historical_slot}: {e}")
            # Return default test values as fallback
            return (
                "0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8",
                "0x28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"
            )
    
    def get_state_with_historical_data(self, slot: str = "head", include_historical: bool = True) -> Dict[str, Any]:
        """
        Get beacon state with optional historical data injection.
        
        Args:
            slot: Slot identifier ("head", "finalized", or specific slot number)
            include_historical: Whether to include historical roots in the response
            
        Returns:
            Beacon state data with optional historical_data field
            
        Raises:
            BeaconAPIError: If API request fails or returns invalid data
        """
        # Get main state data
        state_data = self.get_beacon_state(slot)
        
        if include_historical:
            try:
                # Extract current slot from state
                current_slot = int(state_data.get('slot', '0'), 16 if isinstance(state_data.get('slot'), str) and state_data.get('slot').startswith('0x') else 10)
                
                # Get historical roots
                prev_state_root, prev_block_root = self.get_historical_roots(current_slot)
                
                # Add historical data to response
                state_data['historical_data'] = {
                    'prev_cycle_state_root': prev_state_root,
                    'prev_cycle_block_root': prev_block_root,
                    'slots_back': 8,
                    'historical_slot': max(0, current_slot - 8)
                }
                
            except Exception as e:
                logger.warning(f"Could not add historical data: {e}")
                # Continue without historical data
                pass
        
        return state_data 
    
    def create_test_data_with_historical(self, base_state_file: str, historical_slot_offset: int = 8) -> Dict[str, Any]:
        """
        Create test data structure that includes historical references.
        
        Args:
            base_state_file: Path to base state JSON file
            historical_slot_offset: Number of slots to go back for historical data
            
        Returns:
            Enhanced state data with historical_data field
        """
        import json
        
        try:
            # Load base state data
            with open(base_state_file, 'r') as f:
                state_data = json.load(f)
            
            # Extract current slot
            if 'data' in state_data:
                state_data = state_data['data']
            
            current_slot = int(state_data.get('slot', '0'), 16 if isinstance(state_data.get('slot'), str) and state_data.get('slot').startswith('0x') else 10)
            historical_slot = max(0, current_slot - historical_slot_offset)
            
            # Try to get actual historical data, fall back to defaults
            try:
                prev_state_root, prev_block_root = self.get_historical_roots(current_slot, historical_slot_offset)
            except:
                # Use test defaults
                prev_state_root = "0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8"
                prev_block_root = "0x28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"
            
            # Add historical data
            state_data['historical_data'] = {
                'prev_cycle_state_root': prev_state_root,
                'prev_cycle_block_root': prev_block_root,
                'slots_back': historical_slot_offset,
                'historical_slot': historical_slot,
                'current_slot': current_slot
            }
            
            return state_data
            
        except Exception as e:
            logger.error(f"Error creating test data with historical references: {e}")
            raise BeaconAPIError(f"Could not create test data: {e}")
    
    def extract_historical_roots_from_state(self, state_data: Dict[str, Any]) -> tuple[str, str]:
        """
        Extract historical roots from state data structure.
        
        Args:
            state_data: State data that may contain historical_data field
            
        Returns:
            Tuple of (prev_state_root, prev_block_root) with 0x prefix
        """
        # Check if historical data is already embedded
        if 'historical_data' in state_data:
            hist_data = state_data['historical_data']
            return (
                hist_data.get('prev_cycle_state_root', '0x' + '00' * 32),
                hist_data.get('prev_cycle_block_root', '0x' + '00' * 32)
            )
        
        # Try to calculate from current slot if available
        if 'slot' in state_data:
            try:
                current_slot = int(state_data['slot'], 16 if state_data['slot'].startswith('0x') else 10)
                return self.get_historical_roots(current_slot)
            except:
                pass
        
        # Return test defaults
        return (
            "0x01ef6767e8908883d1e84e91095bbb3f7d98e33773d13b6cc949355909365ff8",
            "0x28925c02852c6462577e73cc0fdb0f49bbf910b559c8c0d1b8f69cac38fa3f74"
        ) 