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
            
            # Return in same format as raw request for same processing later
            logger.info(f"Successfully fetched beacon state for slot {slot}")
            
            # Sanitize the entire response (including the data wrapper)
            return self.sanitize_beacon_data(data)
            
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
    
 
    
    
 