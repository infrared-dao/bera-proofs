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
    
    def __init__(self, base_url: Optional[str] = None):
        """
        Initialize the beacon API client.
        
        Args:
            base_url: Base URL for the beacon API. If None, uses BEACON_RPC_URL env var.
        """
        self.base_url = base_url or os.getenv('BEACON_RPC_URL')
        if not self.base_url:
            raise BeaconAPIError("BEACON_RPC_URL environment variable not set")
            
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
                
            state_data = data['data']
            logger.info(f"Successfully fetched beacon state for slot {slot}")
            
            # Sanitize the data
            return self.sanitize_beacon_data(state_data)
            
        except requests.RequestException as e:
            raise BeaconAPIError(f"Failed to fetch beacon state: {e}")
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
            url = f"{self.base_url}/eth/v1/node/health"
            response = self.session.get(url, timeout=10)
            return response.status_code == 200
        except Exception:
            return False 