#!/usr/bin/env python3
"""
Script to verify header roots against on-chain beacon roots contract.

This script:
1. Fetches blocks via API with 1-second intervals
2. Computes header roots
3. After collecting blocks, queries the beacon roots contract on-chain
4. Verifies that our computed header roots match the on-chain data
"""

import time
import sys
import os
import requests
import json
from typing import Dict, Any, List, Tuple, Optional
from web3 import Web3
from datetime import datetime

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from bera_proofs.api.beacon_client import BeaconAPIClient

# Constants
BEACON_ROOTS_ADDRESS = "0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02"
RPC_URL = "https://bepolia.rpc.berachain.com"
HISTORY_BUFFER_LENGTH = 8191

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))

def get_beacon_root_from_contract(timestamp: int) -> Optional[str]:
    """
    Query the beacon roots contract for a specific timestamp.
    
    Args:
        timestamp: The timestamp to query
        
    Returns:
        The beacon root as hex string, or None if not found
    """
    try:
        # Encode the timestamp as uint256
        encoded_timestamp = timestamp.to_bytes(32, byteorder='big')
        
        # Make the static call
        result = w3.eth.call({
            'to': BEACON_ROOTS_ADDRESS,
            'data': '0x' + encoded_timestamp.hex()
        })
        
        # Decode the result
        if result and len(result) == 32:
            return '0x' + result.hex()
        return None
    except Exception as e:
        print(f"Error querying contract: {e}")
        return None


def fetch_block_data(identifier: str = "0", slot: str = "head") -> Optional[Dict[str, Any]]:
    """
    Fetch block data from the API.
    
    Returns:
        Dict with slot, header_root, parent_root, state_root, timestamp
    """
    try:
        response = requests.post(
            "http://localhost:8000/proofs/combined",
            json={"identifier": identifier, "slot": slot}
        )
        
        if response.status_code != 200:
            print(f"❌ Failed to fetch block: {response.status_code}")
            return None
            
        data = response.json()
        return {
            'slot': data['header']['slot'],
            'header_root': data['header_root'],
            'parent_root': data['header']['parent_root'],
            'state_root': data['header']['state_root'],
            'timestamp': data['metadata'].get('timestamp', 0),
            'proposer_index': data['header']['proposer_index']
        }
    except Exception as e:
        print(f"❌ Error fetching block: {e}")
        return None


def verify_header_roots_onchain(num_blocks: int = 15, delay: float = 1.0):
    """
    Collect blocks and then verify against on-chain beacon roots.
    
    Args:
        num_blocks: Number of blocks to collect
        delay: Delay between fetches (1 second for better coverage)
    """
    print("🔍 Beacon Root On-Chain Verification")
    print("=" * 60)
    print(f"Collecting {num_blocks} blocks with {delay}s intervals...")
    print(f"Beacon Roots Contract: {BEACON_ROOTS_ADDRESS}")
    print(f"RPC: {RPC_URL}")
    print()
    
    blocks: List[Dict[str, Any]] = []
    
    # Phase 1: Collect blocks
    print("📊 Phase 1: Collecting Blocks")
    print("-" * 40)
    
    for i in range(num_blocks):
        if i > 0:
            time.sleep(delay)
            
        block = fetch_block_data()
        if not block:
            continue
            
        blocks.append(block)
        print(f"Block {len(blocks)}: slot={block['slot']}, timestamp={block['timestamp']}")
    
    print(f"\n✅ Collected {len(blocks)} blocks")
    print(f"   Slot range: {blocks[0]['slot']} - {blocks[-1]['slot']}")
    print(f"   Time range: {blocks[0]['timestamp']} - {blocks[-1]['timestamp']}")
    
    # Phase 2: Verify parent roots against on-chain data
    print("\n📊 Phase 2: On-Chain Verification")
    print("-" * 40)
    print("Checking if parent_root matches beacon roots contract...\n")
    
    matches = 0
    mismatches = 0
    not_found = 0
    
    for i in range(len(blocks)):
        block = blocks[i]
        
        # For each block, its parent_root should be stored at its timestamp
        # in the beacon roots contract
        print(f"Block at slot {block['slot']} (timestamp {block['timestamp']}):")
        print(f"  Parent Root: {block['parent_root']}")
        
        # Query the contract
        onchain_root = get_beacon_root_from_contract(block['timestamp'])
        
        if onchain_root:
            print(f"  On-chain:    {onchain_root}")
            
            if block['parent_root'].lower() == onchain_root.lower():
                print("  ✅ MATCH!")
                matches += 1
            else:
                print("  ❌ MISMATCH!")
                mismatches += 1
        else:
            print("  ⚠️  Not found on-chain")
            not_found += 1
            
        # Also check the invariant between consecutive blocks
        if i > 0 and blocks[i]['slot'] == blocks[i-1]['slot'] + 1:
            prev_header = blocks[i-1]['header_root']
            curr_parent = blocks[i]['parent_root']
            
            if prev_header == curr_parent:
                print(f"  ✅ Invariant holds: header_root({blocks[i-1]['slot']}) == parent_root({blocks[i]['slot']})")
            else:
                print(f"  ❌ Invariant broken!")
        
        print()
    
    # Phase 3: Summary
    print("\n" + "=" * 60)
    print("📊 VERIFICATION SUMMARY")
    print("=" * 60)
    print(f"Total blocks checked: {len(blocks)}")
    print(f"\nOn-chain verification:")
    print(f"  ✅ Matches:    {matches}")
    print(f"  ❌ Mismatches: {mismatches}")
    print(f"  ⚠️  Not found:  {not_found}")
    
    if matches > 0 and mismatches == 0:
        print("\n🎉 All found entries match! The beacon roots contract correctly stores parent roots.")
    elif mismatches > 0:
        print("\n❌ Found mismatches between computed and on-chain roots!")
    
    # Additional info about the contract storage
    print(f"\n📝 Contract Storage Info:")
    print(f"  - Parent roots are stored at: timestamp % {HISTORY_BUFFER_LENGTH}")
    print(f"  - Storage is circular with {HISTORY_BUFFER_LENGTH} slots")
    print(f"  - Roots are overwritten after ~{HISTORY_BUFFER_LENGTH * 2 // 3600} hours")
    
    return blocks


def check_specific_timestamp(timestamp: int):
    """Helper to check a specific timestamp against the contract."""
    print(f"\n🔍 Checking specific timestamp: {timestamp}")
    root = get_beacon_root_from_contract(timestamp)
    if root:
        print(f"   Beacon root: {root}")
    else:
        print("   No root found")
    return root


if __name__ == "__main__":
    print("Berachain On-Chain Beacon Root Verification")
    print("=" * 60)
    
    # Check if API is running
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code != 200:
            raise Exception("API not healthy")
        print("✅ API server is running\n")
    except:
        print("❌ API server is not running. Please start it first with:")
        print("   poetry run uvicorn bera_proofs.api.rest_api:app")
        sys.exit(1)
    
    # Check Web3 connection
    try:
        block_number = w3.eth.block_number
        print(f"✅ Connected to RPC (block #{block_number})")
        
        # Check if contract exists
        code = w3.eth.get_code(BEACON_ROOTS_ADDRESS)
        if code == b'':
            print(f"❌ No contract found at {BEACON_ROOTS_ADDRESS}")
            sys.exit(1)
        print(f"✅ Beacon roots contract found at {BEACON_ROOTS_ADDRESS}\n")
    except Exception as e:
        print(f"❌ Failed to connect to RPC: {e}")
        sys.exit(1)
    
    # Run the verification
    blocks = verify_header_roots_onchain(num_blocks=15, delay=1.0)
    
    # Optional: Test a specific recent timestamp
    if blocks and len(blocks) > 5:
        print("\n" + "=" * 60)
        print("Testing direct contract query with a recent timestamp...")
        test_timestamp = blocks[5]['timestamp']
        check_specific_timestamp(test_timestamp)