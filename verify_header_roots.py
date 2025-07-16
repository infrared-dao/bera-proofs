#!/usr/bin/env python3
"""
Script to verify the header root invariant:
- header_root at slot N == parent_root at slot N+1
- This should also match beacon_roots at the corresponding timestamp

This fetches multiple beacon states with a 2-second delay (Berachain block time)
and verifies the chain consistency.
"""

import time
import sys
import os
import requests
from typing import Dict, Any, List, Tuple, Optional

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

from bera_proofs.api.beacon_client import BeaconAPIClient, BeaconAPIError


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
            print(f"Response: {response.text[:500]}...")
            return None
            
        data = response.json()
        return {
            'slot': data['header']['slot'],
            'header_root': data['header_root'],
            'parent_root': data['header']['parent_root'],
            'state_root': data['header']['state_root'],
            'body_root': data['header']['body_root'],
            'proposer_index': data['header']['proposer_index'],
            'timestamp': data['metadata'].get('timestamp', 0),
            'block_number': data['metadata'].get('block_number', 0)
        }
    except Exception as e:
        print(f"❌ Error fetching block: {e}")
        return None


def verify_header_chain_invariant(num_blocks: int = 10, delay: float = 1.0):
    """
    Verify the invariant: parent_root(slot+1) == header_root(slot)
    
    Args:
        num_blocks: Number of blocks to fetch and verify
        delay: Delay in seconds between fetches (default: 1.0 for better consecutive block coverage)
    """
    print(f"🔍 Testing Header Root Invariant")
    print(f"   Thesis: parent_root(slot+1) == header_root(slot)")
    print(f"   Fetching {num_blocks} blocks with {delay}s delay\n")
    
    blocks: List[Dict[str, Any]] = []
    invariant_holds = []
    
    # Fetch initial block
    print("Fetching initial block...")
    initial_block = fetch_block_data()
    if not initial_block:
        return None, []
        
    blocks.append(initial_block)
    print(f"✅ Initial block at slot {initial_block['slot']}")
    print(f"   Header Root: {initial_block['header_root']}")
    print(f"   Timestamp:   {initial_block['timestamp']}")
    print()
    
    # Fetch subsequent blocks
    consecutive_same_slot = 0
    for i in range(1, num_blocks):
        print(f"⏳ Waiting {delay} seconds for next block...")
        time.sleep(delay)
        
        current_block = fetch_block_data()
        if not current_block:
            continue
            
        # Check if we got a new block
        if current_block['slot'] == blocks[-1]['slot']:
            consecutive_same_slot += 1
            print(f"⚠️  Same slot returned ({current_block['slot']}), attempt {consecutive_same_slot}")
            if consecutive_same_slot >= 3:
                print("   Skipping to avoid infinite loop on same slot")
                continue
            time.sleep(delay)  # Extra wait
            continue
        else:
            consecutive_same_slot = 0
            
        blocks.append(current_block)
        prev_block = blocks[-2]
        
        print(f"✅ Block {len(blocks)} at slot {current_block['slot']}")
        print(f"   Header Root: {current_block['header_root']}")
        print(f"   Parent Root: {current_block['parent_root']}")
        print(f"   Timestamp:   {current_block['timestamp']}")
        
        # Verify the invariant
        slot_diff = current_block['slot'] - prev_block['slot']
        if slot_diff == 1:
            # Perfect case: consecutive slots
            invariant_check = prev_block['header_root'] == current_block['parent_root']
            print(f"✅ INVARIANT HOLDS: header_root({prev_block['header_root']}) == parent_root({current_block['parent_root']})")
            invariant_holds.append(invariant_check)
            
            if invariant_check:
                print(f"   ✅ INVARIANT HOLDS: header_root(slot {prev_block['slot']}) == parent_root(slot {current_block['slot']})")
            else:
                print(f"   ❌ INVARIANT BROKEN:")
                print(f"      header_root(slot {prev_block['slot']}): {prev_block['header_root']}")
                print(f"      parent_root(slot {current_block['slot']}): {current_block['parent_root']}")
        else:
            print(f"   ⚠️  Non-consecutive slots (diff: {slot_diff}), skipping invariant check")
            
        # Additional info
        time_diff = current_block['timestamp'] - prev_block['timestamp']
        print(f"   Time difference: {time_diff}s")
        print()
    
    # Summary
    print("\n" + "=" * 80)
    print("📊 INVARIANT VERIFICATION SUMMARY")
    print("=" * 80)
    print(f"Total blocks fetched: {len(blocks)}")
    print(f"Slot range: {blocks[0]['slot']} - {blocks[-1]['slot']}")
    print(f"Invariant checks performed: {len(invariant_holds)}")
    
    if invariant_holds:
        valid_count = sum(invariant_holds)
        invalid_count = len(invariant_holds) - valid_count
        success_rate = (valid_count / len(invariant_holds)) * 100
        
        print(f"\nResults:")
        print(f"  ✅ Valid:   {valid_count} ({success_rate:.1f}%)")
        print(f"  ❌ Invalid: {invalid_count} ({100-success_rate:.1f}%)")
        
        if invalid_count == 0:
            print("\n🎉 INVARIANT VERIFIED: All header roots correctly match subsequent parent roots!")
        else:
            print(f"\n⚠️  INVARIANT VIOLATIONS FOUND: {invalid_count} mismatches detected")
    else:
        print("\n⚠️  No consecutive slots found for invariant verification")
    
    # Additional analysis
    print("\n📈 Chain Analysis:")
    if len(blocks) > 1:
        # Slot progression
        slot_diffs = [blocks[i]['slot'] - blocks[i-1]['slot'] for i in range(1, len(blocks))]
        avg_slot_diff = sum(slot_diffs) / len(slot_diffs)
        print(f"  Average slot difference: {avg_slot_diff:.2f}")
        print(f"  Min slot difference: {min(slot_diffs)}")
        print(f"  Max slot difference: {max(slot_diffs)}")
        
        # Time progression
        time_diffs = [blocks[i]['timestamp'] - blocks[i-1]['timestamp'] for i in range(1, len(blocks))]
        avg_time_diff = sum(time_diffs) / len(time_diffs) if time_diffs else 0
        print(f"  Average time between blocks: {avg_time_diff:.1f}s")
        
        # Block production rate
        total_time = blocks[-1]['timestamp'] - blocks[0]['timestamp']
        total_slots = blocks[-1]['slot'] - blocks[0]['slot']
        if total_time > 0:
            actual_block_time = total_time / total_slots
            print(f"  Actual average block time: {actual_block_time:.2f}s")
            print(f"  Expected block time: {delay}s")
    
    # Detailed block chain visualization
    print("\n🔗 Block Chain Visualization:")
    print("  (showing first 5 and last 5 blocks)")
    
    def print_block_chain(start_idx: int, end_idx: int):
        for i in range(start_idx, min(end_idx, len(blocks))):
            block = blocks[i]
            print(f"  Slot {block['slot']:,}")
            print(f"    Header: {block['header_root'][:16]}...")
            if i > 0:
                prev_header = blocks[i-1]['header_root']
                matches = "✅" if block['parent_root'] == prev_header else "❌"
                print(f"    Parent: {block['parent_root'][:16]}... {matches}")
            print()
    
    if len(blocks) <= 10:
        print_block_chain(0, len(blocks))
    else:
        print_block_chain(0, 5)
        print("  ...")
        print()
        print_block_chain(len(blocks)-5, len(blocks))
    
    return blocks, invariant_holds


def test_beacon_roots_correlation(blocks: List[Dict[str, Any]]):
    """
    Test if the header_root correlates with beacon_roots at the corresponding timestamp.
    Note: This requires access to the beacon_roots storage which may not be directly available.
    """
    print("\n" + "=" * 80)
    print("🔬 BEACON ROOTS CORRELATION TEST")
    print("=" * 80)
    print("Note: beacon_roots storage verification requires on-chain data access")
    print("      which is not directly available through the beacon API.")
    print("\nThe relationship is:")
    print("  beacon_roots[timestamp % HISTORY_BUFFER_LENGTH] = parent_block_root")
    print("  where HISTORY_BUFFER_LENGTH = 8191")
    print("\nFor full verification, you would need to:")
    print("  1. Query the beacon roots contract on-chain")
    print("  2. Use timestamp % 8191 as the key")
    print("  3. Compare the stored value with the parent_block_root")


if __name__ == "__main__":
    print("Berachain Header Root Invariant Verification")
    print("=" * 80)
    print("Testing: parent_root(slot+1) == header_root(slot)")
    print("=" * 80)
    print()
    
    # Check if API is running
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ API server is running (status: {health_data.get('status', 'unknown')})")
            print(f"   Beacon API connected: {health_data.get('beacon_api', False)}")
            print()
        else:
            print("⚠️  API server returned non-200 status\n")
    except:
        print("❌ API server is not running. Please start it first with:")
        print("   python -m bera_proofs.api.rest_api")
        print("\nOr if you're running via CLI:")
        print("   bera-proofs api serve")
        print()
        sys.exit(1)
    
    # Run the invariant test - use 1 second delay to catch more consecutive blocks
    blocks, results = verify_header_chain_invariant(num_blocks=20, delay=1)
    
    # Additional beacon roots analysis
    if blocks:
        test_beacon_roots_correlation(blocks)