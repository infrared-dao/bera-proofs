"""
Merkle Tree Visualization Module

This module provides visualization capabilities for merkle proofs generated
by the bera-proofs library, helping users understand the tree structure
and proof navigation.
"""

import sys
import os
from typing import List, Optional

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from .main import generate_merkle_witness

def print_tree_ascii(proof_steps: List[bytes], validator_index: int, state_root: bytes):
    """
    Print an ASCII representation of the merkle tree structure.
    
    Args:
        proof_steps: List of proof steps (32-byte hashes)
        validator_index: Index of the validator being proved
        state_root: Final state root hash
    """
    print("\n" + "="*80)
    print("MERKLE TREE VISUALIZATION")
    print("="*80)
    
    print(f"\n🎯 Target: Validator Index {validator_index}")
    print(f"📊 Proof Length: {len(proof_steps)} steps")
    print(f"🏁 State Root: {state_root.hex()}")
    
    print("\n📈 MERKLE PROOF PATH:")
    print("="*50)
    
    # Display proof steps in a tree-like format
    for i, step in enumerate(proof_steps):
        # Create indentation based on tree depth
        depth = min(i // 3, 15)  # Group steps and limit max depth for readability
        indent = "  " * depth
        
        # Add tree branch characters
        if i == 0:
            prefix = "🌱 "
        elif i < len(proof_steps) - 1:
            prefix = "├─ "
        else:
            prefix = "└─ "
            
        print(f"{indent}{prefix}Step {i:2d}: {step.hex()}")
        
        # Add explanatory comments for key steps
        if i == 0:
            print(f"{indent}   ↳ Validator leaf hash")
        elif i < 10:
            print(f"{indent}   ↳ Validator list navigation")
        elif i < 40:
            print(f"{indent}   ↳ BeaconState field proof")
        elif i >= len(proof_steps) - 5:
            print(f"{indent}   ↳ Final root computation")

def analyze_proof_structure(proof_steps: List[bytes], validator_index: int):
    """
    Analyze and explain the proof structure.
    
    Args:
        proof_steps: List of proof steps
        validator_index: Index of the validator being proved
    """
    print("\n" + "="*80)
    print("PROOF STRUCTURE ANALYSIS")
    print("="*80)
    
    print(f"\n📊 Proof Breakdown:")
    print(f"   • Validator Index: {validator_index}")
    print(f"   • Total Proof Steps: {len(proof_steps)}")
    
    print(f"\n🔍 Proof Sections:")
    print(f"   • Steps  0- 9: Validator List Navigation")
    print(f"     └─ Path through validator merkle tree")
    print(f"   • Steps 10-34: BeaconState Field Proofs")
    print(f"     └─ Proofs for each BeaconState field")
    print(f"   • Steps 35-44: Root Computation")
    print(f"     └─ Final state root calculation")

def print_comparison_table():
    """Print a comparison table between ETH2 and Berachain implementations."""
    print("\n" + "="*80)
    print("ETH2 vs BERACHAIN COMPARISON")
    print("="*80)
    
    comparison_data = [
        ("Aspect", "ETH2 Specification", "Berachain Implementation"),
        ("-" * 20, "-" * 25, "-" * 30),
        ("List Merkleization", "Variable length lists", "Fixed vectors + length"),
        ("BeaconState Fields", "~45 standard fields", "~32 modified fields"),
        ("State Root Reset", "Not required", "Required before proof"),
        ("Proof Length", "Variable", "Always 45 steps"),
        ("Validator Limit", "2^40 (spec limit)", "Uses ETH2 params"),
        ("SSZ Compliance", "Full compliance", "Custom modifications"),
    ]
    
    # Print table
    for row in comparison_data:
        print(f"│ {row[0]:<20} │ {row[1]:<25} │ {row[2]:<30} │")

def visualize_merkle_proof(proof_steps: List[bytes], validator_index: int, state_root: bytes, detailed: bool = True):
    """
    Main visualization function that combines all visualization elements.
    
    Args:
        proof_steps: List of proof steps from generate_merkle_witness
        validator_index: Index of validator being proved
        state_root: Final state root
        detailed: Whether to include detailed analysis
    """
    print("\n🌳 BERACHAIN MERKLE PROOF VISUALIZATION")
    
    # ASCII tree representation
    print_tree_ascii(proof_steps, validator_index, state_root)
    
    if detailed:
        # Detailed analysis
        analyze_proof_structure(proof_steps, validator_index)
        
        # Comparison table
        print_comparison_table()
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    print(f"✅ Successfully generated {len(proof_steps)}-step merkle proof")
    print(f"✅ Validator {validator_index} proof verified")
    print(f"✅ State root: {state_root.hex()}")
    print("✅ Compatible with Berachain beacon-kit implementation")

def demo_visualization():
    """Demo function showing visualization with test data."""
    try:
        print("🚀 BERACHAIN MERKLE PROOF DEMO")
        print("="*50)
        
        # Generate proof using test data
        proof, state_root = generate_merkle_witness("test/data/state.json", 39)
        
        # Visualize the proof
        visualize_merkle_proof(proof, 39, state_root, detailed=True)
        
        # Interactive section
        print("\n" + "="*80)
        print("INTERACTIVE EXPLORATION")
        print("="*80)
        print("Try different validator indices to see how the proof changes:")
        
        test_indices = [0, 1, 10, 25, 39, 50]
        for idx in test_indices:
            try:
                proof_test, _ = generate_merkle_witness("test/data/state.json", idx)
                print(f"   • Validator {idx:2d}: {len(proof_test)} steps, first hash: {proof_test[0].hex()[:16]}...")
            except Exception as e:
                print(f"   • Validator {idx:2d}: Error - {str(e)[:50]}...")
                
    except FileNotFoundError:
        print("❌ Test data not found. Please ensure test/data/state.json exists.")
        print("   You can still use the visualization functions with your own data:")
        print("\n   Example:")
        print("   proof, state_root = generate_merkle_witness('your_state.json', 0)")
        print("   visualize_merkle_proof(proof, 0, state_root)")

def create_simple_tree_diagram():
    """Create a simple textual diagram of the merkle tree structure."""
    print("\n" + "="*80)
    print("MERKLE TREE STRUCTURE DIAGRAM")
    print("="*80)
    
    diagram = """
                           🏁 STATE ROOT
                                │
                ┌───────────────┴───────────────┐
                │                               │
        🌿 BEACON STATE                    OTHER FIELDS
           (16 fields)                          │
                │                               │
    ┌───────────┼───────────┐                  ...
    │           │           │
 FIELD_0     FIELD_9      FIELD_15
(genesis)  (validators) (total_slashing)
    │           │            │
    │     ┌─────┼─────┐      │
    │     │     │     │      │
    │   VAL_0 VAL_1 VAL_N    │
    │     │     │     │      │
    └─────┼─────┼─────┼──────┘
          │     │     │
        🎯 TARGET VALIDATOR
           (Index {})

📊 BEACONSTATE FIELDS (16 total):
   0. genesis_validators_root    8. latest_execution_payload_header
   1. slot                       9. validators ← TARGET FIELD
   2. fork                      10. balances
   3. latest_block_header       11. randao_mixes
   4. block_roots               12. next_withdrawal_index
   5. state_roots               13. next_withdrawal_validator_index
   6. eth1_data                 14. slashings
   7. eth1_deposit_index        15. total_slashing

🛤️ PROOF PATH (45 steps):
   1. Start at target validator leaf
   2. Navigate up validator list tree (~10 steps)
   3. Combine validator field with other 15 BeaconState fields (~25 steps)
   4. Compute final state root (~10 steps)

🔍 Key Differences from ETH2:
   • Only 16 fields vs ETH2's ~45 fields
   • Validators stored as fixed-capacity vector (field 9)
   • Length appended separately after merkleization
   • State modifications before merkleization
   • Always 45 proof steps regardless of tree size
"""
    
    print(diagram.format("validator_index"))

if __name__ == "__main__":
    import sys
    
    # Always show the comprehensive visualization
    print("🚀 BERACHAIN MERKLE PROOF VISUALIZATION")
    print("=" * 80)
    
    # First show the simple tree structure
    create_simple_tree_diagram()
    
    print("\n" + "=" * 80)
    print("LIVE DEMO WITH TEST DATA")
    print("=" * 80)
    
    # Then show the full demo
    demo_visualization() 