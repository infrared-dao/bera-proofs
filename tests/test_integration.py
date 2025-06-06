"""
Integration Tests for Refactored SSZ Library

This module contains integration tests that verify complete workflows
using the refactored SSZ library, testing end-to-end functionality.
"""

import unittest
import sys
import os
from typing import List

# Add parent directory to path for imports  
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from main import generate_merkle_witness

class TestIntegration(unittest.TestCase):
    """
    Integration tests for complete workflows using the refactored SSZ library.
    """

    def test_generate_merkle_witness_complete_workflow(self):
        """Test the complete generate_merkle_witness workflow"""
        try:
            # Test with the available test data
            proof, state_root = generate_merkle_witness("test/data/state.json", 39)
            
            # Verify the complete workflow produces expected results
            self.assertIsNotNone(proof)
            self.assertIsNotNone(state_root)
            
            # Verify the state root matches expected value
            expected_state_root = "12c3b9e21f6636e8f81bf4a501c00e5bdd789b561ae7e1455807dca558117992"
            actual_state_root = state_root.hex()
            self.assertEqual(actual_state_root, expected_state_root)
            
            # Verify proof structure and length
            self.assertEqual(len(proof), 45)
            
            # Print the proof structure for verification
            print("\nGenerated Merkle Witness:")
            print(f"State Root: {actual_state_root}")
            print(f"Proof Length: {len(proof)}")
            for i, step in enumerate(proof):
                print(f"Step {i}: {step.hex()}")
                
        except FileNotFoundError:
            self.skipTest("Test data file not found")
            
    def test_different_validator_indices(self):
        """Test generate_merkle_witness with different validator indices"""
        try:
            # Test multiple validator indices to ensure consistency
            indices_to_test = [0, 1, 39, 50]
            
            for validator_index in indices_to_test:
                with self.subTest(validator_index=validator_index):
                    proof, state_root = generate_merkle_witness("test/data/state.json", validator_index)
                    
                    # All should produce the same state root (since it's the same state)
                    expected_state_root = "12c3b9e21f6636e8f81bf4a501c00e5bdd789b561ae7e1455807dca558117992"
                    self.assertEqual(state_root.hex(), expected_state_root)
                    
                    # All proofs should have the same length (structure is consistent)
                    self.assertEqual(len(proof), 45)
                    
                    # Verify all proof elements are valid 32-byte hashes
                    for step in proof:
                        self.assertEqual(len(step), 32)
                        
        except FileNotFoundError:
            self.skipTest("Test data file not found")

    def test_error_handling(self):
        """Test error handling in the integration workflow"""
        # Test with non-existent file
        with self.assertRaises(FileNotFoundError):
            generate_merkle_witness("non_existent_file.json", 0)
            
        # Test with invalid validator index (negative)
        try:
            with self.assertRaises((AssertionError, IndexError, ValueError)):
                generate_merkle_witness("test/data/state.json", -1)
        except FileNotFoundError:
            self.skipTest("Test data file not found")


if __name__ == '__main__':
    unittest.main(verbosity=2) 