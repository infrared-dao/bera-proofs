#!/usr/bin/env python3
"""
Simple integration test for Bera Proofs API

This script tests all the main API endpoints to ensure they're working correctly.
"""

import requests
import json
import time
import sys
from typing import Dict, Any


def test_api_endpoint(endpoint: str, description: str) -> bool:
    """Test a single API endpoint and return success status."""
    try:
        print(f"Testing {description}...")
        response = requests.get(f"http://127.0.0.1:8000{endpoint}", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"  ✅ {description} - SUCCESS")
            return True
        else:
            print(f"  ❌ {description} - FAILED (Status: {response.status_code})")
            print(f"     Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"  ❌ {description} - ERROR: {e}")
        return False


def test_proof_endpoint(endpoint: str, description: str, expected_proof_type: str) -> bool:
    """Test a proof generation endpoint with detailed validation."""
    try:
        print(f"Testing {description}...")
        response = requests.get(f"http://127.0.0.1:8000{endpoint}", timeout=30)
        
        if response.status_code == 200:
            data = response.json()
            
            # Validate required fields
            required_fields = ['proof', 'root', 'validator_index', 'slot', 'proof_type', 'metadata']
            missing_fields = [field for field in required_fields if field not in data]
            
            if missing_fields:
                print(f"  ❌ {description} - Missing fields: {missing_fields}")
                return False
            
            # Validate proof format
            if not isinstance(data['proof'], list) or len(data['proof']) == 0:
                print(f"  ❌ {description} - Invalid proof format")
                return False
                
            # Check hex format
            if not all(step.startswith('0x') and len(step) == 66 for step in data['proof']):
                print(f"  ❌ {description} - Invalid hex format in proof")
                return False
                
            # Check root format
            if not data['root'].startswith('0x') or len(data['root']) != 66:
                print(f"  ❌ {description} - Invalid root format")
                return False
                
            # Check proof type
            if data['proof_type'] != expected_proof_type:
                print(f"  ❌ {description} - Wrong proof type: {data['proof_type']}")
                return False
            
            print(f"  ✅ {description} - SUCCESS")
            print(f"     Proof steps: {len(data['proof'])}")
            print(f"     Root: {data['root'][:10]}...")
            print(f"     Validator: {data['validator_index']}")
            return True
            
        else:
            print(f"  ❌ {description} - FAILED (Status: {response.status_code})")
            print(f"     Response: {response.text[:200]}...")
            return False
            
    except Exception as e:
        print(f"  ❌ {description} - ERROR: {e}")
        return False


def main():
    """Run all integration tests."""
    print("🧪 Bera Proofs API Integration Tests")
    print("=" * 50)
    
    # Wait for server to be ready
    print("Checking if API server is running...")
    for i in range(5):
        try:
            response = requests.get("http://127.0.0.1:8000/", timeout=2)
            if response.status_code == 200:
                print("✅ API server is ready!\n")
                break
        except:
            if i == 4:
                print("❌ API server is not running. Please start it first:")
                print("   poetry run python -m src.cli serve --host 127.0.0.1 --port 8000 --dev")
                sys.exit(1)
            time.sleep(1)
    
    results = []
    
    # Test basic endpoints
    results.append(test_api_endpoint("/", "Root endpoint"))
    results.append(test_api_endpoint("/health", "Health check"))
    
    # Test proof endpoints using local test data
    test_data_file = "test/data/state.json"
    
    results.append(test_proof_endpoint(
        f"/proofs/validator/0?json_file={test_data_file}", 
        "Validator proof generation", 
        "validator"
    ))
    
    results.append(test_proof_endpoint(
        f"/proofs/balance/0?json_file={test_data_file}", 
        "Balance proof generation", 
        "balance"
    ))
    
    results.append(test_proof_endpoint(
        f"/proofs/proposer/0?json_file={test_data_file}", 
        "Proposer proof generation", 
        "proposer"
    ))
    
    # Summary
    print("\n" + "=" * 50)
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"🎉 All tests passed! ({passed}/{total})")
        print("✅ The Bera Proofs API is working correctly!")
        sys.exit(0)
    else:
        print(f"❌ Some tests failed. ({passed}/{total} passed)")
        sys.exit(1)


if __name__ == "__main__":
    main() 