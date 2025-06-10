#!/usr/bin/env python3
"""
Simple integration test for Bera Proofs API

This script tests all the main API endpoints to ensure they're working correctly.
"""

import requests
import json
import sys
import os

# Add the parent directory to the path to import our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_api_endpoints():
    """Test all available API endpoints"""
    base_url = "http://localhost:8000"
    test_data_file = "test/data/state.json"
    
    # Test cases: (endpoint, description, expected_proof_type)
    test_cases = [
        (
            f"/proofs/validator/0?json_file={test_data_file}",
            "Validator proof generation",
            "validator"
        ),
        (
            f"/proofs/balance/0?json_file={test_data_file}",
            "Balance proof generation", 
            "balance"
        )
    ]
    
    print("🧪 Testing Bera Proofs API endpoints...")
    print("=" * 50)
    
    success_count = 0
    total_tests = len(test_cases)
    
    for endpoint, description, expected_type in test_cases:
        print(f"\n📋 Testing: {description}")
        print(f"🔗 Endpoint: {endpoint}")
        
        try:
            response = requests.get(f"{base_url}{endpoint}")
            
            if response.status_code == 200:
                data = response.json()
                
                # Validate response structure
                required_fields = ["proof", "root", "validator_index", "slot", "metadata"]
                missing_fields = [field for field in required_fields if field not in data]
                
                if missing_fields:
                    print(f"❌ Missing required fields: {missing_fields}")
                    continue
                
                # Validate proof structure
                if not isinstance(data["proof"], list) or len(data["proof"]) == 0:
                    print(f"❌ Invalid proof structure")
                    continue
                
                # Validate that all proof steps are hex strings
                if not all(isinstance(step, str) and step.startswith("0x") for step in data["proof"]):
                    print(f"❌ Invalid proof step format")
                    continue
                
                print(f"✅ Success!")
                print(f"   📊 Proof length: {len(data['proof'])}")
                print(f"   🔑 Root: {data['root'][:20]}...")
                print(f"   📍 Validator index: {data['validator_index']}")
                
                success_count += 1
                
            else:
                print(f"❌ Request failed with status {response.status_code}")
                print(f"   Response: {response.text}")
                
        except Exception as e:
            print(f"❌ Exception occurred: {e}")
    
    print("\n" + "=" * 50)
    print(f"🎯 Test Results: {success_count}/{total_tests} passed")
    
    if success_count == total_tests:
        print("🎉 All tests passed!")
        return True
    else:
        print("💥 Some tests failed!")
        return False

def test_health_endpoint():
    """Test the health endpoint"""
    print("🏥 Testing health endpoint...")
    
    try:
        response = requests.get("http://localhost:8000/health")
        if response.status_code == 200:
            data = response.json()
            print(f"✅ Health check passed: {data}")
            return True
        else:
            print(f"❌ Health check failed with status {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ Health check exception: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 Starting Bera Proofs API Integration Tests")
    print("📝 Make sure the API server is running on localhost:8000")
    print()
    
    # Test health endpoint first
    health_ok = test_health_endpoint()
    print()
    
    if not health_ok:
        print("💥 Health check failed - make sure API server is running!")
        return False
    
    # Test proof endpoints
    api_ok = test_api_endpoints()
    
    print("\n🏁 Integration tests completed!")
    return health_ok and api_ok

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1) 