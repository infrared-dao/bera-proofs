#!/usr/bin/env python3
"""
Test Runner for Refactored SSZ Library

This script runs all test suites for the refactored SSZ library and provides
comprehensive reporting on test results.
"""

import unittest
import sys
import os
from io import StringIO

# Add project root to path so 'src' module can be imported
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def run_test_suite(test_module_name, description):
    """
    Run a specific test suite and return results.
    
    Args:
        test_module_name: Name of the test module to run
        description: Human-readable description of the test suite
        
    Returns:
        Tuple of (success_count, failure_count, error_count, skip_count)
    """
    print(f"\n{'='*60}")
    print(f"Running {description}")
    print('='*60)
    
    # Import the test module
    test_module = __import__(test_module_name)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(test_module)
    
    # Create test runner with detailed output
    stream = StringIO()
    runner = unittest.TextTestRunner(
        stream=stream, 
        verbosity=2,
        resultclass=unittest.TextTestResult
    )
    
    # Run tests
    result = runner.run(suite)
    
    # Print results
    output = stream.getvalue()
    print(output)
    
    # Print summary
    total_tests = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    success = total_tests - failures - errors - skipped
    
    print(f"\n{description} Summary:")
    print(f"  Total Tests: {total_tests}")
    print(f"  Successful: {success}")
    print(f"  Failed: {failures}")
    print(f"  Errors: {errors}")
    print(f"  Skipped: {skipped}")
    
    if failures > 0:
        print(f"\nFailures in {description}:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
            
    if errors > 0:
        print(f"\nErrors in {description}:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return success, failures, errors, skipped

def main():
    """Run all test suites and provide comprehensive reporting."""
    print("Starting Refactored SSZ Library Test Suite")
    print(f"Python version: {sys.version}")
    print(f"Working directory: {os.getcwd()}")
    
    # Test suites to run
    test_suites = [
        ('test_refactored_compatibility', 'Compatibility Tests'),
        ('test_integration', 'Integration Tests'),
    ]
    
    total_success = 0
    total_failures = 0
    total_errors = 0
    total_skipped = 0
    
    # Run each test suite
    for module_name, description in test_suites:
        try:
            success, failures, errors, skipped = run_test_suite(module_name, description)
            total_success += success
            total_failures += failures
            total_errors += errors
            total_skipped += skipped
        except ImportError as e:
            print(f"\nError importing {module_name}: {e}")
            total_errors += 1
        except Exception as e:
            print(f"\nUnexpected error running {description}: {e}")
            total_errors += 1
    
    # Print overall summary
    print(f"\n{'='*60}")
    print("OVERALL TEST SUMMARY")
    print('='*60)
    
    total_tests = total_success + total_failures + total_errors + total_skipped
    
    print(f"Total Tests Run: {total_tests}")
    print(f"Successful: {total_success}")
    print(f"Failed: {total_failures}")
    print(f"Errors: {total_errors}")
    print(f"Skipped: {total_skipped}")
    
    if total_failures == 0 and total_errors == 0:
        print("\n🎉 ALL TESTS PASSED! 🎉")
        print("The refactored SSZ library is fully compatible with the original implementation.")
        return 0
    else:
        print(f"\n❌ Tests failed: {total_failures + total_errors} issues found")
        return 1

if __name__ == '__main__':
    sys.exit(main()) 