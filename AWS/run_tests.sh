#!/bin/bash
# Test runner script for Okta Event Hook Lambda functions

set -e

echo "=========================================="
echo "Okta Event Hook Lambda - Test Runner"
echo "=========================================="
echo ""

# Check if we're in the right directory
if [ ! -f "api-authoriser.py" ]; then
    echo "Error: Please run this script from the AWS/ directory"
    exit 1
fi

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found"
    exit 1
fi

echo "Step 1: Checking dependencies..."
if ! python3 -c "import boto3" 2>/dev/null; then
    echo "Installing dependencies..."
    pip3 install -q boto3 botocore
fi

echo "Step 2: Running basic integration tests..."
cd "$(dirname "$0")"
python3 test_integration.py

echo ""
echo "Step 3: Running unit tests (if pytest is available)..."
if command -v pytest &> /dev/null; then
    pytest test_lambda_functions.py -v
else
    echo "Pytest not found. Running basic tests instead..."
    python3 test_lambda_functions.py
fi

echo ""
echo "=========================================="
echo "Tests completed!"
echo "=========================================="

