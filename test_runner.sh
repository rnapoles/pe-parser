#!/bin/bash
# PE Parser Test Runner Script for Linux/WSL
# This script runs all tests and generates a summary report

echo "======================================"
echo "PE Parser - Automated Test Suite"
echo "======================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results tracking
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Function to run a test and track results
run_test() {
    local test_name=$1
    local test_command=$2
    
    echo -e "${BLUE}Running: ${test_name}${NC}"
    echo "--------------------------------------"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    if eval "$test_command"; then
        echo -e "${GREEN}✓ ${test_name} PASSED${NC}"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        echo -e "${RED}✗ ${test_name} FAILED${NC}"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
}

# Clean and build
echo -e "${YELLOW}Building test suite...${NC}"
make clean
if ! make all; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
echo ""

# Run unit tests
run_test "Unit Tests" "make test"

# Run integration tests
run_test "Integration Tests" "make test-integration"

# Print summary
echo "======================================"
echo "TEST SUMMARY"
echo "======================================"
echo "Total Tests: $TOTAL_TESTS"
echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
if [ $FAILED_TESTS -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
else
    echo "Failed: $FAILED_TESTS"
fi

PASS_RATE=$((100 * PASSED_TESTS / TOTAL_TESTS))
echo "Pass Rate: ${PASS_RATE}%"
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
