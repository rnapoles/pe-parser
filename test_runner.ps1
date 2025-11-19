# PE Parser Test Runner Script for Windows PowerShell
# This script runs all tests and generates a summary report

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "PE Parser - Automated Test Suite" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Test results tracking
$TotalTests = 0
$PassedTests = 0
$FailedTests = 0

# Function to run a test and track results
function Run-Test {
    param(
        [string]$TestName,
        [string]$TestCommand
    )
    
    Write-Host "Running: $TestName" -ForegroundColor Blue
    Write-Host "--------------------------------------"
    
    $script:TotalTests++
    
    try {
        Invoke-Expression $TestCommand
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ $TestName PASSED" -ForegroundColor Green
            $script:PassedTests++
        } else {
            Write-Host "✗ $TestName FAILED" -ForegroundColor Red
            $script:FailedTests++
        }
    } catch {
        Write-Host "✗ $TestName FAILED (Exception: $_)" -ForegroundColor Red
        $script:FailedTests++
    }
    
    Write-Host ""
}

# Clean and build
Write-Host "Building test suite..." -ForegroundColor Yellow
make clean
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}

make all
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Host ""

# Run unit tests
Run-Test "Unit Tests" "make test"

# Run integration tests
Run-Test "Integration Tests" "make test-integration"

# Print summary
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "TEST SUMMARY" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Total Tests: $TotalTests"
Write-Host "Passed: $PassedTests" -ForegroundColor Green

if ($FailedTests -gt 0) {
    Write-Host "Failed: $FailedTests" -ForegroundColor Red
} else {
    Write-Host "Failed: $FailedTests"
}

$PassRate = [math]::Round((100 * $PassedTests / $TotalTests), 2)
Write-Host "Pass Rate: ${PassRate}%"
Write-Host ""

if ($FailedTests -eq 0) {
    Write-Host "✓ ALL TESTS PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "✗ SOME TESTS FAILED" -ForegroundColor Red
    exit 1
}
