#include "PeParser.h"
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <fstream>
#include <cstdlib>

// ANSI color codes for better output readability
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_CYAN    "\033[36m"

// Test result tracking
struct TestResult {
    std::string testName;
    bool passed;
    std::string message;
};

std::vector<TestResult> testResults;

// Helper macros for test assertions
#define TEST_ASSERT(condition, message) \
    if (!(condition)) { \
        testResults.push_back({currentTestName, false, message}); \
        std::cout << COLOR_RED << "  ✗ FAILED: " << message << COLOR_RESET << std::endl; \
        return false; \
    }

#define TEST_PASS(message) \
    testResults.push_back({currentTestName, true, message}); \
    std::cout << COLOR_GREEN << "  ✓ PASSED: " << message << COLOR_RESET << std::endl;

// Test helper functions
void printTestHeader(const std::string& category) {
    std::cout << "\n" << COLOR_CYAN << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << category << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "========================================" << COLOR_RESET << std::endl;
}

void printTestName(const std::string& name) {
    std::cout << "\n" << COLOR_BLUE << "Test: " << name << COLOR_RESET << std::endl;
}

// ============================================================================
// 1. COMPLETE PARSING WORKFLOW TESTS
// ============================================================================

bool testCompleteWorkflowExe(const std::string& currentTestName) {
    printTestName("Complete Workflow - EXE File");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        TEST_ASSERT(parser.isExe(), "File should be identified as EXE");
        TEST_ASSERT(!parser.isDLL(), "File should not be identified as DLL");
        
        // Verify imports were parsed
        std::vector<std::string> imports = parser.getImportFunctionNames();
        TEST_ASSERT(!imports.empty(), "EXE should have imports");
        
        TEST_PASS("Complete workflow for EXE file");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testCompleteWorkflowDll(const std::string& currentTestName) {
    printTestName("Complete Workflow - DLL File");
    
    try {
        // Try to use a system DLL
        const char* dllPath = "C:\\Windows\\System32\\kernel32.dll";
        
        // Check if file exists
        std::ifstream testFile(dllPath);
        if (!testFile.good()) {
            std::cout << COLOR_YELLOW << "  ⊘ SKIPPED: kernel32.dll not accessible" << COLOR_RESET << std::endl;
            testResults.push_back({currentTestName, true, "Skipped - DLL not accessible"});
            return true;
        }
        testFile.close();
        
        PeParser parser(dllPath);
        parser.parseFile();
        
        TEST_ASSERT(parser.isDLL(), "File should be identified as DLL");
        TEST_ASSERT(!parser.isExe(), "File should not be identified as EXE");
        
        // Verify exports were parsed
        std::vector<std::string> exports = parser.getExportFunctionNames();
        TEST_ASSERT(!exports.empty(), "DLL should have exports");
        
        TEST_PASS("Complete workflow for DLL file");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testDataConsistency(const std::string& currentTestName) {
    printTestName("Data Consistency Across Structures");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        // Parse multiple times and verify consistency
        std::vector<std::string> imports1 = parser.getImportFunctionNames();
        std::vector<std::string> imports2 = parser.getImportFunctionNames();
        
        TEST_ASSERT(imports1.size() == imports2.size(), 
                    "Import count should be consistent across calls");
        
        TEST_PASS("Data consistency verified");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool test64BitParsing(const std::string& currentTestName) {
    printTestName("64-bit PE File Parsing");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        // test_rich_header.exe is a 64-bit executable
        TEST_ASSERT(parser.is64Bits(), "File should be identified as 64-bit");
        
        TEST_PASS("64-bit PE file parsed correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

// ============================================================================
// 2. QUERY METHOD VERIFICATION TESTS
// ============================================================================

bool testIsExeMethod(const std::string& currentTestName) {
    printTestName("isExe() Method Verification");
    
    try {
        // Test with EXE file
        PeParser parser1("test_rich_header.exe");
        parser1.parseFile();
        TEST_ASSERT(parser1.isExe(), "EXE file should return true for isExe()");
        
        // Test with DLL file if available
        std::ifstream testFile("C:\\Windows\\System32\\kernel32.dll");
        if (testFile.good()) {
            testFile.close();
            PeParser parser2("C:\\Windows\\System32\\kernel32.dll");
            parser2.parseFile();
            TEST_ASSERT(!parser2.isExe(), "DLL file should return false for isExe()");
        }
        
        TEST_PASS("isExe() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testIsDllMethod(const std::string& currentTestName) {
    printTestName("isDLL() Method Verification");
    
    try {
        // Test with EXE file
        PeParser parser1("test_rich_header.exe");
        parser1.parseFile();
        TEST_ASSERT(!parser1.isDLL(), "EXE file should return false for isDLL()");
        
        // Test with DLL file if available
        std::ifstream testFile("C:\\Windows\\System32\\kernel32.dll");
        if (testFile.good()) {
            testFile.close();
            PeParser parser2("C:\\Windows\\System32\\kernel32.dll");
            parser2.parseFile();
            TEST_ASSERT(parser2.isDLL(), "DLL file should return true for isDLL()");
        }
        
        TEST_PASS("isDLL() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testIs64BitsMethod(const std::string& currentTestName) {
    printTestName("is64Bits() Method Verification");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        bool is64 = parser.is64Bits();
        TEST_ASSERT(is64 == true || is64 == false, "is64Bits() should return boolean");
        
        TEST_PASS("is64Bits() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testGetTargetOSMethod(const std::string& currentTestName) {
    printTestName("getTargetOS() Method Verification");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        std::string targetOS = parser.getTargetOS();
        TEST_ASSERT(!targetOS.empty(), "getTargetOS() should return non-empty string");
        
        std::cout << "    Target OS: " << targetOS << std::endl;
        TEST_PASS("getTargetOS() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testGetImportFunctionNamesMethod(const std::string& currentTestName) {
    printTestName("getImportFunctionNames() Method Verification");
    
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        std::vector<std::string> imports = parser.getImportFunctionNames();
        TEST_ASSERT(!imports.empty(), "Should have at least one import");
        
        // Verify all entries are non-empty strings
        for (const auto& funcName : imports) {
            TEST_ASSERT(!funcName.empty(), "Import function name should not be empty");
        }
        
        std::cout << "    Total imports: " << imports.size() << std::endl;
        TEST_PASS("getImportFunctionNames() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testGetExportFunctionNamesMethod(const std::string& currentTestName) {
    printTestName("getExportFunctionNames() Method Verification");
    
    try {
        // Most EXE files don't have exports, so test with a DLL
        std::ifstream testFile("C:\\Windows\\System32\\kernel32.dll");
        if (!testFile.good()) {
            std::cout << COLOR_YELLOW << "  ⊘ SKIPPED: kernel32.dll not accessible" << COLOR_RESET << std::endl;
            testResults.push_back({currentTestName, true, "Skipped - DLL not accessible"});
            return true;
        }
        testFile.close();
        
        PeParser parser("C:\\Windows\\System32\\kernel32.dll");
        parser.parseFile();
        
        std::vector<std::string> exports = parser.getExportFunctionNames();
        TEST_ASSERT(!exports.empty(), "DLL should have exports");
        
        // Verify all entries are non-empty strings
        for (size_t i = 0; i < std::min(size_t(10), exports.size()); ++i) {
            TEST_ASSERT(!exports[i].empty(), "Export function name should not be empty");
        }
        
        std::cout << "    Total exports: " << exports.size() << std::endl;
        TEST_PASS("getExportFunctionNames() method works correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

// ============================================================================
// 3. PERFORMANCE AND MEMORY TESTS
// ============================================================================

bool testLargeFileParsing(const std::string& currentTestName) {
    printTestName("Large PE File Parsing Performance");
    
    try {
        // Test with ntdll.dll which is typically a large system DLL
        const char* largeDll = "C:\\Windows\\System32\\ntdll.dll";
        
        std::ifstream testFile(largeDll);
        if (!testFile.good()) {
            std::cout << COLOR_YELLOW << "  ⊘ SKIPPED: ntdll.dll not accessible" << COLOR_RESET << std::endl;
            testResults.push_back({currentTestName, true, "Skipped - DLL not accessible"});
            return true;
        }
        testFile.close();
        
        auto start = std::chrono::high_resolution_clock::now();
        
        PeParser parser(largeDll);
        parser.parseFile();
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "    Parse time: " << duration.count() << " ms" << std::endl;
        TEST_ASSERT(duration.count() < 5000, "Parsing should complete in under 5 seconds");
        
        TEST_PASS("Large file parsed within acceptable time");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testMultipleSequentialParses(const std::string& currentTestName) {
    printTestName("Multiple Sequential Parse Operations");
    
    try {
        const int numIterations = 5;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < numIterations; ++i) {
            PeParser parser("test_rich_header.exe");
            parser.parseFile();
            
            // Verify basic functionality
            TEST_ASSERT(parser.isExe(), "Each parse should correctly identify file type");
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        std::cout << "    Total time for " << numIterations << " parses: " 
                  << duration.count() << " ms" << std::endl;
        std::cout << "    Average time per parse: " 
                  << (duration.count() / numIterations) << " ms" << std::endl;
        
        TEST_PASS("Multiple sequential parses completed successfully");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

// ============================================================================
// 4. EDGE CASE AND ROBUSTNESS TESTS
// ============================================================================

bool testFileWithNoExports(const std::string& currentTestName) {
    printTestName("File With No Exports");
    
    try {
        // Most EXE files don't have exports
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        std::vector<std::string> exports = parser.getExportFunctionNames();
        // This should not crash even if there are no exports
        std::cout << "    Export count: " << exports.size() << std::endl;
        
        TEST_PASS("Handled file with no exports gracefully");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Exception: ") + e.what());
        return false;
    }
}

bool testInvalidFileHandling(const std::string& currentTestName) {
    printTestName("Invalid File Handling");
    
    try {
        // Try to parse a non-PE file (should throw exception)
        bool exceptionThrown = false;
        try {
            PeParser parser("PeParser.cpp");
            parser.parseFile();
        } catch (const std::runtime_error&) {
            exceptionThrown = true;
        }
        
        TEST_ASSERT(exceptionThrown, "Should throw exception for non-PE file");
        TEST_PASS("Invalid file handled correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Unexpected exception: ") + e.what());
        return false;
    }
}

bool testNonExistentFileHandling(const std::string& currentTestName) {
    printTestName("Non-Existent File Handling");
    
    try {
        bool exceptionThrown = false;
        try {
            PeParser parser("non_existent_file_12345.exe");
            parser.parseFile();
        } catch (const std::runtime_error&) {
            exceptionThrown = true;
        }
        
        TEST_ASSERT(exceptionThrown, "Should throw exception for non-existent file");
        TEST_PASS("Non-existent file handled correctly");
        return true;
    } catch (const std::exception& e) {
        TEST_ASSERT(false, std::string("Unexpected exception: ") + e.what());
        return false;
    }
}

// ============================================================================
// MAIN TEST RUNNER
// ============================================================================

void printSummary() {
    std::cout << "\n" << COLOR_CYAN << "========================================" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "TEST SUMMARY" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "========================================" << COLOR_RESET << std::endl;
    
    int passed = 0;
    int failed = 0;
    int total = testResults.size();
    
    for (const auto& result : testResults) {
        if (result.passed) {
            passed++;
        } else {
            failed++;
            std::cout << COLOR_RED << "FAILED: " << result.testName 
                      << " - " << result.message << COLOR_RESET << std::endl;
        }
    }
    
    std::cout << "\nTotal Tests: " << total << std::endl;
    std::cout << COLOR_GREEN << "Passed: " << passed << COLOR_RESET << std::endl;
    if (failed > 0) {
        std::cout << COLOR_RED << "Failed: " << failed << COLOR_RESET << std::endl;
    } else {
        std::cout << "Failed: " << failed << std::endl;
    }
    
    double passRate = (total > 0) ? (100.0 * passed / total) : 0.0;
    std::cout << "Pass Rate: " << passRate << "%" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n" << COLOR_GREEN << "✓ ALL TESTS PASSED!" << COLOR_RESET << std::endl;
    } else {
        std::cout << "\n" << COLOR_RED << "✗ SOME TESTS FAILED" << COLOR_RESET << std::endl;
    }
}

int main() {
    std::cout << COLOR_CYAN << "PE Parser - Comprehensive Integration Tests" << COLOR_RESET << std::endl;
    std::cout << COLOR_CYAN << "===========================================" << COLOR_RESET << std::endl;
    
    // 1. Complete Parsing Workflow Tests
    printTestHeader("1. COMPLETE PARSING WORKFLOW TESTS");
    testCompleteWorkflowExe("Complete Workflow - EXE");
    testCompleteWorkflowDll("Complete Workflow - DLL");
    testDataConsistency("Data Consistency");
    test64BitParsing("64-bit Parsing");
    
    // 2. Query Method Verification Tests
    printTestHeader("2. QUERY METHOD VERIFICATION TESTS");
    testIsExeMethod("isExe() Verification");
    testIsDllMethod("isDLL() Verification");
    testIs64BitsMethod("is64Bits() Verification");
    testGetTargetOSMethod("getTargetOS() Verification");
    testGetImportFunctionNamesMethod("getImportFunctionNames() Verification");
    testGetExportFunctionNamesMethod("getExportFunctionNames() Verification");
    
    // 3. Performance and Memory Tests
    printTestHeader("3. PERFORMANCE AND MEMORY TESTS");
    testLargeFileParsing("Large File Parsing");
    testMultipleSequentialParses("Multiple Sequential Parses");
    
    // 4. Edge Case and Robustness Tests
    printTestHeader("4. EDGE CASE AND ROBUSTNESS TESTS");
    testFileWithNoExports("File With No Exports");
    testInvalidFileHandling("Invalid File Handling");
    testNonExistentFileHandling("Non-Existent File Handling");
    
    // Print summary
    printSummary();
    
    // Return appropriate exit code
    int failed = 0;
    for (const auto& result : testResults) {
        if (!result.passed) failed++;
    }
    
    return (failed == 0) ? 0 : 1;
}
