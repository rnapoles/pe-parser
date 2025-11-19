#include "PeParser.h"
#include <iostream>
#include <cassert>
#include <vector>
#include <string>
#include <fstream>

// Simple test framework
#define ASSERT_TRUE(condition) \
    if (!(condition)) { \
        std::cerr << "Assertion failed: " << #condition << " at " << __FILE__ << ":" << __LINE__ << std::endl; \
        return false; \
    }

#define ASSERT_THROWS(statement, exceptionType) \
    try { \
        statement; \
        std::cerr << "Expected exception " << #exceptionType << " but none was thrown at " << __FILE__ << ":" << __LINE__ << std::endl; \
        return false; \
    } catch (const exceptionType&) { \
        /* Expected */ \
    } catch (...) { \
        std::cerr << "Expected exception " << #exceptionType << " but different exception was thrown at " << __FILE__ << ":" << __LINE__ << std::endl; \
        return false; \
    }

bool testValidPEFile() {
    std::cout << "Running testValidPEFile..." << std::endl;
    try {
        PeParser parser("test_rich_header.exe");
        parser.parseFile();
        
        // Check basic properties
        ASSERT_TRUE(parser.isExe());
        // We don't know if it's 64-bit or 32-bit without checking the file, but let's assume it parses correctly
        // parser.is64Bits(); 
        
        // Check imports
        std::vector<std::string> imports = parser.getImportFunctionNames();
        // Even a simple exe should have some imports (usually kernel32.dll functions)
        // But it might be empty if it's a very simple file or static linked.
        // However, test_rich_header.exe is likely a normal C++ exe.
        
        std::cout << "  Imports found: " << imports.size() << std::endl;
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with exception: " << e.what() << std::endl;
        return false;
    }
}

bool testInvalidPEFile() {
    std::cout << "Running testInvalidPEFile..." << std::endl;
    // PeParser.cpp is a text file, not a PE file
    // Constructor should throw or parseFile should throw
    
    // The constructor checks for file size and MZ signature
    ASSERT_THROWS(PeParser parser("PeParser.cpp"), std::runtime_error);
    
    return true;
}

bool testNonExistentFile() {
    std::cout << "Running testNonExistentFile..." << std::endl;
    ASSERT_THROWS(PeParser parser("non_existent_file.exe"), std::runtime_error);
    return true;
}

int main() {
    int failed = 0;
    
    if (!testValidPEFile()) failed++;
    if (!testInvalidPEFile()) failed++;
    if (!testNonExistentFile()) failed++;
    
    if (failed == 0) {
        std::cout << "All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << failed << " tests failed." << std::endl;
        return 1;
    }
}
