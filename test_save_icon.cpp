#include "PeParser.h"
#include <iostream>
#include <filesystem>
#include <vector>

namespace fs = std::filesystem;

// Test result structure
struct TestResult {
    std::string testName;
    bool passed;
    std::string message;
};

// Helper function to print test results
void printTestResult(const TestResult& result) {
    std::cout << "[" << (result.passed ? "PASS" : "FAIL") << "] " 
              << result.testName << std::endl;
    if (!result.message.empty()) {
        std::cout << "    " << result.message << std::endl;
    }
}

// Test 1: Extract icon from a valid PE file with icon
TestResult testValidPEWithIcon(const std::string& peFile) {
    TestResult result;
    result.testName = "Extract icon from valid PE file";
    
    try {
        PeParser parser(peFile);
        parser.parseFile();
        
        std::string outputFile = "test_output_icon.ico";
        
        // Remove output file if it exists
        if (fs::exists(outputFile)) {
            fs::remove(outputFile);
        }
        
        bool success = parser.saveIcon(outputFile);
        
        if (success && fs::exists(outputFile)) {
            // Check if file has content
            auto fileSize = fs::file_size(outputFile);
            if (fileSize > 0) {
                result.passed = true;
                result.message = "Icon extracted successfully (" + std::to_string(fileSize) + " bytes)";
                
                // Clean up
                fs::remove(outputFile);
            } else {
                result.passed = false;
                result.message = "Output file is empty";
            }
        } else {
            result.passed = false;
            result.message = "Failed to extract icon or create output file";
        }
        
    } catch (const std::exception& e) {
        result.passed = false;
        result.message = std::string("Exception: ") + e.what();
    }
    
    return result;
}

// Test 2: Try to extract icon from PE file without icon resources
TestResult testPEWithoutIcon(const std::string& peFile) {
    TestResult result;
    result.testName = "Handle PE file without icon resources";
    
    try {
        PeParser parser(peFile);
        parser.parseFile();
        
        std::string outputFile = "test_no_icon.ico";
        
        // This should fail gracefully
        bool success = parser.saveIcon(outputFile);
        
        if (!success) {
            result.passed = true;
            result.message = "Correctly handled PE file without icons";
        } else {
            result.passed = false;
            result.message = "Should have failed for PE without icons";
        }
        
        // Clean up if file was created
        if (fs::exists(outputFile)) {
            fs::remove(outputFile);
        }
        
    } catch (const std::exception& e) {
        result.passed = false;
        result.message = std::string("Exception: ") + e.what();
    }
    
    return result;
}

// Test 3: Try to extract icon from invalid file
TestResult testInvalidFile() {
    TestResult result;
    result.testName = "Handle invalid/non-PE file";
    
    try {
        // Try to parse a text file (this .cpp file)
        PeParser parser("test_save_icon.cpp");
        parser.parseFile();
        
        std::string outputFile = "test_invalid.ico";
        bool success = parser.saveIcon(outputFile);
        
        if (!success) {
            result.passed = true;
            result.message = "Correctly rejected invalid PE file";
        } else {
            result.passed = false;
            result.message = "Should have failed for non-PE file";
        }
        
        // Clean up if file was created
        if (fs::exists(outputFile)) {
            fs::remove(outputFile);
        }
        
    } catch (const std::exception& e) {
        // Exception is also acceptable for invalid files
        result.passed = true;
        result.message = "Correctly threw exception for invalid file";
    }
    
    return result;
}

// Test 4: Test output path validation
TestResult testInvalidOutputPath() {
    TestResult result;
    result.testName = "Handle invalid output path";
    
    try {
        // Use a valid PE file
        std::string peFile = "C:\\Windows\\System32\\notepad.exe";
        
        if (!fs::exists(peFile)) {
            result.passed = false;
            result.message = "Test PE file not found: " + peFile;
            return result;
        }
        
        PeParser parser(peFile);
        parser.parseFile();
        
        // Try to write to an invalid path
        std::string invalidPath = "Z:\\nonexistent\\path\\icon.ico";
        bool success = parser.saveIcon(invalidPath);
        
        if (!success) {
            result.passed = true;
            result.message = "Correctly handled invalid output path";
        } else {
            result.passed = false;
            result.message = "Should have failed for invalid output path";
        }
        
    } catch (const std::exception& e) {
        result.passed = false;
        result.message = std::string("Exception: ") + e.what();
    }
    
    return result;
}

// Test 5: Extract icon from multiple common Windows executables
TestResult testMultipleExecutables() {
    TestResult result;
    result.testName = "Extract icons from multiple Windows executables";
    
    std::vector<std::string> testFiles = {
        "C:\\Windows\\System32\\notepad.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\mspaint.exe",
        "C:\\Windows\\explorer.exe"
    };
    
    int successCount = 0;
    int totalTests = 0;
    std::string details;
    
    for (const auto& peFile : testFiles) {
        if (!fs::exists(peFile)) {
            continue;
        }
        
        totalTests++;
        
        try {
            PeParser parser(peFile);
            parser.parseFile();
            
            std::string filename = fs::path(peFile).filename().string();
            std::string outputFile = "test_" + filename + ".ico";
            
            if (parser.saveIcon(outputFile)) {
                if (fs::exists(outputFile) && fs::file_size(outputFile) > 0) {
                    successCount++;
                    details += "\n    ✓ " + filename;
                    fs::remove(outputFile);
                } else {
                    details += "\n    ✗ " + filename + " (empty file)";
                }
            } else {
                details += "\n    ✗ " + filename + " (extraction failed)";
            }
            
        } catch (const std::exception& e) {
            details += "\n    ✗ " + fs::path(peFile).filename().string() + " (exception)";
        }
    }
    
    if (totalTests == 0) {
        result.passed = false;
        result.message = "No test files found";
    } else {
        result.passed = (successCount == totalTests);
        result.message = std::to_string(successCount) + "/" + std::to_string(totalTests) + " succeeded" + details;
    }
    
    return result;
}

// Test 6: Verify ICO file format
TestResult testICOFileFormat(const std::string& peFile) {
    TestResult result;
    result.testName = "Verify ICO file format is valid";
    
    try {
        PeParser parser(peFile);
        parser.parseFile();
        
        std::string outputFile = "test_format_check.ico";
        
        if (fs::exists(outputFile)) {
            fs::remove(outputFile);
        }
        
        if (!parser.saveIcon(outputFile)) {
            result.passed = false;
            result.message = "Failed to extract icon";
            return result;
        }
        
        // Read and verify ICO file header
        std::ifstream icoFile(outputFile, std::ios::binary);
        if (!icoFile.is_open()) {
            result.passed = false;
            result.message = "Failed to open output file";
            return result;
        }
        
        // Read ICO header (6 bytes)
        uint16_t reserved, type, count;
        icoFile.read(reinterpret_cast<char*>(&reserved), 2);
        icoFile.read(reinterpret_cast<char*>(&type), 2);
        icoFile.read(reinterpret_cast<char*>(&count), 2);
        
        icoFile.close();
        
        // Verify ICO format
        bool validFormat = (reserved == 0 && type == 1 && count > 0);
        
        if (validFormat) {
            result.passed = true;
            result.message = "Valid ICO format (type=" + std::to_string(type) + 
                           ", count=" + std::to_string(count) + ")";
        } else {
            result.passed = false;
            result.message = "Invalid ICO format (reserved=" + std::to_string(reserved) + 
                           ", type=" + std::to_string(type) + 
                           ", count=" + std::to_string(count) + ")";
        }
        
        // Clean up
        fs::remove(outputFile);
        
    } catch (const std::exception& e) {
        result.passed = false;
        result.message = std::string("Exception: ") + e.what();
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  PeParser::saveIcon() Test Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    std::vector<TestResult> results;
    
    // Determine test PE file
    std::string testPEFile = "C:\\Windows\\System32\\notepad.exe";
    
    if (argc > 1) {
        testPEFile = argv[1];
    }
    
    // Check if test file exists
    if (!fs::exists(testPEFile)) {
        std::cerr << "Error: Test PE file not found: " << testPEFile << std::endl;
        std::cerr << "Usage: " << argv[0] << " [path_to_pe_file]" << std::endl;
        std::cerr << "Default: C:\\Windows\\System32\\notepad.exe" << std::endl;
        return 1;
    }
    
    std::cout << "Using test file: " << testPEFile << std::endl;
    std::cout << std::endl;
    
    // Run tests
    std::cout << "Running tests..." << std::endl;
    std::cout << "----------------------------------------" << std::endl;
    
    results.push_back(testValidPEWithIcon(testPEFile));
    results.push_back(testICOFileFormat(testPEFile));
    results.push_back(testInvalidFile());
    results.push_back(testInvalidOutputPath());
    results.push_back(testMultipleExecutables());
    
    // Print results
    std::cout << std::endl;
    for (const auto& result : results) {
        printTestResult(result);
    }
    
    // Summary
    int passed = 0;
    for (const auto& result : results) {
        if (result.passed) passed++;
    }
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Summary: " << passed << "/" << results.size() << " tests passed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    return (passed == results.size()) ? 0 : 1;
}
