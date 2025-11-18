#include "PeParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        // Test with the specified file or default to test_nt_headers.exe
        const char* filename = (argc > 1) ? argv[1] : "test_nt_headers.exe";
        PeParser parser(filename);
        
        std::cout << "Testing Import Table Parsing..." << std::endl;
        
        // Parse DOS header first (required)
        parser.parseDOSHeader();
        std::cout << "✓ DOS header parsed" << std::endl;
        
        // Parse NT headers (required before imports)
        parser.parseNTHeaders();
        std::cout << "✓ NT headers parsed" << std::endl;
        
        // Parse section headers (required for RVA to file offset conversion)
        parser.parseSectionHeaders();
        std::cout << "✓ Section headers parsed" << std::endl;
        
        // Don't display NT headers for now
        
        // Parse imports
        parser.parseImports();
        std::cout << "✓ Import table parsed" << std::endl;
        
        // Display import table information
        parser.printImportTableInfo();
        
        // Display all imported functions
        parser.printImportFunctions();
        
        // Test getImportFunctionNames method
        std::cout << "\n=== Testing getImportFunctionNames() ===" << std::endl;
        std::vector<std::string> functionNames = parser.getImportFunctionNames();
        std::cout << "Total functions retrieved: " << functionNames.size() << std::endl;
        
        if (!functionNames.empty()) {
            std::cout << "First few functions:" << std::endl;
            for (size_t i = 0; i < std::min(size_t(5), functionNames.size()); ++i) {
                std::cout << "  - " << functionNames[i] << std::endl;
            }
        }
        std::cout << "========================================" << std::endl;
        
        std::cout << "\n✓ All tests passed!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
