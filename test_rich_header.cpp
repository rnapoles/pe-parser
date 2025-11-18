#include "PeParser.h"
#include <iostream>

int main() {
    try {
        // Test with test_exports.exe which should have a Rich header
        std::cout << "Testing Rich Header Parsing with test_exports.exe\n" << std::endl;
        
        PeParser parser("test_exports.exe");
        
        // Parse DOS header first (required before Rich header)
        parser.parseDOSHeader();
        
        // Parse Rich header
        parser.parseRichHeader();
        
        // Display Rich header information
        parser.printRichHeaderInfo();
        
        std::cout << "\n\nTesting with another PE file (test_imports.cpp compiled)\n" << std::endl;
        
        // Try with another file if available
        try {
            PeParser parser2("test_imports_debug.cpp");
            parser2.parseDOSHeader();
            parser2.parseRichHeader();
            parser2.printRichHeaderInfo();
        } catch (const std::exception& e) {
            std::cout << "Could not test second file: " << e.what() << std::endl;
        }
        
        std::cout << "\nRich header parsing test completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
