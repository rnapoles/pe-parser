#include "PeParser.h"
#include <iostream>

int main() {
    try {
        // Test with the existing test executable
        PeParser parser("test_nt_headers.exe");
        
        std::cout << "Testing Section Headers Parsing..." << std::endl;
        
        // Parse DOS header first (required)
        parser.parseDOSHeader();
        std::cout << "✓ DOS header parsed" << std::endl;
        
        // Parse NT headers (required before sections)
        parser.parseNTHeaders();
        std::cout << "✓ NT headers parsed" << std::endl;
        
        // Parse section headers
        parser.parseSectionHeaders();
        std::cout << "✓ Section headers parsed" << std::endl;
        
        // Display section headers information
        parser.printSectionHeadersInfo();
        
        std::cout << "\n✓ All tests passed!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
