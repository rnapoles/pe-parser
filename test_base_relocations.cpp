#include "PeParser.h"
#include <iostream>
#include <exception>

int main() {
    try {
        // Test with test_rich_comprehensive.exe which should have base relocations
        std::cout << "Testing Base Relocations Parsing with test_rich_comprehensive.exe" << std::endl;
        std::cout << "=================================================================" << std::endl;
        
        PeParser parser("test_rich_comprehensive.exe");
        
        // Parse the necessary structures
        parser.parseDOSHeader();
        parser.parseNTHeaders();
        parser.parseSectionHeaders();
        
        // Parse base relocations
        parser.parseBaseRelocations();
        
        // Display base relocations information
        parser.printBaseRelocationsInfo();
        
        std::cout << "\n\nTest completed successfully!" << std::endl;
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
