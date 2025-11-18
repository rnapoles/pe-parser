#include "PeParser.h"
#include <iostream>

int main() {
    try {
        // Test with Windows system binary that should have Rich header
        std::cout << "Testing Rich Header Parsing with Windows system binary\n" << std::endl;
        
        // Try notepad.exe which typically has a Rich header
        PeParser parser("C:\\Windows\\System32\\notepad.exe");
        
        // Parse DOS header first (required before Rich header)
        parser.parseDOSHeader();
        
        // Parse Rich header
        parser.parseRichHeader();
        
        // Display Rich header information
        parser.printRichHeaderInfo();
        
        std::cout << "\nRich header parsing test completed!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        std::cerr << "\nNote: This test requires access to Windows system files." << std::endl;
        return 1;
    }
    
    return 0;
}
