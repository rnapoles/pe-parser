#include "PeParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <PE file path>" << std::endl;
        return 1;
    }
    
    try {
        // Create parser instance
        PeParser parser(argv[1]);
        
        // Parse DOS header first (required for NT headers)
        parser.parseDOSHeader();
        std::cout << "DOS header parsed successfully." << std::endl;
        
        // Parse NT headers
        parser.parseNTHeaders();
        std::cout << "NT headers parsed successfully." << std::endl;
        
        // Display DOS header info
        parser.printDOSHeaderInfo();
        
        // Display NT headers info
        parser.printNTHeadersInfo();
        
        // Test query methods
        std::cout << "\n=== Query Methods Test ===" << std::endl;
        std::cout << "Is 64-bit: " << (parser.is64Bits() ? "Yes" : "No") << std::endl;
        std::cout << "Is EXE: " << (parser.isExe() ? "Yes" : "No") << std::endl;
        std::cout << "Is DLL: " << (parser.isDLL() ? "Yes" : "No") << std::endl;
        std::cout << "Target OS: " << parser.getTargetOS() << std::endl;
        std::cout << "================================" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
