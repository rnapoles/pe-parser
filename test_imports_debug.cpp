#include "PeParser.h"
#include <iostream>
#include <iomanip>

int main(int argc, char* argv[]) {
    const char* filename = (argc > 1) ? argv[1] : "test_nt_headers.exe";
    
    try {
        PeParser parser(filename);
        
        std::cout << "Testing Import Table Parsing on: " << filename << std::endl;
        
        // Parse headers
        parser.parseDOSHeader();
        parser.parseNTHeaders();
        parser.parseSectionHeaders();
        
        // Parse imports
        parser.parseImports();
        
        // Display results
        parser.printImportTableInfo();
        parser.printImportFunctions();
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
