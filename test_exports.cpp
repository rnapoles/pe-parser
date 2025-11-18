#include "PeParser.h"
#include <iostream>

int main(int argc, char* argv[]) {

    try {
        // Test with a Windows system DLL that has exports
        //PeParser parser("C:\\Windows\\System32\\kernel32.dll");
        
        const char* filename = (argc > 1) ? argv[1] : "C:\\Windows\\System32\\kernel32.dll";
        PeParser parser(filename);
        
        std::cout << "Testing export parsing functionality..." << std::endl;
        
        // Parse the PE file structures
        parser.parseDOSHeader();
        parser.parseNTHeaders();
        parser.parseSectionHeaders();
        parser.parseExports();
        
        // Test getExportFunctionNames() method
        std::vector<std::string> exportNames = parser.getExportFunctionNames();
        std::cout << "\ngetExportFunctionNames() returned " << exportNames.size() << " functions" << std::endl;
        
        if (!exportNames.empty()) {
            std::cout << "First 5 exported functions:" << std::endl;
            for (size_t i = 0; i < std::min(size_t(5), exportNames.size()); ++i) {
                std::cout << "  " << (i+1) << ". " << exportNames[i] << std::endl;
            }
        }
        
        // Test printExportFunctions() method
        parser.printExportFunctions();
        
        std::cout << "\nExport parsing test completed successfully!" << std::endl;
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
