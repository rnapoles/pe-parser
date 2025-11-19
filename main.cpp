#include "PeParser.h"
#include <iostream>
#include <string>
#include <vector>

void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " <pe_file_path> [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --all           Show all information (default)" << std::endl;
    std::cout << "  --headers       Show DOS, NT, and Section headers" << std::endl;
    std::cout << "  --imports       Show Import table information" << std::endl;
    std::cout << "  --exports       Show Export table information" << std::endl;
    std::cout << "  --rich          Show Rich header information" << std::endl;
    std::cout << "  --reloc         Show Base Relocations" << std::endl;
    std::cout << "  --help          Show this help message" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string filepath = argv[1];
    if (filepath == "--help" || filepath == "-h") {
        printUsage(argv[0]);
        return 0;
    }

    bool showAll = false;
    bool showHeaders = false;
    bool showImports = false;
    bool showExports = false;
    bool showRich = false;
    bool showReloc = false;

    // Parse arguments
    if (argc == 2) {
        showAll = true;
    } else {
        for (int i = 2; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--all") showAll = true;
            else if (arg == "--headers") showHeaders = true;
            else if (arg == "--imports") showImports = true;
            else if (arg == "--exports") showExports = true;
            else if (arg == "--rich") showRich = true;
            else if (arg == "--reloc") showReloc = true;
            else {
                std::cerr << "Unknown option: " << arg << std::endl;
                printUsage(argv[0]);
                return 1;
            }
        }
    }

    if (showAll) {
        showHeaders = true;
        showImports = true;
        showExports = true;
        showRich = true;
        showReloc = true;
    }

    try {
        PeParser parser(filepath);
        
        std::cout << "Parsing file: " << filepath << std::endl;
        parser.parseFile();
        
        std::cout << "\n=== File Summary ===" << std::endl;
        parser.printFileInfo();
        
        if (showHeaders) {
            std::cout << "\n=== DOS Header ===" << std::endl;
            parser.printDOSHeaderInfo();
            
            std::cout << "\n=== NT Headers ===" << std::endl;
            parser.printNTHeadersInfo();
            
            std::cout << "\n=== Section Headers ===" << std::endl;
            parser.printSectionHeadersInfo();
        }
        
        if (showRich) {
            std::cout << "\n=== Rich Header ===" << std::endl;
            parser.printRichHeaderInfo();
        }
        
        if (showImports) {
            std::cout << "\n=== Import Table ===" << std::endl;
            parser.printImportTableInfo();
            std::cout << "\n--- Imported Functions ---" << std::endl;
            parser.printImportFunctions();
        }
        
        if (showExports) {
            std::cout << "\n=== Export Table ===" << std::endl;
            parser.printExportFunctions();
        }
        
        if (showReloc) {
            std::cout << "\n=== Base Relocations ===" << std::endl;
            parser.printBaseRelocationsInfo();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
