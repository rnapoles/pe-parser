#include "PeParser.h"
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pe_file>" << std::endl;
        return 1;
    }

    std::string filepath = argv[1];
    
    try {
        std::cout << "Testing printFileInfo() with " << filepath << "..." << std::endl;
        
        PeParser parser(filepath);
        parser.parseFile();
        parser.printFileInfo();
        
        std::cout << "\nTest completed successfully." << std::endl;
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
