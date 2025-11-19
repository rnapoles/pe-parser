#include "PeParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    // Check command line arguments
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <PE file> [output.ico]" << std::endl;
        std::cout << "Example: " << argv[0] << " notepad.exe notepad.ico" << std::endl;
        return 1;
    }
    
    std::string inputFile = argv[1];
    std::string outputFile = (argc >= 3) ? argv[2] : "extracted_icon.ico";
    
    try {
        // Create PE parser instance
        std::cout << "Opening PE file: " << inputFile << std::endl;
        PeParser parser(inputFile);
        
        // Parse the file
        std::cout << "Parsing PE file..." << std::endl;
        parser.parseFile();
        
        // Extract the icon
        std::cout << "\nExtracting icon..." << std::endl;
        if (parser.saveIcon(outputFile)) {
            std::cout << "\nSuccess! Icon extracted successfully." << std::endl;
        } else {
            std::cout << "\nFailed to extract icon." << std::endl;
            return 1;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
