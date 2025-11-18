#include "PeParser.h"
#include <iostream>

int main() {
    std::cout << "=== Comprehensive Rich Header Test ===" << std::endl;
    std::cout << "\nTest 1: PE file without Rich header" << std::endl;
    
    try {
        PeParser parser1("test_exports.exe");
        parser1.parseDOSHeader();
        parser1.parseRichHeader();
        parser1.printRichHeaderInfo();
    } catch (const std::exception& e) {
        std::cerr << "Test 1 Error: " << e.what() << std::endl;
    }
    
    std::cout << "\n\nTest 2: PE file with Rich header (Windows system binary)" << std::endl;
    
    try {
        PeParser parser2("C:\\Windows\\System32\\notepad.exe");
        parser2.parseDOSHeader();
        parser2.parseRichHeader();
        parser2.printRichHeaderInfo();
    } catch (const std::exception& e) {
        std::cerr << "Test 2 Error: " << e.what() << std::endl;
    }
    
    std::cout << "\n\nTest 3: Another Windows system binary" << std::endl;
    
    try {
        PeParser parser3("C:\\Windows\\System32\\cmd.exe");
        parser3.parseDOSHeader();
        parser3.parseRichHeader();
        parser3.printRichHeaderInfo();
    } catch (const std::exception& e) {
        std::cerr << "Test 3 Error: " << e.what() << std::endl;
    }
    
    std::cout << "\n\n=== All Rich Header Tests Completed ===" << std::endl;
    
    return 0;
}
