#include "PeParser.h"
#include <iostream>
#include <cstring>

// Constructor - opens file and performs basic validation
PeParser::PeParser(const std::string& filepath) 
    : filename(filepath), isValidPE(false) {
    
    // Open file in binary mode
    file.open(filepath, std::ios::binary | std::ios::in);
    
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filepath);
    }
    
    // Check file size
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();
    file.seekg(0, std::ios::beg);
    
    if (fileSize < 64) {
        throw std::runtime_error("File too small to be a valid PE file");
    }
    
    // Validate PE signature
    if (!validatePESignature()) {
        throw std::runtime_error("Invalid PE signature");
    }
    
    isValidPE = true;
}

// Destructor - closes file handle
PeParser::~PeParser() {
    if (file.is_open()) {
        file.close();
    }
}

// Validate PE signature (MZ header and PE signature)
bool PeParser::validatePESignature() {
    // Read DOS signature (first 2 bytes)
    file.seekg(0, std::ios::beg);
    uint16_t dosSignature;
    file.read(reinterpret_cast<char*>(&dosSignature), sizeof(dosSignature));
    
    if (dosSignature != 0x5A4D) { // "MZ" in little-endian
        return false;
    }
    
    // Read e_lfanew offset (at offset 0x3C)
    file.seekg(0x3C, std::ios::beg);
    uint32_t e_lfanew;
    file.read(reinterpret_cast<char*>(&e_lfanew), sizeof(e_lfanew));
    
    // Read PE signature at e_lfanew offset
    file.seekg(e_lfanew, std::ios::beg);
    uint32_t peSignature;
    file.read(reinterpret_cast<char*>(&peSignature), sizeof(peSignature));
    
    if (peSignature != 0x00004550) { // "PE\0\0" in little-endian
        return false;
    }
    
    return true;
}

// Template method to read typed data from file at specified offset
template<typename T>
T PeParser::readData(size_t offset) {
    T data;
    file.seekg(offset, std::ios::beg);
    file.read(reinterpret_cast<char*>(&data), sizeof(T));
    return data;
}

// Read null-terminated string from file at specified offset
std::string PeParser::readString(size_t offset, size_t maxLength) {
    file.seekg(offset, std::ios::beg);
    std::string result;
    result.reserve(maxLength);
    
    char ch;
    for (size_t i = 0; i < maxLength; ++i) {
        file.read(&ch, 1);
        if (ch == '\0' || file.eof()) {
            break;
        }
        result += ch;
    }
    
    return result;
}

// Placeholder implementations for parsing methods
void PeParser::parseFile() {
    // To be implemented in later tasks
}

void PeParser::parseDOSHeader() {
    // To be implemented in task 2
}

void PeParser::parseRichHeader() {
    // To be implemented in task 7
}

void PeParser::parseNTHeaders() {
    // To be implemented in task 3
}

void PeParser::parseSectionHeaders() {
    // To be implemented in task 4
}

void PeParser::parseImports() {
    // To be implemented in task 5
}

void PeParser::parseExports() {
    // To be implemented in task 6
}

// Placeholder implementations for information methods
void PeParser::printFileInfo() {
    // To be implemented in task 8
}

void PeParser::printDOSHeaderInfo() {
    // To be implemented in task 2
}

void PeParser::printRichHeaderInfo() {
    // To be implemented in task 7
}

void PeParser::printNTHeadersInfo() {
    // To be implemented in task 3
}

void PeParser::printSectionHeadersInfo() {
    // To be implemented in task 4
}

void PeParser::printImportTableInfo() {
    // To be implemented in task 5
}

void PeParser::printBaseRelocationsInfo() {
    // To be implemented in task 9
}

void PeParser::printImportFunctions() {
    // To be implemented in task 5
}

void PeParser::printExportFunctions() {
    // To be implemented in task 6
}

// Placeholder implementations for query methods
std::string PeParser::getTargetOS() {
    // To be implemented in task 3
    return "";
}

std::vector<std::string> PeParser::getExportFunctionNames() {
    // To be implemented in task 6
    return std::vector<std::string>();
}

std::vector<std::string> PeParser::getImportFunctionNames() {
    // To be implemented in task 5
    return std::vector<std::string>();
}

bool PeParser::isExe() {
    // To be implemented in task 3
    return false;
}

bool PeParser::isDLL() {
    // To be implemented in task 3
    return false;
}

bool PeParser::is64Bits() {
    // To be implemented in task 3
    return false;
}
