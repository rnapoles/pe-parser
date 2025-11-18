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
    // Seek to beginning of file
    file.seekg(0, std::ios::beg);
    
    // Read the entire DOS header structure (64 bytes)
    file.read(reinterpret_cast<char*>(&dosHeader), sizeof(DOSHeader));
    
    // Validate DOS signature (MZ magic number = 0x5A4D)
    if (dosHeader.e_magic != 0x5A4D) {
        throw std::runtime_error("Invalid DOS signature: Expected MZ (0x5A4D)");
    }
    
    // Additional validation: check if e_lfanew is reasonable
    if (dosHeader.e_lfanew < 64 || dosHeader.e_lfanew > 0x10000000) {
        throw std::runtime_error("Invalid e_lfanew offset in DOS header");
    }
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
    std::cout << "\n=== DOS Header Information ===" << std::endl;
    std::cout << "File Offset: 0x00000000" << std::endl;
    
    // Display magic number with validation status
    std::cout << "Magic Number (e_magic): 0x" << std::hex << dosHeader.e_magic << std::dec;
    if (dosHeader.e_magic == 0x5A4D) {
        std::cout << " (MZ) - Valid" << std::endl;
    } else {
        std::cout << " - Invalid (Expected 0x5A4D)" << std::endl;
    }
    
    // Display key DOS header fields
    std::cout << "Bytes on Last Page (e_cblp): " << dosHeader.e_cblp << std::endl;
    std::cout << "Pages in File (e_cp): " << dosHeader.e_cp << std::endl;
    std::cout << "Relocations (e_crlc): " << dosHeader.e_crlc << std::endl;
    std::cout << "Size of Header in Paragraphs (e_cparhdr): " << dosHeader.e_cparhdr << std::endl;
    std::cout << "Minimum Extra Paragraphs (e_minalloc): " << dosHeader.e_minalloc << std::endl;
    std::cout << "Maximum Extra Paragraphs (e_maxalloc): " << dosHeader.e_maxalloc << std::endl;
    std::cout << "Initial SS Value (e_ss): 0x" << std::hex << dosHeader.e_ss << std::dec << std::endl;
    std::cout << "Initial SP Value (e_sp): 0x" << std::hex << dosHeader.e_sp << std::dec << std::endl;
    std::cout << "Checksum (e_csum): 0x" << std::hex << dosHeader.e_csum << std::dec << std::endl;
    std::cout << "Initial IP Value (e_ip): 0x" << std::hex << dosHeader.e_ip << std::dec << std::endl;
    std::cout << "Initial CS Value (e_cs): 0x" << std::hex << dosHeader.e_cs << std::dec << std::endl;
    std::cout << "File Address of Relocation Table (e_lfarlc): 0x" << std::hex << dosHeader.e_lfarlc << std::dec << std::endl;
    std::cout << "Overlay Number (e_ovno): " << dosHeader.e_ovno << std::endl;
    std::cout << "OEM Identifier (e_oemid): " << dosHeader.e_oemid << std::endl;
    std::cout << "OEM Information (e_oeminfo): " << dosHeader.e_oeminfo << std::endl;
    
    // Display e_lfanew - critical field pointing to NT headers
    std::cout << "PE Header Offset (e_lfanew): 0x" << std::hex << dosHeader.e_lfanew << std::dec;
    std::cout << " (" << dosHeader.e_lfanew << " bytes)" << std::endl;
    
    std::cout << "================================" << std::endl;
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
