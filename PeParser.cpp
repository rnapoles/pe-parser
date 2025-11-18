#include "PeParser.h"
#include <iostream>
#include <iomanip>
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
    // Seek to NT headers offset using e_lfanew from DOS header
    file.seekg(dosHeader.e_lfanew, std::ios::beg);
    
    // Read and validate PE signature (4 bytes: "PE\0\0")
    file.read(reinterpret_cast<char*>(&ntHeaders.signature), sizeof(ntHeaders.signature));
    
    if (ntHeaders.signature != 0x00004550) { // "PE\0\0" in little-endian
        throw std::runtime_error("Invalid PE signature: Expected PE\\0\\0 (0x00004550)");
    }
    
    // Read file header (20 bytes)
    file.read(reinterpret_cast<char*>(&ntHeaders.fileHeader), sizeof(FileHeader));
    
    // Read the magic number from optional header to determine architecture
    uint16_t magic;
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    
    // Seek back to read the full optional header
    file.seekg(dosHeader.e_lfanew + 4 + sizeof(FileHeader), std::ios::beg);
    
    // Determine 32-bit vs 64-bit architecture from optional header magic
    if (magic == 0x10b) {
        // 32-bit PE (PE32)
        ntHeaders.is64Bit = false;
        file.read(reinterpret_cast<char*>(&ntHeaders.optionalHeader32), sizeof(OptionalHeader32));
    } else if (magic == 0x20b) {
        // 64-bit PE (PE32+)
        ntHeaders.is64Bit = true;
        file.read(reinterpret_cast<char*>(&ntHeaders.optionalHeader64), sizeof(OptionalHeader64));
    } else {
        throw std::runtime_error("Invalid optional header magic: Unknown PE format");
    }
}

void PeParser::parseSectionHeaders() {
    // Calculate section headers offset after NT headers
    // Offset = e_lfanew + 4 (PE signature) + 20 (File Header) + sizeOfOptionalHeader
    size_t sectionHeadersOffset = dosHeader.e_lfanew + 4 + sizeof(FileHeader) + ntHeaders.fileHeader.sizeOfOptionalHeader;
    
    // Clear any existing section headers
    sectionHeaders.clear();
    
    // Get number of sections from file header
    uint16_t numberOfSections = ntHeaders.fileHeader.numberOfSections;
    
    // Validate number of sections is reasonable
    if (numberOfSections == 0 || numberOfSections > 96) {
        throw std::runtime_error("Invalid number of sections: " + std::to_string(numberOfSections));
    }
    
    // Seek to section headers offset
    file.seekg(sectionHeadersOffset, std::ios::beg);
    
    // Read all section headers (40 bytes each)
    for (uint16_t i = 0; i < numberOfSections; ++i) {
        SectionHeader section;
        
        // Read the entire section header structure
        file.read(reinterpret_cast<char*>(&section), sizeof(SectionHeader));
        
        if (file.fail()) {
            throw std::runtime_error("Failed to read section header " + std::to_string(i));
        }
        
        // Validate section boundaries
        // Check that pointerToRawData and sizeOfRawData are reasonable
        if (section.sizeOfRawData > 0) {
            // Ensure raw data pointer is not zero if size is non-zero
            if (section.pointerToRawData == 0) {
                throw std::runtime_error("Invalid section: non-zero size but zero raw data pointer");
            }
            
            // Check file alignment
            uint32_t fileAlignment = ntHeaders.is64Bit ? 
                ntHeaders.optionalHeader64.fileAlignment : 
                ntHeaders.optionalHeader32.fileAlignment;
            
            if (fileAlignment > 0 && section.pointerToRawData % fileAlignment != 0) {
                // Warning: section not aligned, but don't throw - some packers do this
            }
        }
        
        // Validate virtual address and size
        if (section.virtualSize > 0 && section.virtualAddress == 0 && i > 0) {
            // First section can have VA of 0, but others typically shouldn't
            // This is a warning condition, not an error
        }
        
        // Validate characteristics - should have at least one flag set
        if (section.characteristics == 0) {
            // Warning: section with no characteristics is unusual but not invalid
        }
        
        // Store section information in sectionHeaders vector
        sectionHeaders.push_back(section);
    }
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
    std::cout << "\n=== NT Headers Information ===" << std::endl;
    std::cout << "File Offset: 0x" << std::hex << dosHeader.e_lfanew << std::dec << std::endl;
    
    // Display PE signature
    std::cout << "\nPE Signature: 0x" << std::hex << ntHeaders.signature << std::dec;
    if (ntHeaders.signature == 0x00004550) {
        std::cout << " (PE\\0\\0) - Valid" << std::endl;
    } else {
        std::cout << " - Invalid" << std::endl;
    }
    
    // Display file header information
    std::cout << "\n--- File Header ---" << std::endl;
    
    // Machine type
    std::cout << "Machine Type: 0x" << std::hex << ntHeaders.fileHeader.machine << std::dec << " (";
    switch (ntHeaders.fileHeader.machine) {
        case 0x014c: std::cout << "Intel 386"; break;
        case 0x0162: std::cout << "MIPS R3000"; break;
        case 0x0166: std::cout << "MIPS R4000"; break;
        case 0x0168: std::cout << "MIPS R10000"; break;
        case 0x0169: std::cout << "MIPS little-endian WCE v2"; break;
        case 0x0184: std::cout << "Alpha AXP"; break;
        case 0x01a2: std::cout << "Hitachi SH3"; break;
        case 0x01a3: std::cout << "Hitachi SH3 DSP"; break;
        case 0x01a6: std::cout << "Hitachi SH4"; break;
        case 0x01a8: std::cout << "Hitachi SH5"; break;
        case 0x01c0: std::cout << "ARM little endian"; break;
        case 0x01c2: std::cout << "Thumb"; break;
        case 0x01c4: std::cout << "ARMv7 Thumb"; break;
        case 0x01d3: std::cout << "Matsushita AM33"; break;
        case 0x01f0: std::cout << "PowerPC little endian"; break;
        case 0x01f1: std::cout << "PowerPC with FPU"; break;
        case 0x0200: std::cout << "Intel IA64"; break;
        case 0x0266: std::cout << "MIPS16"; break;
        case 0x0284: std::cout << "Alpha AXP 64-bit"; break;
        case 0x0366: std::cout << "MIPS with FPU"; break;
        case 0x0466: std::cout << "MIPS16 with FPU"; break;
        case 0x0ebc: std::cout << "EFI Byte Code"; break;
        case 0x8664: std::cout << "AMD64 (x64)"; break;
        case 0x9041: std::cout << "Mitsubishi M32R little endian"; break;
        case 0xaa64: std::cout << "ARM64 little endian"; break;
        case 0xc0ee: std::cout << "clr pure MSIL"; break;
        default: std::cout << "Unknown"; break;
    }
    std::cout << ")" << std::endl;
    
    std::cout << "Number of Sections: " << ntHeaders.fileHeader.numberOfSections << std::endl;
    
    // Timestamp
    std::cout << "Time/Date Stamp: 0x" << std::hex << ntHeaders.fileHeader.timeDateStamp << std::dec;
    std::cout << " (" << ntHeaders.fileHeader.timeDateStamp << ")" << std::endl;
    
    std::cout << "Pointer to Symbol Table: 0x" << std::hex << ntHeaders.fileHeader.pointerToSymbolTable << std::dec << std::endl;
    std::cout << "Number of Symbols: " << ntHeaders.fileHeader.numberOfSymbols << std::endl;
    std::cout << "Size of Optional Header: " << ntHeaders.fileHeader.sizeOfOptionalHeader << " bytes" << std::endl;
    
    // Characteristics
    std::cout << "Characteristics: 0x" << std::hex << ntHeaders.fileHeader.characteristics << std::dec << " (";
    bool first = true;
    if (ntHeaders.fileHeader.characteristics & 0x0001) { if (!first) std::cout << ", "; std::cout << "RELOCS_STRIPPED"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0002) { if (!first) std::cout << ", "; std::cout << "EXECUTABLE"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0004) { if (!first) std::cout << ", "; std::cout << "LINE_NUMS_STRIPPED"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0008) { if (!first) std::cout << ", "; std::cout << "LOCAL_SYMS_STRIPPED"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0010) { if (!first) std::cout << ", "; std::cout << "AGGRESSIVE_WS_TRIM"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0020) { if (!first) std::cout << ", "; std::cout << "LARGE_ADDRESS_AWARE"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0080) { if (!first) std::cout << ", "; std::cout << "BYTES_REVERSED_LO"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0100) { if (!first) std::cout << ", "; std::cout << "32BIT_MACHINE"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0200) { if (!first) std::cout << ", "; std::cout << "DEBUG_STRIPPED"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0400) { if (!first) std::cout << ", "; std::cout << "REMOVABLE_RUN_FROM_SWAP"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x0800) { if (!first) std::cout << ", "; std::cout << "NET_RUN_FROM_SWAP"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x1000) { if (!first) std::cout << ", "; std::cout << "SYSTEM"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x2000) { if (!first) std::cout << ", "; std::cout << "DLL"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x4000) { if (!first) std::cout << ", "; std::cout << "UP_SYSTEM_ONLY"; first = false; }
    if (ntHeaders.fileHeader.characteristics & 0x8000) { if (!first) std::cout << ", "; std::cout << "BYTES_REVERSED_HI"; first = false; }
    std::cout << ")" << std::endl;
    
    // Display optional header information
    std::cout << "\n--- Optional Header ---" << std::endl;
    
    if (ntHeaders.is64Bit) {
        std::cout << "Magic: 0x" << std::hex << ntHeaders.optionalHeader64.magic << std::dec << " (PE32+ / 64-bit)" << std::endl;
        std::cout << "Linker Version: " << (int)ntHeaders.optionalHeader64.majorLinkerVersion << "." << (int)ntHeaders.optionalHeader64.minorLinkerVersion << std::endl;
        std::cout << "Size of Code: " << ntHeaders.optionalHeader64.sizeOfCode << " bytes" << std::endl;
        std::cout << "Size of Initialized Data: " << ntHeaders.optionalHeader64.sizeOfInitializedData << " bytes" << std::endl;
        std::cout << "Size of Uninitialized Data: " << ntHeaders.optionalHeader64.sizeOfUninitializedData << " bytes" << std::endl;
        std::cout << "Entry Point Address: 0x" << std::hex << ntHeaders.optionalHeader64.addressOfEntryPoint << std::dec << std::endl;
        std::cout << "Base of Code: 0x" << std::hex << ntHeaders.optionalHeader64.baseOfCode << std::dec << std::endl;
        std::cout << "Image Base: 0x" << std::hex << ntHeaders.optionalHeader64.imageBase << std::dec << std::endl;
        std::cout << "Section Alignment: " << ntHeaders.optionalHeader64.sectionAlignment << " bytes" << std::endl;
        std::cout << "File Alignment: " << ntHeaders.optionalHeader64.fileAlignment << " bytes" << std::endl;
        std::cout << "OS Version: " << ntHeaders.optionalHeader64.majorOperatingSystemVersion << "." << ntHeaders.optionalHeader64.minorOperatingSystemVersion << std::endl;
        std::cout << "Image Version: " << ntHeaders.optionalHeader64.majorImageVersion << "." << ntHeaders.optionalHeader64.minorImageVersion << std::endl;
        std::cout << "Subsystem Version: " << ntHeaders.optionalHeader64.majorSubsystemVersion << "." << ntHeaders.optionalHeader64.minorSubsystemVersion << std::endl;
        std::cout << "Size of Image: " << ntHeaders.optionalHeader64.sizeOfImage << " bytes" << std::endl;
        std::cout << "Size of Headers: " << ntHeaders.optionalHeader64.sizeOfHeaders << " bytes" << std::endl;
        std::cout << "Checksum: 0x" << std::hex << ntHeaders.optionalHeader64.checkSum << std::dec << std::endl;
        
        // Subsystem
        std::cout << "Subsystem: " << ntHeaders.optionalHeader64.subsystem << " (";
        switch (ntHeaders.optionalHeader64.subsystem) {
            case 1: std::cout << "Native"; break;
            case 2: std::cout << "Windows GUI"; break;
            case 3: std::cout << "Windows CUI"; break;
            case 5: std::cout << "OS/2 CUI"; break;
            case 7: std::cout << "POSIX CUI"; break;
            case 9: std::cout << "Windows CE GUI"; break;
            case 10: std::cout << "EFI Application"; break;
            case 11: std::cout << "EFI Boot Service Driver"; break;
            case 12: std::cout << "EFI Runtime Driver"; break;
            case 13: std::cout << "EFI ROM"; break;
            case 14: std::cout << "XBOX"; break;
            case 16: std::cout << "Windows Boot Application"; break;
            default: std::cout << "Unknown"; break;
        }
        std::cout << ")" << std::endl;
        
        std::cout << "DLL Characteristics: 0x" << std::hex << ntHeaders.optionalHeader64.dllCharacteristics << std::dec << std::endl;
        std::cout << "Number of RVA and Sizes: " << ntHeaders.optionalHeader64.numberOfRvaAndSizes << std::endl;
    } else {
        std::cout << "Magic: 0x" << std::hex << ntHeaders.optionalHeader32.magic << std::dec << " (PE32 / 32-bit)" << std::endl;
        std::cout << "Linker Version: " << (int)ntHeaders.optionalHeader32.majorLinkerVersion << "." << (int)ntHeaders.optionalHeader32.minorLinkerVersion << std::endl;
        std::cout << "Size of Code: " << ntHeaders.optionalHeader32.sizeOfCode << " bytes" << std::endl;
        std::cout << "Size of Initialized Data: " << ntHeaders.optionalHeader32.sizeOfInitializedData << " bytes" << std::endl;
        std::cout << "Size of Uninitialized Data: " << ntHeaders.optionalHeader32.sizeOfUninitializedData << " bytes" << std::endl;
        std::cout << "Entry Point Address: 0x" << std::hex << ntHeaders.optionalHeader32.addressOfEntryPoint << std::dec << std::endl;
        std::cout << "Base of Code: 0x" << std::hex << ntHeaders.optionalHeader32.baseOfCode << std::dec << std::endl;
        std::cout << "Base of Data: 0x" << std::hex << ntHeaders.optionalHeader32.baseOfData << std::dec << std::endl;
        std::cout << "Image Base: 0x" << std::hex << ntHeaders.optionalHeader32.imageBase << std::dec << std::endl;
        std::cout << "Section Alignment: " << ntHeaders.optionalHeader32.sectionAlignment << " bytes" << std::endl;
        std::cout << "File Alignment: " << ntHeaders.optionalHeader32.fileAlignment << " bytes" << std::endl;
        std::cout << "OS Version: " << ntHeaders.optionalHeader32.majorOperatingSystemVersion << "." << ntHeaders.optionalHeader32.minorOperatingSystemVersion << std::endl;
        std::cout << "Image Version: " << ntHeaders.optionalHeader32.majorImageVersion << "." << ntHeaders.optionalHeader32.minorImageVersion << std::endl;
        std::cout << "Subsystem Version: " << ntHeaders.optionalHeader32.majorSubsystemVersion << "." << ntHeaders.optionalHeader32.minorSubsystemVersion << std::endl;
        std::cout << "Size of Image: " << ntHeaders.optionalHeader32.sizeOfImage << " bytes" << std::endl;
        std::cout << "Size of Headers: " << ntHeaders.optionalHeader32.sizeOfHeaders << " bytes" << std::endl;
        std::cout << "Checksum: 0x" << std::hex << ntHeaders.optionalHeader32.checkSum << std::dec << std::endl;
        
        // Subsystem
        std::cout << "Subsystem: " << ntHeaders.optionalHeader32.subsystem << " (";
        switch (ntHeaders.optionalHeader32.subsystem) {
            case 1: std::cout << "Native"; break;
            case 2: std::cout << "Windows GUI"; break;
            case 3: std::cout << "Windows CUI"; break;
            case 5: std::cout << "OS/2 CUI"; break;
            case 7: std::cout << "POSIX CUI"; break;
            case 9: std::cout << "Windows CE GUI"; break;
            case 10: std::cout << "EFI Application"; break;
            case 11: std::cout << "EFI Boot Service Driver"; break;
            case 12: std::cout << "EFI Runtime Driver"; break;
            case 13: std::cout << "EFI ROM"; break;
            case 14: std::cout << "XBOX"; break;
            case 16: std::cout << "Windows Boot Application"; break;
            default: std::cout << "Unknown"; break;
        }
        std::cout << ")" << std::endl;
        
        std::cout << "DLL Characteristics: 0x" << std::hex << ntHeaders.optionalHeader32.dllCharacteristics << std::dec << std::endl;
        std::cout << "Number of RVA and Sizes: " << ntHeaders.optionalHeader32.numberOfRvaAndSizes << std::endl;
    }
    
    // Show file characteristics and architecture information
    std::cout << "\n--- File Type and Architecture ---" << std::endl;
    std::cout << "Architecture: " << (is64Bits() ? "64-bit (x64)" : "32-bit (x86)") << std::endl;
    std::cout << "File Type: ";
    if (isDLL()) {
        std::cout << "Dynamic Link Library (DLL)" << std::endl;
    } else if (isExe()) {
        std::cout << "Executable (EXE)" << std::endl;
    } else {
        std::cout << "Other" << std::endl;
    }
    std::cout << "Target OS: " << getTargetOS() << std::endl;
    
    std::cout << "================================" << std::endl;
}

void PeParser::printSectionHeadersInfo() {
    std::cout << "\n=== Section Headers Information ===" << std::endl;
    std::cout << "Number of Sections: " << sectionHeaders.size() << std::endl;
    std::cout << "\n";
    
    // Display table header
    std::cout << "Section Name    Virtual Addr  Virtual Size  Raw Size      Raw Offset    Characteristics" << std::endl;
    std::cout << "------------    ------------  ------------  ------------  ------------  ---------------" << std::endl;
    
    // Display each section
    for (size_t i = 0; i < sectionHeaders.size(); ++i) {
        const SectionHeader& section = sectionHeaders[i];
        
        // Extract section name (max 8 chars, may not be null-terminated)
        char sectionName[9] = {0};
        std::memcpy(sectionName, section.name, 8);
        
        // Display section information in table format
        std::cout.width(15);
        std::cout << std::left << sectionName << " ";
        
        std::cout << "0x" << std::hex << std::setfill('0');
        std::cout.width(10);
        std::cout << std::right << section.virtualAddress << "  ";
        
        std::cout << "0x" << std::setfill('0');
        std::cout.width(10);
        std::cout << section.virtualSize << "  ";
        
        std::cout << "0x" << std::setfill('0');
        std::cout.width(10);
        std::cout << section.sizeOfRawData << "  ";
        
        std::cout << "0x" << std::setfill('0');
        std::cout.width(10);
        std::cout << section.pointerToRawData << "  ";
        
        std::cout << std::dec << std::setfill(' ');
        
        // Display section flags (executable, readable, writable)
        std::cout << "0x" << std::hex << section.characteristics << " (";
        
        bool first = true;
        
        // Check common section characteristics flags
        if (section.characteristics & 0x00000020) { // IMAGE_SCN_CNT_CODE
            if (!first) std::cout << ", ";
            std::cout << "CODE";
            first = false;
        }
        if (section.characteristics & 0x00000040) { // IMAGE_SCN_CNT_INITIALIZED_DATA
            if (!first) std::cout << ", ";
            std::cout << "INIT_DATA";
            first = false;
        }
        if (section.characteristics & 0x00000080) { // IMAGE_SCN_CNT_UNINITIALIZED_DATA
            if (!first) std::cout << ", ";
            std::cout << "UNINIT_DATA";
            first = false;
        }
        if (section.characteristics & 0x02000000) { // IMAGE_SCN_MEM_DISCARDABLE
            if (!first) std::cout << ", ";
            std::cout << "DISCARDABLE";
            first = false;
        }
        if (section.characteristics & 0x10000000) { // IMAGE_SCN_MEM_SHARED
            if (!first) std::cout << ", ";
            std::cout << "SHARED";
            first = false;
        }
        if (section.characteristics & 0x20000000) { // IMAGE_SCN_MEM_EXECUTE
            if (!first) std::cout << ", ";
            std::cout << "EXEC";
            first = false;
        }
        if (section.characteristics & 0x40000000) { // IMAGE_SCN_MEM_READ
            if (!first) std::cout << ", ";
            std::cout << "READ";
            first = false;
        }
        if (section.characteristics & 0x80000000) { // IMAGE_SCN_MEM_WRITE
            if (!first) std::cout << ", ";
            std::cout << "WRITE";
            first = false;
        }
        
        std::cout << ")" << std::dec << std::endl;
    }
    
    // Display detailed information for each section
    std::cout << "\n--- Detailed Section Information ---" << std::endl;
    
    for (size_t i = 0; i < sectionHeaders.size(); ++i) {
        const SectionHeader& section = sectionHeaders[i];
        
        // Extract section name
        char sectionName[9] = {0};
        std::memcpy(sectionName, section.name, 8);
        
        std::cout << "\nSection " << (i + 1) << ": " << sectionName << std::endl;
        std::cout << "  Virtual Address: 0x" << std::hex << section.virtualAddress << std::dec << std::endl;
        std::cout << "  Virtual Size: " << section.virtualSize << " bytes (0x" << std::hex << section.virtualSize << std::dec << ")" << std::endl;
        std::cout << "  Raw Data Size: " << section.sizeOfRawData << " bytes (0x" << std::hex << section.sizeOfRawData << std::dec << ")" << std::endl;
        std::cout << "  Raw Data Offset: 0x" << std::hex << section.pointerToRawData << std::dec << std::endl;
        std::cout << "  Relocations Offset: 0x" << std::hex << section.pointerToRelocations << std::dec << std::endl;
        std::cout << "  Line Numbers Offset: 0x" << std::hex << section.pointerToLinenumbers << std::dec << std::endl;
        std::cout << "  Number of Relocations: " << section.numberOfRelocations << std::endl;
        std::cout << "  Number of Line Numbers: " << section.numberOfLinenumbers << std::endl;
        std::cout << "  Characteristics: 0x" << std::hex << section.characteristics << std::dec << std::endl;
        
        // Show section flags in readable format
        std::cout << "  Flags: ";
        bool hasFlags = false;
        
        if (section.characteristics & 0x20000000) { // EXEC
            std::cout << "Executable";
            hasFlags = true;
        }
        if (section.characteristics & 0x40000000) { // READ
            if (hasFlags) std::cout << " | ";
            std::cout << "Readable";
            hasFlags = true;
        }
        if (section.characteristics & 0x80000000) { // WRITE
            if (hasFlags) std::cout << " | ";
            std::cout << "Writable";
            hasFlags = true;
        }
        
        if (!hasFlags) {
            std::cout << "None";
        }
        std::cout << std::endl;
    }
    
    std::cout << "\n====================================" << std::endl;
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
    // Extract OS version from optional header
    uint16_t majorVersion, minorVersion;
    
    if (ntHeaders.is64Bit) {
        majorVersion = ntHeaders.optionalHeader64.majorOperatingSystemVersion;
        minorVersion = ntHeaders.optionalHeader64.minorOperatingSystemVersion;
    } else {
        majorVersion = ntHeaders.optionalHeader32.majorOperatingSystemVersion;
        minorVersion = ntHeaders.optionalHeader32.minorOperatingSystemVersion;
    }
    
    // Map version numbers to Windows versions
    std::string osVersion = "Windows ";
    
    if (majorVersion == 4 && minorVersion == 0) {
        osVersion += "NT 4.0 / 95";
    } else if (majorVersion == 5 && minorVersion == 0) {
        osVersion += "2000";
    } else if (majorVersion == 5 && minorVersion == 1) {
        osVersion += "XP";
    } else if (majorVersion == 5 && minorVersion == 2) {
        osVersion += "Server 2003 / XP 64-bit";
    } else if (majorVersion == 6 && minorVersion == 0) {
        osVersion += "Vista / Server 2008";
    } else if (majorVersion == 6 && minorVersion == 1) {
        osVersion += "7 / Server 2008 R2";
    } else if (majorVersion == 6 && minorVersion == 2) {
        osVersion += "8 / Server 2012";
    } else if (majorVersion == 6 && minorVersion == 3) {
        osVersion += "8.1 / Server 2012 R2";
    } else if (majorVersion == 10 && minorVersion == 0) {
        osVersion += "10 / Server 2016+";
    } else {
        osVersion += std::to_string(majorVersion) + "." + std::to_string(minorVersion);
    }
    
    return osVersion;
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
    // Check characteristics field for executable flag
    // IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    // IMAGE_FILE_DLL = 0x2000
    // An EXE has the executable flag set but NOT the DLL flag
    const uint16_t IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
    const uint16_t IMAGE_FILE_DLL = 0x2000;
    
    return (ntHeaders.fileHeader.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) &&
           !(ntHeaders.fileHeader.characteristics & IMAGE_FILE_DLL);
}

bool PeParser::isDLL() {
    // Check characteristics field for DLL flag
    // IMAGE_FILE_DLL = 0x2000
    const uint16_t IMAGE_FILE_DLL = 0x2000;
    
    return (ntHeaders.fileHeader.characteristics & IMAGE_FILE_DLL) != 0;
}

bool PeParser::is64Bits() {
    // Check optional header magic value
    // 0x10b = PE32 (32-bit), 0x20b = PE32+ (64-bit)
    return ntHeaders.is64Bit;
}
