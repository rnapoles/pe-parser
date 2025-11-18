#ifndef PE_PARSER_H
#define PE_PARSER_H

#include <string>
#include <vector>
#include <fstream>
#include <cstdint>

// DOS Header structure (64 bytes)
struct DOSHeader {
    uint16_t e_magic;      // Magic number (MZ)
    uint16_t e_cblp;       // Bytes on last page
    uint16_t e_cp;         // Pages in file
    uint16_t e_crlc;       // Relocations
    uint16_t e_cparhdr;    // Size of header in paragraphs
    uint16_t e_minalloc;   // Minimum extra paragraphs
    uint16_t e_maxalloc;   // Maximum extra paragraphs
    uint16_t e_ss;         // Initial relative SS value
    uint16_t e_sp;         // Initial SP value
    uint16_t e_csum;       // Checksum
    uint16_t e_ip;         // Initial IP value
    uint16_t e_cs;         // Initial relative CS value
    uint16_t e_lfarlc;     // File address of relocation table
    uint16_t e_ovno;       // Overlay number
    uint16_t e_res[4];     // Reserved words
    uint16_t e_oemid;      // OEM identifier
    uint16_t e_oeminfo;    // OEM information
    uint16_t e_res2[10];   // Reserved words
    uint32_t e_lfanew;     // File address of new exe header
};

// Rich Header structure
struct RichHeader {
    bool present;
    std::vector<uint8_t> data;
};

// File Header structure (20 bytes)
struct FileHeader {
    uint16_t machine;              // Target machine type
    uint16_t numberOfSections;     // Number of sections
    uint32_t timeDateStamp;        // Time/date stamp
    uint32_t pointerToSymbolTable; // Pointer to symbol table
    uint32_t numberOfSymbols;      // Number of symbols
    uint16_t sizeOfOptionalHeader; // Size of optional header
    uint16_t characteristics;      // File characteristics
};

#pragma pack(push, 1)

// Data Directory structure
struct DataDirectory {
    uint32_t virtualAddress;  // RVA of the data
    uint32_t size;            // Size of the data
};

// Optional Header for 32-bit PE
struct OptionalHeader32 {
    uint16_t magic;                    // Magic number
    uint8_t majorLinkerVersion;        // Linker version
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;               // Size of code section
    uint32_t sizeOfInitializedData;    // Size of initialized data
    uint32_t sizeOfUninitializedData;  // Size of uninitialized data
    uint32_t addressOfEntryPoint;      // Entry point RVA
    uint32_t baseOfCode;               // Base of code RVA
    uint32_t baseOfData;               // Base of data RVA
    uint32_t imageBase;                // Image base address
    uint32_t sectionAlignment;         // Section alignment
    uint32_t fileAlignment;            // File alignment
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;              // Size of image
    uint32_t sizeOfHeaders;            // Size of headers
    uint32_t checkSum;                 // Checksum
    uint16_t subsystem;                // Subsystem
    uint16_t dllCharacteristics;       // DLL characteristics
    uint32_t sizeOfStackReserve;       // Stack reserve size
    uint32_t sizeOfStackCommit;        // Stack commit size
    uint32_t sizeOfHeapReserve;        // Heap reserve size
    uint32_t sizeOfHeapCommit;         // Heap commit size
    uint32_t loaderFlags;              // Loader flags
    uint32_t numberOfRvaAndSizes;      // Number of data directories
};

// Optional Header for 64-bit PE
struct OptionalHeader64 {
    uint16_t magic;                    // Magic number
    uint8_t majorLinkerVersion;        // Linker version
    uint8_t minorLinkerVersion;
    uint32_t sizeOfCode;               // Size of code section
    uint32_t sizeOfInitializedData;    // Size of initialized data
    uint32_t sizeOfUninitializedData;  // Size of uninitialized data
    uint32_t addressOfEntryPoint;      // Entry point RVA
    uint32_t baseOfCode;               // Base of code RVA
    uint64_t imageBase;                // Image base address
    uint32_t sectionAlignment;         // Section alignment
    uint32_t fileAlignment;            // File alignment
    uint16_t majorOperatingSystemVersion;
    uint16_t minorOperatingSystemVersion;
    uint16_t majorImageVersion;
    uint16_t minorImageVersion;
    uint16_t majorSubsystemVersion;
    uint16_t minorSubsystemVersion;
    uint32_t win32VersionValue;
    uint32_t sizeOfImage;              // Size of image
    uint32_t sizeOfHeaders;            // Size of headers
    uint32_t checkSum;                 // Checksum
    uint16_t subsystem;                // Subsystem
    uint16_t dllCharacteristics;       // DLL characteristics
    uint64_t sizeOfStackReserve;       // Stack reserve size
    uint64_t sizeOfStackCommit;        // Stack commit size
    uint64_t sizeOfHeapReserve;        // Heap reserve size
    uint64_t sizeOfHeapCommit;         // Heap commit size
    uint32_t loaderFlags;              // Loader flags
    uint32_t numberOfRvaAndSizes;      // Number of data directories
};

// NT Headers structure
struct NTHeaders {
    uint32_t signature;           // PE signature
    FileHeader fileHeader;
    OptionalHeader32 optionalHeader32;
    OptionalHeader64 optionalHeader64;
    DataDirectory dataDirectories[16];  // Data directories (separate from optional header)
    bool is64Bit;
};

// Section Header structure (40 bytes)
struct SectionHeader {
    char name[8];                 // Section name
    uint32_t virtualSize;         // Virtual size
    uint32_t virtualAddress;      // Virtual address
    uint32_t sizeOfRawData;       // Size of raw data
    uint32_t pointerToRawData;    // Pointer to raw data
    uint32_t pointerToRelocations; // Pointer to relocations
    uint32_t pointerToLinenumbers; // Pointer to line numbers
    uint16_t numberOfRelocations;  // Number of relocations
    uint16_t numberOfLinenumbers;  // Number of line numbers
    uint32_t characteristics;      // Section characteristics
};

#pragma pack(pop)

// Import Entry structure
struct ImportEntry {
    std::string dllName;
    std::vector<std::string> functionNames;
    std::vector<uint32_t> ordinals;
};

// Export Entry structure
struct ExportEntry {
    std::string functionName;
    uint32_t ordinal;
    uint32_t rva;
};

// Main PE Parser class
class PeParser {
private:
    // File handling
    std::ifstream file;
    std::string filename;
    bool isValidPE;
    
    // PE Structures
    DOSHeader dosHeader;
    RichHeader richHeader;
    NTHeaders ntHeaders;
    std::vector<SectionHeader> sectionHeaders;
    std::vector<ImportEntry> imports;
    std::vector<ExportEntry> exports;
    
    // Helper methods
    template<typename T> T readData(size_t offset);
    std::string readString(size_t offset, size_t maxLength = 256);
    bool validatePESignature();
    uint32_t rvaToFileOffset(uint32_t rva);
    std::string readStringAtRVA(uint32_t rva, size_t maxLength = 256);
    
public:
    // Constructor/Destructor
    PeParser(const std::string& filepath);
    ~PeParser();
    
    // Parsing methods
    void parseFile();
    void parseDOSHeader();
    void parseRichHeader();
    void parseNTHeaders();
    void parseSectionHeaders();
    void parseImports();
    void parseExports();
    
    // Information methods
    void printFileInfo();
    void printDOSHeaderInfo();
    void printRichHeaderInfo();
    void printNTHeadersInfo();
    void printSectionHeadersInfo();
    void printImportTableInfo();
    void printBaseRelocationsInfo();
    void printImportFunctions();
    void printExportFunctions();
    
    // Query methods
    std::string getTargetOS();
    std::vector<std::string> getExportFunctionNames();
    std::vector<std::string> getImportFunctionNames();
    bool isExe();
    bool isDLL();
    bool is64Bits();
};

#endif // PE_PARSER_H
