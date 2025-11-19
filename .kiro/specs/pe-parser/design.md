# PE Parser Design Document

## Overview

The PE Parser is a C++ class that provides comprehensive parsing and analysis capabilities for Windows Portable Executable files. The design follows a modular approach where each PE structure (DOS header, NT headers, sections, imports, exports) is parsed by dedicated methods and stored in structured data members for efficient access and display.

## Architecture

The PE Parser uses a single-class design with clear separation of concerns:

- **File I/O Layer**: Handles binary file reading and validation
- **Parsing Layer**: Dedicated methods for each PE structure type
- **Data Storage Layer**: Internal structures to hold parsed information
- **Information Access Layer**: Query methods and display functions

```
┌─────────────────────────────────────────┐
│              PE Parser Class            │
├─────────────────────────────────────────┤
│  File I/O & Validation                  │
│  ├─ File reading/seeking                │
│  ├─ Error handling                      │
│  └─ Data validation                     │
├─────────────────────────────────────────┤
│  Structure Parsing                      │
│  ├─ DOS Header parsing                  │
│  ├─ Rich Header parsing                 │
│  ├─ NT Headers parsing                  │
│  ├─ Section Headers parsing             │
│  ├─ Import Table parsing                │
│  └─ Export Table parsing                │
├─────────────────────────────────────────┤
│  Data Storage                           │
│  ├─ Header structures                   │
│  ├─ Section information                 │
│  ├─ Import/Export lists                 │
│  └─ File metadata                       │
├─────────────────────────────────────────┤
│  Information Access                     │
│  ├─ Query methods (isExe, isDLL, etc.)  │
│  └─ Display methods (print functions)   │
└─────────────────────────────────────────┘
```

## Components and Interfaces

### Core Class Structure

```cpp
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
```

### Supporting Data Structures

```cpp
struct DOSHeader {
    uint16_t e_magic;      // Magic number
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

struct FileHeader {
    uint16_t machine;              // Target machine type
    uint16_t numberOfSections;     // Number of sections
    uint32_t timeDateStamp;        // Time/date stamp
    uint32_t pointerToSymbolTable; // Pointer to symbol table
    uint32_t numberOfSymbols;      // Number of symbols
    uint16_t sizeOfOptionalHeader; // Size of optional header
    uint16_t characteristics;      // File characteristics
};

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

struct ImportEntry {
    std::string dllName;
    std::vector<std::string> functionNames;
    std::vector<uint32_t> ordinals;
};

struct ExportEntry {
    std::string functionName;
    uint32_t ordinal;
    uint32_t rva;
};
```

## Data Models

### PE File Structure Layout

The parser handles the standard PE file layout:

1. **DOS Header** (64 bytes) - Legacy MS-DOS compatibility header
2. **DOS Stub** (variable) - Legacy MS-DOS program stub
3. **Rich Header** (optional) - Microsoft compiler metadata
4. **NT Headers** - Core PE headers including:
   - PE Signature (4 bytes)
   - File Header (20 bytes)
   - Optional Header (224/240 bytes for 32/64-bit)
5. **Section Headers** (40 bytes each) - Section metadata
6. **Section Data** - Actual section contents (.text, .data, etc.)

### Memory Management

- File data is read on-demand using file stream seeking
- Parsed structures are stored in class members for efficient access
- String data is copied to std::string objects for safe memory management
- Vector containers manage variable-length data (sections, imports, exports)

## Error Handling

### File I/O Errors
- Invalid file paths result in constructor exceptions
- File read errors are caught and reported through error flags
- Malformed PE files are detected through signature validation

### Data Validation
- PE signature validation ensures file is actually a PE file
- Header size validation prevents buffer overruns
- Section boundary validation prevents invalid memory access
- Import/export table validation ensures data integrity

### Error Reporting Strategy
```cpp
enum class ParseError {
    None,
    FileNotFound,
    InvalidPESignature,
    CorruptedHeader,
    InvalidSectionData,
    ImportTableError,
    ExportTableError
};
```

## Testing Strategy

### Unit Testing Approach
- Test each parsing method independently with known PE files
- Validate data structure population with expected values
- Test error handling with malformed/corrupted PE files
- Verify cross-platform compatibility (Linux parsing Windows PE files)

### Test Data Requirements
- Sample PE files: .exe, .dll, both 32-bit and 64-bit
- Corrupted PE files for error handling validation
- PE files with various section layouts and import/export configurations
- Files with and without Rich headers

### Integration Testing
- End-to-end parsing of complete PE files
- Validation of parsed data consistency across all structures
- Performance testing with large PE files
- Memory usage validation for resource management

### Platform Testing
- Compilation testing on Linux with GCC
- Compilation testing on Windows with GCC
- Endianness handling verification
- File path handling across different filesystems
- Standard library compatibility validation

## Implementation Notes

### Cross-Platform Considerations
- Use standard C++ file I/O for maximum portability
- Handle little-endian PE format on potentially big-endian systems
- Use fixed-width integer types (uint32_t, uint16_t) for consistent data sizes
- Implement proper error handling for different filesystem behaviors

### Performance Optimizations
- Lazy loading: Parse structures only when requested
- Efficient file seeking to avoid loading entire file into memory
- Minimal memory footprint by storing only essential parsed data
- Fast string operations using std::string with reserve() for known sizes

### Security Considerations
- Bounds checking for all file reads to prevent buffer overflows
- Validation of all offset values before file seeking
- Safe string handling to prevent buffer overruns
- Input sanitization for display functions to prevent format string attacks