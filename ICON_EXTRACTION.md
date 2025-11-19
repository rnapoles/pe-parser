# Icon Extraction Feature

## Overview
The `PeParser::saveIcon()` function extracts icon resources from Windows PE files (.exe, .dll) and saves them in standard .ICO format.

## Function Signature
```cpp
bool PeParser::saveIcon(const std::string& outputPath);
```

## Parameters
- `outputPath`: The file path where the extracted icon will be saved (e.g., "output.ico")

## Return Value
- Returns `true` if the icon was successfully extracted and saved
- Returns `false` if extraction failed (no icon found, invalid PE file, etc.)

## How It Works
The function performs the following steps:

1. **Validates the PE file** - Ensures the file is a valid PE executable
2. **Locates the resource directory** - Finds the resource section in the PE file
3. **Navigates the resource tree** - Traverses the three-level resource directory structure:
   - Level 1: Resource type (RT_GROUP_ICON and RT_ICON)
   - Level 2: Resource ID
   - Level 3: Language
4. **Reads icon group data** - Extracts metadata about all icon images
5. **Collects icon image data** - Retrieves the actual pixel data for each icon size/format
6. **Writes ICO file** - Creates a standard Windows .ICO file with all icon images

## Icon File Format
The extracted .ICO file contains:
- **ICO Header**: Identifies the file as an icon and specifies the number of images
- **Icon Directory Entries**: Metadata for each icon image (dimensions, color depth, size)
- **Icon Image Data**: The actual bitmap or PNG data for each icon variant

Most Windows executables contain multiple icon images at different resolutions (16x16, 32x32, 48x48, 256x256, etc.) to support various display contexts.

## Usage Example

### Basic Usage
```cpp
#include "PeParser.h"

int main() {
    PeParser parser("notepad.exe");
    parser.parseFile();
    
    if (parser.saveIcon("notepad.ico")) {
        std::cout << "Icon extracted successfully!" << std::endl;
    } else {
        std::cout << "Failed to extract icon" << std::endl;
    }
    
    return 0;
}
```

### Command-Line Tool
```cpp
#include "PeParser.h"
#include <iostream>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <input.exe> <output.ico>" << std::endl;
        return 1;
    }
    
    try {
        PeParser parser(argv[1]);
        parser.parseFile();
        
        if (parser.saveIcon(argv[2])) {
            std::cout << "Success!" << std::endl;
        } else {
            std::cerr << "Extraction failed" << std::endl;
            return 1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
```

## Error Handling
The function provides detailed error messages for various failure scenarios:

- **"Not a valid PE file"** - The input file is not a valid PE executable
- **"No resource directory in PE file"** - The PE file has no resource section
- **"Resource directory is empty"** - The resource section exists but is empty
- **"No icon group found in resources"** - No RT_GROUP_ICON resource type found
- **"No icon resources found"** - No RT_ICON resource type found
- **"Failed to create output file"** - Unable to write to the specified output path
- **"No icon data was extracted"** - Icon resources exist but couldn't be read

## Technical Details

### Resource Types
- **RT_ICON (3)**: Individual icon images at specific resolutions
- **RT_GROUP_ICON (14)**: Icon group that references multiple RT_ICON resources

### Resource Directory Structure
Windows PE resources are organized in a three-level tree:
```
Root Directory
├── Resource Type (RT_GROUP_ICON, RT_ICON, etc.)
│   ├── Resource ID (numeric identifier)
│   │   └── Language (0x409 for English, etc.)
│   │       └── Data Entry (RVA and size of actual data)
```

### Structures Used
The implementation uses several structures defined in `PeParser.h`:

- `ResourceDirectoryTable`: Header for each directory level
- `ResourceDirectoryEntry`: Entry in a resource directory
- `ResourceDataEntry`: Points to actual resource data
- `IconDir`: ICO file header
- `IconDirEntry`: Entry in ICO file directory

## Limitations
- Extracts only the first icon group found (typically the main application icon)
- Requires the PE file to have a valid resource section
- Only supports standard icon resources (not custom or compressed formats)

## Compilation
Make sure to compile with C++11 or later:
```bash
g++ -std=c++11 example_icon_extraction.cpp PeParser.cpp -o icon_extractor
```

## Testing
Test with common Windows executables:
```bash
./icon_extractor C:\Windows\System32\notepad.exe notepad.ico
./icon_extractor C:\Windows\System32\calc.exe calculator.ico
```

## See Also
- `PeParser::parseFile()` - Main parsing method that must be called first
- Microsoft PE/COFF Specification
- ICO file format specification
