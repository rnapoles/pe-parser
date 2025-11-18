#include "PeParser.h"
#include <iostream>

int main() {
    std::cout << "OptionalHeader32 size: " << sizeof(OptionalHeader32) << " bytes" << std::endl;
    std::cout << "OptionalHeader64 size: " << sizeof(OptionalHeader64) << " bytes" << std::endl;
    std::cout << "DataDirectory size: " << sizeof(DataDirectory) << " bytes" << std::endl;
    return 0;
}
