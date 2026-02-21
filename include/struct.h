////////////////////////
//
//  Created: Tue Jun 25 2024
//  File: struct.h
//
////////////////////////

#pragma once

#include <stdint.h>

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

typedef struct CoffHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} __attribute__((packed)) CoffHeader;

typedef struct ImageDataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
} __attribute__((packed)) ImageDataDirectory;

typedef struct OptionalHeader32 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((packed)) OptionalHeader32;

typedef struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t MajorLinkerVersion;
    uint8_t MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
    ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} __attribute__((packed)) OptionalHeader64;

typedef struct SectionHeader {
    uint8_t Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            uint32_t PhysicalAddress;
            uint32_t VirtualSize;
    } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} __attribute__((packed)) SectionHeader_t;

typedef struct ImageImportDescriptor {
    union {
        uint32_t Characteristics;
        uint32_t OriginalFirstThunk;    // RVA Import Lookup Table
    } DUMMY_UNION_NAME;
    uint32_t TimeDateStamp;             // 0 -> no bound | -1 bound
    uint32_t Forwarder1Chain;           // Index of the 1st reference of the forwarder
    uint32_t Name;                      // RVA str ascii of the import DLL name
    uint32_t FirstThunk;                // RVA Import Address Table
} ImageImportDescriptor_t;

typedef struct ImageImportByName {
    uint16_t Hint;
    char Name[1];
} ImageImportByName_t;

//If a biased ordinal is retrieved, it must be made unbiased.
//The formula to do so being ordinal = biased_ordinal - OrdinalBase.
typedef struct ImageExportDescriptor
{
    uint32_t ExportFlags;
    uint32_t TimeStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t NameRVA;
    uint32_t OrdinalBase;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t ExportAddressTableRVA;
    uint32_t NamePointerRVA;
    uint32_t OrdinalTableRVA;
} __attribute__((packed)) ImageExportDescriptor_t;

//If the specified uint32 value isn't within the export section (boundaries are the address and size defined in the OptionalHeader),
//then it is an ExportRVA, otherwise, it is a ForwarderRVA.
//ExportRVAs are addresses in the binary, ForwarderRVAs are pointers to a NULL terminated ASCII string in the form DLLNAME.functionname OR DLLNAME#OrdinalNumber.
//If a ForwarderRVA is used, the DLL referenced by it must be searched as well to locate the real exported function's address.
typedef struct ImageExportAddressTableEntry
{
    union
    {
        uint32_t ExportRVA;
        uint32_t ForwarderRVA;
    } RVA;
} ImageExportAddressTableEntry_t;

//These three tables effectively act as one.
//If an export has an export name pointer entry, then the ordinal and its name are located at the same index.
//Using the ordinal, one can fetch the correct export address entry.
typedef struct ImageExportNamePointerTableEntry
{
    uint32_t ExportNameTableEntryRVA;
} ImageExportNamePointerTableEntry_t;

typedef struct ImageExportOrdinalTableEntry
{
    uint16_t Ordinal;
} ImageExportOrdinalTableEntry_t;

typedef struct ImageExportNameTableEntry
{
    char Name[1];
} ImageExportNameTableEntry_t;
