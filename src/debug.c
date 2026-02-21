////////////////////////
//
//  Created: Sun Nov 09 2025
//  File: debug.c
//
////////////////////////

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "read.h"
#include "struct.h"

static void display_optional_header32(const char *binary_without_offset, const char *binary, CoffHeader *coff_header);
static void display_optional_header64(const char *binary_without_offset, const char *binary, CoffHeader *coff_header);

void parse_binary(const char *path)
{
    size_t binary_size = 0;
    char *binary = read_file(path, &binary_size);

    if (!binary) {
        printf("Failed to read the file: %s\n", path);
        return;
    }

    // Check magic number
    if (binary[0] != 'M' || binary[1] != 'Z') {
        printf("Invalid magic number\n");
        free(binary);
        return;
    }

    uint16_t address = (binary[60] & 0xFF) | (binary[61] & 0xFF) << 8;
    size_t current_offset = address + 4;
    printf("Address: %d\n", address);

    // Check PE
    if (strcmp(&binary[address], "PE\0\0")) {
        printf("Invalid PE\n");
        free(binary);
        return;
    }

    CoffHeader coff_header = *(CoffHeader *)&binary[current_offset];
    printf("Machine: %x\n", coff_header.Machine);
    printf("NumberOfSections: %d\n", coff_header.NumberOfSections);
    printf("TimeDateStamp: %d\n", coff_header.TimeDateStamp);
    printf("PointerToSymbolTable: %x\n", coff_header.PointerToSymbolTable);
    printf("NumberOfSymbols: %d\n", coff_header.NumberOfSymbols);
    printf("SizeOfOptionalHeader: %d\n", coff_header.SizeOfOptionalHeader);
    printf("Characteristics: %x\n", coff_header.Characteristics);
    current_offset += sizeof(CoffHeader);

    // Check has optional header
    if (!coff_header.SizeOfOptionalHeader) {
        printf("No optional header\n");
        free(binary);
        return;
    }

    if (coff_header.Machine == 0x8664)
        display_optional_header64(binary, binary + current_offset, &coff_header);
    else if (coff_header.Machine == 0x014C)
        display_optional_header32(binary, binary + current_offset, &coff_header);
    else
        printf("Unsupported binary: %x\n", coff_header.Machine);

    free(binary);
}

static void display_optional_header32(const char *binary_without_offset, const char *binary, CoffHeader *coff_header)
{
    OptionalHeader32 optional_header = *(OptionalHeader32 *)binary;
    printf("\n");
    printf("Magic: %x\n", optional_header.Magic);
    printf("MajorLinkerVersion: %d\n", optional_header.MajorLinkerVersion);
    printf("MinorLinkerVersion: %d\n", optional_header.MinorLinkerVersion);
    printf("SizeOfCode: %d\n", optional_header.SizeOfCode);
    printf("SizeOfInitializedData: %d\n", optional_header.SizeOfInitializedData);
    printf("SizeOfUninitializedData: %d\n", optional_header.SizeOfUninitializedData);
    printf("AddressOfEntryPoint: %x\n", optional_header.AddressOfEntryPoint);
    printf("BaseOfCode: %x\n", optional_header.BaseOfCode);
    printf("ImageBase: %x\n", optional_header.ImageBase);
    printf("SectionAlignment: %d\n", optional_header.SectionAlignment);
    printf("FileAlignment: %d\n", optional_header.FileAlignment);
    printf("MajorOperatingSystemVersion: %d\n", optional_header.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %d\n", optional_header.MinorOperatingSystemVersion);
    printf("MajorImageVersion: %d\n", optional_header.MajorImageVersion);
    printf("MinorImageVersion: %d\n", optional_header.MinorImageVersion);
    printf("MajorSubsystemVersion: %d\n", optional_header.MajorSubsystemVersion);
    printf("MinorSubsystemVersion: %d\n", optional_header.MinorSubsystemVersion);
    printf("Win32VersionValue: %x\n", optional_header.Win32VersionValue);
    printf("SizeOfImage: %d\n", optional_header.SizeOfImage);
    printf("SizeOfHeaders: %d\n", optional_header.SizeOfHeaders);
    printf("CheckSum: %x\n", optional_header.CheckSum);
    printf("Subsystem: %x\n", optional_header.Subsystem);
    printf("DllCharacteristics: %x\n", optional_header.DllCharacteristics);
    printf("SizeOfStackReserve: %d\n", optional_header.SizeOfStackReserve);
    printf("SizeOfStackCommit: %d\n", optional_header.SizeOfStackCommit);
    printf("SizeOfHeapReserve: %d\n", optional_header.SizeOfHeapReserve);
    printf("SizeOfHeapCommit: %d\n", optional_header.SizeOfHeapCommit);
    printf("LoaderFlags: %x\n", optional_header.LoaderFlags);
    printf("NumberOfRvaAndSizes: %d\n", optional_header.NumberOfRvaAndSizes);

    for (size_t i = 0; i < optional_header.NumberOfRvaAndSizes; ++i) {
        printf("-VirtualAddress: %x\n", optional_header.DataDirectory[i].VirtualAddress);
        printf("-Size: %d\n", optional_header.DataDirectory[i].Size);
    }

    uint32_t import_directory_virtual_address = 0;
    uint32_t import_directory_size = 0;

    if (optional_header.NumberOfRvaAndSizes > 12) {
        import_directory_virtual_address = optional_header.DataDirectory[1].VirtualAddress;
        import_directory_size = optional_header.DataDirectory[1].Size;
    }

    SectionHeader_t *section_headers = (SectionHeader_t *)&binary[sizeof(OptionalHeader32)];
    uint32_t import_directory_section_header_index = 0;

    for (size_t i = 0; i < coff_header->NumberOfSections; ++i) {
        printf("\nName: %s\n", section_headers[i].Name);
        printf("PhysicalAddress: %x\n", section_headers[i].Misc.PhysicalAddress);
        printf("VirtualAddress: %x\n", section_headers[i].VirtualAddress);
        printf("SizeOfRawData: %d\n", section_headers[i].SizeOfRawData);
        printf("PointerToRawData: %x\n", section_headers[i].PointerToRawData);
        printf("PointerToRelocations: %x\n", section_headers[i].PointerToRelocations);
        printf("PointerToLinenumbers: %x\n", section_headers[i].PointerToLinenumbers);
        printf("NumberOfRelocations: %d\n", section_headers[i].NumberOfRelocations);
        printf("NumberOfLinenumbers: %d\n", section_headers[i].NumberOfLinenumbers);
        printf("Characteristics: %x\n", section_headers[i].Characteristics);

        if (section_headers[i].VirtualAddress <= import_directory_virtual_address && section_headers[i].VirtualAddress + section_headers[i].SizeOfRawData > import_directory_virtual_address)
            import_directory_section_header_index = i;
    }

    printf("\nImport Directory Section Header Name: %s\n", section_headers[import_directory_section_header_index].Name);

    uint64_t pointer_to_raw_data = (section_headers[import_directory_section_header_index].PointerToRawData);
    ImageImportDescriptor_t *image_import_descriptors = (ImageImportDescriptor_t *)(&binary_without_offset[pointer_to_raw_data + import_directory_virtual_address - section_headers[import_directory_section_header_index].VirtualAddress]);
    uint32_t number_of_image_import_descriptor = (import_directory_size / sizeof(ImageImportDescriptor_t)) - 1;
    uint32_t import_lookup_table_physical_address = 0;
    ImageImportByName_t *imported_by_name_function = NULL;

    printf("Import Directory Virtual Address: %x\n", import_directory_virtual_address);
    printf("Section Header Virtual Address: %x\n", section_headers[import_directory_section_header_index].VirtualAddress);
    printf("Number of Image Import Descriptor: %d\n", number_of_image_import_descriptor);

    for (size_t i = 0; i < number_of_image_import_descriptor; ++i) {
        printf("\nName: %s\n", (char *)(&binary_without_offset[pointer_to_raw_data + image_import_descriptors[i].Name - section_headers[import_directory_section_header_index].VirtualAddress]));
        printf("First Thunk: %x\n", image_import_descriptors[i].FirstThunk);
        printf("TimeDateStamp: %x\n", image_import_descriptors[i].TimeDateStamp);
        printf("Forwarder 1 Chain: %x\n", image_import_descriptors[i].Forwarder1Chain);
        printf("Name Address: %x\n", image_import_descriptors[i].Name);

        import_lookup_table_physical_address = pointer_to_raw_data + image_import_descriptors[i].FirstThunk - section_headers[import_directory_section_header_index].VirtualAddress;
        for (uint32_t j = import_lookup_table_physical_address; *(uint32_t *)&binary_without_offset[j]; j += 4) {
            if (*(uint32_t *)&binary_without_offset[j] & 0x80000000)
                printf("Ordinal Number: %x\n", *(uint32_t *)&binary_without_offset[j] & 0xFFFF);
            else {
                printf("Imported function name RVA: %x\n", *(uint32_t *)&binary_without_offset[j]);
                imported_by_name_function = (ImageImportByName_t *)&binary_without_offset[pointer_to_raw_data + *(uint32_t *)&binary_without_offset[j] - section_headers[import_directory_section_header_index].VirtualAddress];
                printf("Imported function name: %s\n", imported_by_name_function->Name);
            }
        }
    }

    for (size_t i = 0; i < coff_header->NumberOfSections; ++i) {
        printf("\nBytes of section %s:\n", section_headers[i].Name);
        size_t code_size = section_headers[i].SizeOfRawData;
        unsigned char *code = (unsigned char *)(&binary_without_offset[section_headers[i].PointerToRawData]);

        for (size_t j = 0; j < code_size; ++j) {
            printf("%02x ", code[j]);
            if ((j + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    }
}

static void display_optional_header64(const char *binary_without_offset, const char *binary, CoffHeader *coff_header)
{
    (void)binary_without_offset;
    OptionalHeader64 optional_header = *(OptionalHeader64 *)binary;
    printf("\n");
    printf("Magic: %x\n", optional_header.Magic);
    printf("MajorLinkerVersion: %d\n", optional_header.MajorLinkerVersion);
    printf("MinorLinkerVersion: %d\n", optional_header.MinorLinkerVersion);
    printf("SizeOfCode: %d\n", optional_header.SizeOfCode);
    printf("SizeOfInitializedData: %d\n", optional_header.SizeOfInitializedData);
    printf("SizeOfUninitializedData: %d\n", optional_header.SizeOfUninitializedData);
    printf("AddressOfEntryPoint: %x\n", optional_header.AddressOfEntryPoint);
    printf("BaseOfCode: %x\n", optional_header.BaseOfCode);
    printf("ImageBase: %lx\n", optional_header.ImageBase);
    printf("SectionAlignment: %d\n", optional_header.SectionAlignment);
    printf("FileAlignment: %d\n", optional_header.FileAlignment);
    printf("MajorOperatingSystemVersion: %d\n", optional_header.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: %d\n", optional_header.MinorOperatingSystemVersion);
    printf("MajorImageVersion: %d\n", optional_header.MajorImageVersion);
    printf("MinorImageVersion: %d\n", optional_header.MinorImageVersion);
    printf("MajorSubsystemVersion: %d\n", optional_header.MajorSubsystemVersion);
    printf("MinorSubsystemVersion: %d\n", optional_header.MinorSubsystemVersion);
    printf("Win32VersionValue: %x\n", optional_header.Win32VersionValue);
    printf("SizeOfImage: %d\n", optional_header.SizeOfImage);
    printf("SizeOfHeaders: %d\n", optional_header.SizeOfHeaders);
    printf("CheckSum: %x\n", optional_header.CheckSum);
    printf("Subsystem: %x\n", optional_header.Subsystem);
    printf("DllCharacteristics: %x\n", optional_header.DllCharacteristics);
    printf("SizeOfStackReserve: %ld\n", optional_header.SizeOfStackReserve);
    printf("SizeOfStackCommit: %ld\n", optional_header.SizeOfStackCommit);
    printf("SizeOfHeapReserve: %ld\n", optional_header.SizeOfHeapReserve);
    printf("SizeOfHeapCommit: %ld\n", optional_header.SizeOfHeapCommit);
    printf("LoaderFlags: %x\n", optional_header.LoaderFlags);
    printf("NumberOfRvaAndSizes: %d\n", optional_header.NumberOfRvaAndSizes);

    for (size_t i = 0; i < optional_header.NumberOfRvaAndSizes; ++i) {
        printf("-VirtualAddress: %x\n", optional_header.DataDirectory[i].VirtualAddress);
        printf("-Size: %d\n", optional_header.DataDirectory[i].Size);
    }

    SectionHeader_t *section_headers = (SectionHeader_t *)&binary[sizeof(OptionalHeader64)];

    for (size_t i = 0; i < coff_header->NumberOfSections; ++i) {
        printf("\nName: %s\n", section_headers[i].Name);
        printf("PhysicalAddress: %x\n", section_headers[i].Misc.PhysicalAddress);
        printf("VirtualAddress: %x\n", section_headers[i].VirtualAddress);
        printf("SizeOfRawData: %d\n", section_headers[i].SizeOfRawData);
        printf("PointerToRawData: %x\n", section_headers[i].PointerToRawData);
        printf("PointerToRelocations: %x\n", section_headers[i].PointerToRelocations);
        printf("PointerToLinenumbers: %x\n", section_headers[i].PointerToLinenumbers);
        printf("NumberOfRelocations: %d\n", section_headers[i].NumberOfRelocations);
        printf("NumberOfLinenumbers: %d\n", section_headers[i].NumberOfLinenumbers);
        printf("Characteristics: %x\n", section_headers[i].Characteristics);
    }

    for (size_t i = 0; i < coff_header->NumberOfSections; ++i) {
        printf("\nBytes of section %s:\n", section_headers[i].Name);
        size_t code_size = section_headers[i].SizeOfRawData;
        unsigned char *code = (unsigned char *)(binary + section_headers[i].PointerToRawData);

        for (size_t j = 0; j < code_size; ++j) {
            printf("%02x ", code[j]);
            if ((j + 1) % 16 == 0) {
                printf("\n");
            }
        }
        printf("\n");
    }
}
