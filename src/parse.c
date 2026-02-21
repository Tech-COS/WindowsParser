////////////////////////
//
//  Created: Mon Jun 24 2024
//  File: parse.c
//
////////////////////////

#include <stddef.h>
#include <stdint.h>
//#include <stdlib.h>
#include "kernel/lib/string.h"
#include "struct.h"
#include "windows_parser.h"

typedef int64_t ssize_t;

extern void cos_putchar(char character);
extern void cos_printf(const char *str, ...);
extern void cos_free(void *ptr);
extern void *cos_malloc(uint64_t size);

BinFileData_t *windows32_fill_bin_file_data(__attribute__((unused)) uint8_t *binary)
{
    return NULL;
}

static uint64_t get_number_of_64bit_entries(uint64_t *pointed_entry)
{
    uint64_t *temp = pointed_entry;

    do
    {
        temp = (uint64_t *)((uint64_t)temp + 8);
    } while (*temp);
    return ((uint64_t)temp - (uint64_t)pointed_entry) / 8;
}

static void windows64_fill_section_data(const BinFileData_t *bin_file_data, const CoffHeader *coff_header, const SectionHeader_t *section_headers)
{
    for (size_t i = 0; i < coff_header->NumberOfSections; ++i)
    {
        const BinFileSection_t section = {
            .size = section_headers[i].SizeOfRawData,
            .address = section_headers[i].VirtualAddress + bin_file_data->bin_load_address,
            .offset = section_headers[i].PointerToRawData
        };

        bin_file_data->sections[i] = section;
    }
}

char *strchr(const char *s, const int c)
{
    while (*s && *s != (char)c)
        s++;
    return (char *)s;
}

void putchar_until(const char *s, const int c)
{
    if (!s)
        return;
    while (*s && *s != (char)c)
        cos_putchar(*s);
}

BinFileData_t *windows64_fill_bin_file_data(uint8_t *binary)
{
    const uint16_t address = (binary[60] & 0xFF) | (binary[61] & 0xFF) << 8;
    const size_t offset = address + 4;
    const CoffHeader *coff_header = (CoffHeader *)(binary + offset);

    BinFileData_t *bin_file_data = (BinFileData_t *)cos_malloc(sizeof(BinFileData_t));
    if (!bin_file_data)
        return NULL;
    memset(bin_file_data, 0, sizeof(struct BinFileData));

    const OptionalHeader64 *optional_header = (OptionalHeader64 *)(binary + offset + sizeof(CoffHeader));
    const SectionHeader_t *section_headers = (SectionHeader_t *)(binary + offset + sizeof(OptionalHeader64) + sizeof(CoffHeader));

    bin_file_data->bin_load_address = optional_header->ImageBase;
    bin_file_data->entry_point = optional_header->AddressOfEntryPoint + bin_file_data->bin_load_address;
    bin_file_data->stack_size = optional_header->SizeOfStackReserve;
    bin_file_data->heap_size = optional_header->SizeOfHeapReserve;
    bin_file_data->number_of_sections = coff_header->NumberOfSections;
    bin_file_data->sections = cos_malloc(sizeof(BinFileSection_t) * (coff_header->NumberOfSections + 1));
    memset(bin_file_data->sections, 0, sizeof(BinFileSection_t) * (coff_header->NumberOfSections + 1));
    windows64_fill_section_data(bin_file_data, coff_header, section_headers);

    if (optional_header->DataDirectory[1].VirtualAddress && optional_header->DataDirectory[1].Size)
    {
        const uint32_t import_directory_virtual_address = optional_header->DataDirectory[1].VirtualAddress;
        const uint32_t import_directory_size = optional_header->DataDirectory[1].Size;
        uint32_t import_directory_section_header_index = 0;

        for (size_t i = 0; i < coff_header->NumberOfSections; ++i)
        {
            if (section_headers[i].VirtualAddress <= import_directory_virtual_address && section_headers[i].VirtualAddress + section_headers[i].SizeOfRawData > import_directory_virtual_address)
                import_directory_section_header_index = i;
        }

        const uint64_t pointer_to_raw_data = section_headers[import_directory_section_header_index].PointerToRawData;
        const ImageImportDescriptor_t *image_import_descriptors = (ImageImportDescriptor_t *)&binary[pointer_to_raw_data + import_directory_virtual_address - section_headers[import_directory_section_header_index].VirtualAddress];
        const uint64_t number_of_image_import_descriptor = import_directory_size / sizeof(ImageImportDescriptor_t) - 1;

        bin_file_data->imported_libraries = cos_malloc((number_of_image_import_descriptor + 1) * sizeof(struct BinFileLibrary));
        memset(bin_file_data->imported_libraries, 0, (number_of_image_import_descriptor + 1) * sizeof(struct BinFileLibrary));
        for (uint64_t i = 0; i < number_of_image_import_descriptor; ++i)
        {
            const uint64_t import_lookup_table_physical_address = pointer_to_raw_data + image_import_descriptors[i].FirstThunk - section_headers[import_directory_section_header_index].VirtualAddress;
            uint64_t *pointed_entry = (uint64_t *)((uint64_t)binary + import_lookup_table_physical_address);

            bin_file_data->imported_libraries[i].name = (char *)&binary[pointer_to_raw_data + image_import_descriptors[i].Name - section_headers[import_directory_section_header_index].VirtualAddress];
            bin_file_data->imported_libraries[i].first_thunk = image_import_descriptors[i].FirstThunk;
            bin_file_data->imported_libraries[i].required_functions = cos_malloc((get_number_of_64bit_entries(pointed_entry) + 1) * sizeof(struct BinFileFunction));

            for (uint64_t j = 0; *pointed_entry; ++j)
            {
                if (*pointed_entry & 0x8000000000000000)
                {
                    bin_file_data->imported_libraries[i].required_functions[j].hint_or_ordinal = *pointed_entry & 0xFFFFF;
                } else {
                    ImageImportByName_t *imported_by_name_function = (ImageImportByName_t *)&binary[pointer_to_raw_data + *pointed_entry - section_headers[import_directory_section_header_index].VirtualAddress];
                    bin_file_data->imported_libraries[i].required_functions[j].name = imported_by_name_function->Name;
                    bin_file_data->imported_libraries[i].required_functions[j].hint_or_ordinal = imported_by_name_function->Hint;
                }
                pointed_entry = (uint64_t *)((uint64_t)pointed_entry + 8);
            }
        }
    }

    if ((coff_header->Characteristics & CHARACTERISTICS_IMAGE_FILE_DLL) && optional_header->DataDirectory[0].VirtualAddress && optional_header->DataDirectory[0].Size)
    {
        const uint32_t export_directory_virtual_address = optional_header->DataDirectory[0].VirtualAddress;
        uint32_t export_directory_section_header_index = 0;

        for (size_t i = 0; i < coff_header->NumberOfSections; ++i)
        {
            if (section_headers[i].VirtualAddress <= export_directory_virtual_address && section_headers[i].VirtualAddress + section_headers[i].SizeOfRawData > export_directory_virtual_address)
                export_directory_section_header_index = i;
        }

        const int64_t pointer_to_raw_data = section_headers[export_directory_section_header_index].PointerToRawData;
        const int64_t export_offset = pointer_to_raw_data - section_headers[export_directory_section_header_index].VirtualAddress;
        const ImageExportDescriptor_t *image_export_descriptor = (ImageExportDescriptor_t *)&binary[export_directory_virtual_address + export_offset];
        const ImageExportAddressTableEntry_t *export_address_table = (ImageExportAddressTableEntry_t *)&binary[image_export_descriptor->ExportAddressTableRVA + export_offset];

        //During loading, an unbiased ordinal or a hint is used as an index into the export_address_table.
        //If the function was exported by name and the hint failed to retrieve the correct export address, the name_pointer_table must be binary searched to find the index of the name in the table.
        //This index can then be used to retrieve the correct ordinal inside the ordinal_table as the name_pointer_table and the ordinal_table share the same indexes according to the specification of the WinPE format.
        //If the exported function RVA is a forwarder RVA, the exports of the referenced DLL must be searched according to the prior algorithm (if it was forwarded by name, a binary search is required).
        for (uint32_t i = 0; i < image_export_descriptor->NumberOfFunctions; ++i)
        {
            if (section_headers[export_directory_section_header_index].VirtualAddress <= export_address_table[i].RVA.ForwarderRVA && section_headers[export_directory_section_header_index].VirtualAddress + section_headers[export_directory_section_header_index].SizeOfRawData > export_address_table[i].RVA.ForwarderRVA)
            {
                const char *forwarded_function = (char *)&binary[export_address_table[i].RVA.ForwarderRVA + export_offset];
                char *name_or_ordinal = strchr(forwarded_function, '.');
                if (name_or_ordinal[0] != '\0')
                {
                    cos_printf("Forwarded function: %s\n", name_or_ordinal + 1);
                    cos_printf("DLL Name: ");
                    putchar_until(forwarded_function, '.');
                } else {
                    name_or_ordinal = strchr(forwarded_function, '#');
                    cos_printf("Forwarded Ordinal: %s\n", name_or_ordinal + 1);
                    cos_printf("DLL Name: ");
                    putchar_until(forwarded_function, '#');
                }
                cos_printf("\n");
                continue;
            }
            cos_printf("Exported RVA: %x\n", export_address_table[i].RVA.ExportRVA);
            cos_printf("DLL Name: %s\n", (char *)&binary[image_export_descriptor->NameRVA + export_offset]);
        }
    }

    return bin_file_data;
}

BinFileData_t *(*check_windows_type(uint8_t *binary))(uint8_t *)
{
    const uint16_t address = (binary[60] & 0xFF) | (binary[61] & 0xFF) << 8;
    const size_t current_offset = address + 4;

    if (cos_strcmp((char *)&binary[address], "PE\0\0"))
        return NULL;

    const CoffHeader *coff_header = (CoffHeader *)&binary[current_offset];

    //The specification states that DLLs and executable Images have this header.
    if (!coff_header->SizeOfOptionalHeader)
        return NULL;

    if (coff_header->Machine == (uint16_t)0x8664)
        return windows64_fill_bin_file_data;
    else if (coff_header->Machine == (uint16_t)0x014C)
        return windows32_fill_bin_file_data;
    else
        return NULL;
}
