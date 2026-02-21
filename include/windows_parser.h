////////////////////////
//
//  Created: Sun Nov 09 2025
//  File: windows_parser.h
//
////////////////////////

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "kernel/term/commands.h"

#define CHARACTERISTICS_IMAGE_FILE_RELOCS_STRIPPED 0x0001 //Image doesn't contain base relocations. Must be loaded at ImageBase.
#define CHARACTERISTICS_IMAGE_FILE_EXECUTABLE_IMAGE 0x0002 //Image file is valid and can be run. Linker error otherwise.
#define CHARACTERISTICS_IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020 //Application can handle > 2GB addresses.
#define CHARACTERISTICS_IMAGE_FILE_IMAGE_FILE_32BIT_MACHINE 0x0100 //Machine is 32bit word architecture.
#define CHARACTERISTICS_IMAGE_FILE_DEBUG_STRIPPED 0x0200 //Debug information was removed.
#define CHARACTERISTICS_IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400 //If on removable media, must be loaded and then copied to swap.
#define CHARACTERISTICS_IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800 //If on network media, must be loaded and then copied to swap.
#define CHARACTERISTICS_IMAGE_FILE_SYSTEM 0x1000 //Is a system file, not a user program.
#define CHARACTERISTICS_IMAGE_FILE_DLL 0x2000 //Is a DLL. While considered executable, it cannot be run as is.
#define CHARACTERISTICS_IMAGE_FILE_UP_SYSTEM_ONLY 0x4000 //File should be on a uniprocessor machine.

typedef struct BinFileData BinFileData_t;
