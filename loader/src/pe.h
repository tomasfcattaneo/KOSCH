/* безликий */
#pragma once

#include "types.h"
#include <windows.h>

#define LX_MAX_SECTIONS 32
#define LX_MAX_IMPORTS  64
#define LX_MAX_RELOCS   1024

typedef struct
{
    char name[8];
    uint32_t va;
    uint32_t virt_size;
    uint32_t raw_offset;
    uint32_t raw_size;
    uint32_t characteristics;
} LxSection;

typedef struct
{
    uint32_t rva;
    uint16_t type;
} LxReloc;

typedef struct
{
    char dll[64];
    uint32_t iat_rva;
    uint32_t thunk_rva;
} LxImportDesc;

typedef struct
{
    uint64_t image_base;
    uint32_t image_size;
    uint32_t entry_rva;
    uint32_t cookie_rva;

    LxSection sections[LX_MAX_SECTIONS];
    uint32_t section_count;

    LxReloc relocs[LX_MAX_RELOCS];
    uint32_t reloc_count;

    LxImportDesc imports[LX_MAX_IMPORTS];
    uint32_t import_count;
} LxImage;

typedef struct
{
    VirtAddr base;
    uint32_t size;
    VirtAddr entry;
} MxImage;

Result Lx_Parse(const uint8_t *raw, size_t raw_size, LxImage *out);
