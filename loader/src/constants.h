/* безликий */
#pragma once

#include <stdint.h>
#include <windows.h>

#define NX_SEED      0xA7E4B2D9u
#define NX_MAGIC     (NX_SEED ^ 0x3D8F1A7Eu)
#define NX_SENTINEL1 0xD3A9F07E2B6C8154ULL
#define NX_SENTINEL2 0x8154D3A9F07E2B6CULL

#define XOR_KEY_VAL  0xA3B7C1D9E5F20486ULL

#define DX_BUF_SIZE 4096

enum
{
    CMD_PING = 0,
    CMD_READ_MEMORY,
    CMD_WRITE_MEMORY,
    CMD_GET_MODULE_BASE,
    CMD_GET_PEB,
    CMD_HIDE_PROCESS,
    CMD_UNHIDE_PROCESS,
    CMD_HIDE_DRIVER,
    CMD_TRANSLATE_VA,
    CMD_QUERY_STATE,
    CMD_CREATE_AIMBOT_THREAD,
    CMD_STOP_AIMBOT_THREAD,
    CMD_MAX
};

typedef struct
{
    uint32_t magic;
    uint32_t cmd;
    uint32_t size;
} DX_HDR;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    uint64_t address;
    uint32_t length;
} DX_READ;

typedef struct
{
    DX_HDR hdr;
    uint32_t pid;
    WCHAR module_name[64];
} DX_MODBASE;

typedef struct
{
    uint32_t magic;
    uint32_t status;
    uint64_t value;
    uint8_t data[];
} DX_RSP;
