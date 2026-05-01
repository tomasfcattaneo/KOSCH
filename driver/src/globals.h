/* безликий */
#pragma once

#include <ntifs.h>
#include "offsets.h"

#define NX_SEED        0xA7E4B2D9u
#define NX_MAGIC       (NX_SEED ^ 0x3D8F1A7Eu)
#define NX_SENTINEL1   0xD3A9F07E2B6C8154ULL
#define NX_SENTINEL2   0x8154D3A9F07E2B6CULL
#define POOL_TAG_COMMS (NX_SEED ^ 0x12345678u)

typedef struct
{
    UINT64 sentinel1;
    UINT64 sentinel2;
    UINT64 cmd_buffer_va;
    UINT32 cmd_buffer_pid;
    UINT32 flags;
    UINT64 dispatch_va;
} NX_BRIDGE;

extern volatile LONG g_Initialized;
extern NX_BRIDGE g_CommsBootstrap;
extern PVOID g_NtosBase;
extern PVOID g_ImageBase;
extern ULONG g_ImageSize;
