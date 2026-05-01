/* безликий */
#include "globals.h"

volatile LONG g_Initialized = 0;

NX_BRIDGE g_CommsBootstrap = {.sentinel1      = NX_SENTINEL1,
                              .sentinel2      = NX_SENTINEL2,
                              .cmd_buffer_va  = 0,
                              .cmd_buffer_pid = 0,
                              .flags          = 0,
                              .dispatch_va    = 0};

PVOID g_NtosBase  = NULL;
PVOID g_ImageBase = NULL;
ULONG g_ImageSize = 0;
