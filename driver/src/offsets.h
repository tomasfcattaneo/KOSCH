/* безликий */
#pragma once

#include <ntifs.h>

typedef struct
{
    ULONG eprocess_active_links;
    ULONG eprocess_image_name;
    ULONG eprocess_pid;
    ULONG eprocess_cr3;
    ULONG eprocess_peb;
} KernelOffsets;

extern KernelOffsets g_Offsets;

NTSTATUS Sx_ResolveOffsets(void);
