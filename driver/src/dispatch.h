/* безликий */
#pragma once

#include <ntifs.h>

#pragma warning(push)
#pragma warning(disable : 4200)

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
    UINT32 magic;
    UINT32 cmd;
    UINT32 size;
} DX_HDR;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
    UINT64 address;
    UINT32 length;
} DX_READ;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
    UINT64 address;
    UINT32 length;
    UCHAR data[];
} DX_WRITE;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
    WCHAR module_name[64];
} DX_MODBASE;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
} DX_PEB;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
} DX_HIDE;

typedef struct
{
    DX_HDR hdr;
    UINT32 pid;
    UINT64 address;
} DX_XLATE;

typedef struct
{
    UINT32 magic;
    UINT32 status;
    UINT64 value;
    UCHAR data[];
} DX_RSP;

#pragma warning(pop)

NTSTATUS Dx_Route(PVOID buffer, ULONG size);
