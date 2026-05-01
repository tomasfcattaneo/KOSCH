/* безликий */
#pragma once

#include <windows.h>
#include "types.h"

typedef struct
{
    SC_HANDLE scm;
    SC_HANDLE service;
} IoCtx;

Result Io_CreateAndStart(IoCtx *ctx, const char *name, const char *sys_path);
Result Io_StopAndDelete(IoCtx *ctx);
