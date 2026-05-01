/* безликий */
#pragma once

#include <stdint.h>

#define XS_KEY 0x4Bu

static inline void xs_dec(char *out, const char *enc, uint32_t len)
{
    for (uint32_t i = 0; i < len; i++)
        out[i] = enc[i] ^ XS_KEY;
    out[len] = 0;
}

static inline void xs_dec_w(wchar_t *out, const uint8_t *enc, uint32_t char_count)
{
    for (uint32_t i = 0; i < char_count; i++)
        out[i] = (wchar_t)((enc[i * 2] ^ XS_KEY) | ((enc[i * 2 + 1] ^ XS_KEY) << 8));
    out[char_count] = 0;
}

static inline uint32_t fnv1a(const char *s)
{
    uint32_t h = 0x811C9DC5u;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 0x01000193u;
    }
    return h;
}

#define H_NtClose                  0x6B372C05u
#define H_NtQuerySystemInformation 0x7A43974Au
#define H_RtlAdjustPrivilege       0x33F3DF29u
#define H_PsGetCurrentThread       0xD1CCBF41u
#define H_MmUnloadSystemImage      0x4A18C56Au
#define H_LdrLoadDll               0x7B566B5Fu
#define H_LdrUnloadDll             0x16EA992Au

#define H_CreateEventW             0xE3D2BB40u
#define H_CloseHandle              0xFABA0065u

#define H_ntdll_dll                0x1CDE56F9u
#define H_kernel32_dll             0xC705800Du

#ifdef KOSHCHEI_RELEASE
#define EMSG(s) NULL
#else
#define EMSG(s) (s)
#endif
