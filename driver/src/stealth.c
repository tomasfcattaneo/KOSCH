/* безликий */
#include "stealth.h"
#include "globals.h"
#include <ntimage.h>

void Ex_ZeroHeaders(void)
{
    if (!g_ImageBase || !g_ImageSize) return;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)g_ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)((UCHAR *)g_ImageBase + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;

    ULONG header_size = nt->OptionalHeader.SizeOfHeaders;
    if (header_size > g_ImageSize) return;

    IMAGE_DATA_DIRECTORY *imp =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    IMAGE_DATA_DIRECTORY *dbg =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];

    ULONG imp_rva  = imp->VirtualAddress;
    ULONG imp_size = imp->Size;
    ULONG dbg_rva  = dbg->VirtualAddress;
    ULONG dbg_size = dbg->Size;

    RtlZeroMemory(g_ImageBase, header_size);

    if (imp_rva && imp_size && imp_rva + imp_size <= g_ImageSize)
        RtlZeroMemory((UCHAR *)g_ImageBase + imp_rva, imp_size);

    if (dbg_rva && dbg_size && dbg_rva + dbg_size <= g_ImageSize)
        RtlZeroMemory((UCHAR *)g_ImageBase + dbg_rva, dbg_size);
}
