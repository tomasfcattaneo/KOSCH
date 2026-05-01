/* безликий */
#include "resolve.h"
#include "peb.h"
#include "crypt.h"
#include <string.h>

static VirtAddr find_module_base(SxInfo *ki, const char *dll)
{
    for (uint32_t i = 0; i < ki->module_count; i++) {
        if (_stricmp(ki->modules[i].name, dll) == 0) return ki->modules[i].base;
    }
    return 0;
}

static char    g_cached_dll[64];
static void   *g_cached_image;

static void *get_cached_image(const char *dll)
{
    if (g_cached_image && _stricmp(g_cached_dll, dll) == 0)
        return g_cached_image;

    if (g_cached_image) {
        Peb_UnloadImage(g_cached_image);
        g_cached_image = NULL;
    }

    wchar_t wide_dll[64];
    for (int i = 0; dll[i] && i < 63; i++) {
        wide_dll[i]     = (wchar_t)dll[i];
        wide_dll[i + 1] = 0;
    }

    g_cached_image = Peb_LoadImage(wide_dll);
    if (g_cached_image)
        strncpy(g_cached_dll, dll, sizeof(g_cached_dll) - 1);
    return g_cached_image;
}

Result Rx_Import(SxInfo *ki, const char *dll, const char *func_name,
                 VirtAddr *out)
{
    VirtAddr module_base = find_module_base(ki, dll);
    if (!module_base) return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("module not found"));

    void *local = get_cached_image(dll);
    if (!local) return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("image load failed"));

    void *proc = Peb_FindExport(local, fnv1a(func_name));
    if (!proc) return ERR(STATUS_ERR_IMPORT_RESOLVE, EMSG("export not found"));

    uint32_t rva = (uint32_t)((uintptr_t)proc - (uintptr_t)local);
    *out = module_base + rva;
    return OK_VOID;
}
