/* безликий */
#include "peb.h"
#include "crypt.h"
#include <intrin.h>

typedef struct
{
    uint16_t Length;
    uint16_t MaximumLength;
    wchar_t *Buffer;
} USTR;

typedef struct
{
    uint32_t Length;
    uint8_t Initialized;
    void *SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} LDR_DATA;

typedef struct
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void *DllBase;
    void *EntryPoint;
    uint32_t SizeOfImage;
    uint32_t _pad;
    USTR FullDllName;
    USTR BaseDllName;
} LDR_ENTRY;

typedef struct
{
    uint8_t Reserved1[2];
    uint8_t BeingDebugged;
    uint8_t Reserved2[1];
    void *Reserved3[2];
    LDR_DATA *Ldr;
} PEB_S;

static uint32_t hash_unicode_lower(const wchar_t *s, uint16_t byte_len)
{
    uint32_t h          = 0x811C9DC5u;
    uint32_t char_count = byte_len / sizeof(wchar_t);
    for (uint32_t i = 0; i < char_count; i++) {
        wchar_t c = s[i];
        if (c >= L'A' && c <= L'Z') c += 32;
        h ^= (uint8_t)(c & 0xFF);
        h *= 0x01000193u;
        h ^= (uint8_t)((c >> 8) & 0xFF);
        h *= 0x01000193u;
    }
    return h;
}

void *Peb_FindModule(uint32_t name_hash)
{
#ifdef _M_X64
    PEB_S *peb = (PEB_S *)__readgsqword(0x60);
#else
    PEB_S *peb = (PEB_S *)__readfsdword(0x30);
#endif
    LIST_ENTRY *head = &peb->Ldr->InLoadOrderModuleList;
    LIST_ENTRY *cur  = head->Flink;

    while (cur != head) {
        LDR_ENTRY *entry = (LDR_ENTRY *)cur;
        if (entry->BaseDllName.Length > 0) {
            uint32_t h = hash_unicode_lower(entry->BaseDllName.Buffer,
                                            entry->BaseDllName.Length);
            if (h == name_hash) return entry->DllBase;
        }
        cur = cur->Flink;
    }
    return NULL;
}

void *Peb_FindExport(void *module_base, uint32_t func_hash)
{
    uint8_t *base         = (uint8_t *)module_base;
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != 0x5A4D) return NULL;

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY *exp_dir =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir->VirtualAddress == 0 || exp_dir->Size == 0) return NULL;

    IMAGE_EXPORT_DIRECTORY *exports =
        (IMAGE_EXPORT_DIRECTORY *)(base + exp_dir->VirtualAddress);
    uint32_t *names    = (uint32_t *)(base + exports->AddressOfNames);
    uint16_t *ordinals = (uint16_t *)(base + exports->AddressOfNameOrdinals);
    uint32_t *funcs    = (uint32_t *)(base + exports->AddressOfFunctions);

    uint32_t exp_start = exp_dir->VirtualAddress;
    uint32_t exp_end   = exp_start + exp_dir->Size;

    for (uint32_t i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)(base + names[i]);
        if (fnv1a(name) != func_hash) continue;

        uint32_t rva = funcs[ordinals[i]];
        if (rva >= exp_start && rva < exp_end) continue;

        return base + rva;
    }
    return NULL;
}

void *Peb_LoadImage(const wchar_t *path)
{
    typedef long(__stdcall * PLdrLoadDll)(wchar_t *, uint32_t *, USTR *, void **);
    void *ntdll = Peb_FindModule(H_ntdll_dll);
    if (!ntdll) return NULL;
    PLdrLoadDll ldr = (PLdrLoadDll)Peb_FindExport(ntdll, H_LdrLoadDll);
    if (!ldr) return NULL;

    USTR us;
    us.Length        = (uint16_t)(wcslen(path) * sizeof(wchar_t));
    us.MaximumLength = us.Length + sizeof(wchar_t);
    us.Buffer        = (wchar_t *)path;

    uint32_t flags = 0x02;
    void *base     = NULL;
    ldr(NULL, &flags, &us, &base);
    return base;
}

void Peb_UnloadImage(void *base)
{
    typedef long(__stdcall * PLdrUnloadDll)(void *);
    void *ntdll = Peb_FindModule(H_ntdll_dll);
    if (!ntdll) return;
    PLdrUnloadDll unload = (PLdrUnloadDll)Peb_FindExport(ntdll, H_LdrUnloadDll);
    if (unload) unload(base);
}
