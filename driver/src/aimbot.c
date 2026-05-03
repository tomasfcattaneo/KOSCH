/* безликий */
#include "aimbot.h"
#include "mouse.h"
#include "memory.h"
#include "sysinfo.h"
#include <ntstrsafe.h>

// Global variables
static BOOLEAN g_AimbotRunning = FALSE;
static HANDLE g_AimbotThread = NULL;
static KEVENT g_StopEvent;

// CS 1.6 specific structures and offsets (replace with actual values)
#define MAX_ENTITIES 32
#define dwEntityList 0x4A4D1C  // Example offset
#define m_entitySize 0x10C     // Example
#define m_entityOrigin 0x4      // Example
#define dwViewMatrix 0x4A4D1C  // Example

typedef struct {
    float x, y, z;
} Vector3;

typedef struct {
    float x, y;
} Vector2;

typedef float view_matrix_t[4][4];

typedef struct {
    Vector3 origin;
    int health;
    int team;
} player_t;

typedef struct {
    player_t players[MAX_ENTITIES];
    view_matrix_t view_matrix;
} game_state_t;

// Function to read view matrix
NTSTATUS ReadViewMatrix(HANDLE pid, UINT64 hw_base, view_matrix_t *matrix) {
    return Vx_Read(pid, hw_base + dwViewMatrix, matrix, sizeof(view_matrix_t));
}

// Function to read entity origin
NTSTATUS ReadEntityOrigin(HANDLE pid, UINT64 hw_base, int i, Vector3 *origin) {
    return Vx_Read(pid, hw_base + dwEntityList + (i * m_entitySize) + m_entityOrigin, origin, sizeof(Vector3));
}

// Simplified: populate state
NTSTATUS ReadGameEntities(HANDLE pid, UINT64 hw_base, game_state_t *state) {
    NTSTATUS status = ReadViewMatrix(pid, hw_base, &state->view_matrix);
    if (!NT_SUCCESS(status)) return status;

    for (int i = 0; i < MAX_ENTITIES; i++) {
        status = ReadEntityOrigin(pid, hw_base, i, &state->players[i].origin);
        if (!NT_SUCCESS(status)) continue;
        // Add health/team reads if needed
        state->players[i].health = 100; // Placeholder
        state->players[i].team = 1;     // Placeholder
    }
    return STATUS_SUCCESS;
}

// Calculate best target (closest to center)
int CalculateTarget(game_state_t *state, Vector2 screen_center) {
    int best = -1;
    float min_dist = FLT_MAX;
    for (int i = 0; i < MAX_ENTITIES; i++) {
        if (state->players[i].health <= 0 || state->players[i].team == 1) continue; // Own team

        Vector2 screen_pos;
        // World to screen conversion (simplified)
        // Use w2s function from Zodiak
        // For now, placeholder
        screen_pos.x = state->players[i].origin.x * 10; // Placeholder
        screen_pos.y = state->players[i].origin.y * 10;

        float dist = sqrt((screen_pos.x - screen_center.x) * (screen_pos.x - screen_center.x) +
                          (screen_pos.y - screen_center.y) * (screen_pos.y - screen_center.y));
        if (dist < min_dist) {
            min_dist = dist;
            best = i;
        }
    }
    return best;
}

// Main aimbot thread
VOID AimbotThreadRoutine(PVOID context) {
    UNREFERENCED_PARAMETER(context);

    // Wait for hl.exe
    HANDLE hl_pid = 0;
    while (g_AimbotRunning) {
        hl_pid = Sx_FindPidByName(L"hl.exe");
        if (hl_pid) break;
        LARGE_INTEGER delay = { .QuadPart = -10000000 }; // 1s
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    if (!hl_pid) return;

    // Get hw.dll base
    UINT64 hw_base = 0;
    Vx_GetModuleBase(hl_pid, L"hw.dll", &hw_base);
    if (!hw_base) return;

    PEPROCESS hl_proc = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(hl_pid, &hl_proc);
    if (!NT_SUCCESS(status)) return;

    KAPC_STATE apc;
    KeStackAttachProcess(hl_proc, &apc);

    Vector2 screen_center = { 800, 600 }; // Placeholder screen size / 2

    while (g_AimbotRunning) {
        game_state_t state;
        if (NT_SUCCESS(ReadGameEntities(hl_pid, hw_base, &state))) {
            int target = CalculateTarget(&state, screen_center);
            if (target >= 0) {
                // Simple aim: move towards target screen pos
                Vector2 target_screen;
                // Placeholder w2s
                target_screen.x = state.players[target].origin.x * 10;
                target_screen.y = state.players[target].origin.y * 10;
                LONG delta_x = (LONG)(target_screen.x - screen_center.x);
                LONG delta_y = (LONG)(target_screen.y - screen_center.y);
                MouseMove(delta_x / 10, delta_y / 10); // Smooth
            }
        }
        LARGE_INTEGER delay = { .QuadPart = -500000 }; // 50ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    KeUnstackDetachProcess(&apc);
    ObDereferenceObject(hl_proc);
}

NTSTATUS AimbotInit(VOID) {
    if (g_AimbotRunning) return STATUS_ALREADY_INITIALIZED;

    NTSTATUS status = MouseInit();
    if (!NT_SUCCESS(status)) return status;

    g_AimbotRunning = TRUE;
    KeInitializeEvent(&g_StopEvent, NotificationEvent, FALSE);

    OBJECT_ATTRIBUTES oa = { sizeof(oa) };
    status = PsCreateSystemThread(&g_AimbotThread, THREAD_ALL_ACCESS, &oa, NULL, NULL,
                                  AimbotThreadRoutine, NULL);
    return status;
}

NTSTATUS AimbotStop(VOID) {
    if (!g_AimbotRunning) return STATUS_INVALID_DEVICE_STATE;

    g_AimbotRunning = FALSE;
    if (g_AimbotThread) {
        KeWaitForSingleObject(g_AimbotThread, Executive, KernelMode, FALSE, NULL);
        ZwClose(g_AimbotThread);
        g_AimbotThread = NULL;
    }
    return STATUS_SUCCESS;
}