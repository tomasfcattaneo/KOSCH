/* безликий - Adapted from Zodiak */
#pragma once

#include <ntifs.h>

typedef struct _MOUSE_INPUT_DATA {
    USHORT UnitId;
    USHORT Flags;
    union {
        ULONG Buttons;
        struct {
            USHORT ButtonFlags;
            USHORT ButtonData;
        };
    };
    ULONG  RawButtons;
    LONG   LastX;
    LONG   LastY;
    ULONG  ExtraInformation;
} MOUSE_INPUT_DATA, * PMOUSE_INPUT_DATA;

typedef VOID (*MouseClassServiceCallbackFn)(
    PDEVICE_OBJECT DeviceObject,
    PMOUSE_INPUT_DATA InputDataStart,
    PMOUSE_INPUT_DATA InputDataEnd,
    PULONG InputDataConsumed
);

typedef struct _MOUSE_OBJECT {
    PDEVICE_OBJECT mouse_device;
    MouseClassServiceCallbackFn service_callback;
    BOOLEAN use_mouse;
} MOUSE_OBJECT, * PMOUSE_OBJECT;

extern MOUSE_OBJECT gMouseObject;

NTSTATUS MouseInit(VOID);
VOID MouseMove(LONG delta_x, LONG delta_y);