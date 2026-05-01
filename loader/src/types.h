/* безликий */
#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef uint64_t VirtAddr;
typedef uint64_t PhysAddr;

typedef enum
{
    STATUS_OK = 0,
    STATUS_ERR_PRIVILEGE,
    STATUS_ERR_HYPERVISOR,
    STATUS_ERR_DRIVER_DROP,
    STATUS_ERR_SERVICE_CREATE,
    STATUS_ERR_SERVICE_START,
    STATUS_ERR_DEVICE_OPEN,
    STATUS_ERR_IOCTL_FAILED,
    STATUS_ERR_VIRT_TO_PHYS,
    STATUS_ERR_ALLOC_FAILED,
    STATUS_ERR_NTOS_NOT_FOUND,
    STATUS_ERR_GATE_INSTALL,
    STATUS_ERR_GATE_CALL,
    STATUS_ERR_PE_INVALID,
    STATUS_ERR_IMPORT_RESOLVE,
    STATUS_ERR_BOOTSTRAP_NOT_FOUND,
    STATUS_ERR_CLEANUP,
} StatusCode;

typedef struct
{
    StatusCode code;
    uint64_t value;
    const char *msg;
} Result;

#define OK_VAL(v) ((Result){.code = STATUS_OK, .value = (uint64_t)(v), .msg = NULL})
#define OK_VOID   ((Result){.code = STATUS_OK, .value = 0, .msg = NULL})
#define ERR(c, m) ((Result){.code = (c), .value = 0, .msg = (m)})
#define IS_OK(r)  ((r).code == STATUS_OK)
#define IS_ERR(r) ((r).code != STATUS_OK)

#define TRY(expr)                  \
    do {                           \
        Result _r = (expr);        \
        if (IS_ERR(_r)) return _r; \
    } while (0)
