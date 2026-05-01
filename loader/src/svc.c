/* безликий */
#include "svc.h"
#include "crypt.h"
#include <string.h>

Result Io_CreateAndStart(IoCtx *ctx, const char *name, const char *sys_path)
{
    memset(ctx, 0, sizeof(*ctx));

    ctx->scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!ctx->scm) return ERR(STATUS_ERR_SERVICE_CREATE, EMSG("SCM open failed"));

    SC_HANDLE existing = OpenServiceA(ctx->scm, name, SERVICE_ALL_ACCESS);
    if (existing) {
        SERVICE_STATUS ss;
        ControlService(existing, SERVICE_CONTROL_STOP, &ss);
        DeleteService(existing);
        CloseServiceHandle(existing);
        Sleep(100);
    }

    ctx->service = CreateServiceA(ctx->scm, name, name, SERVICE_ALL_ACCESS,
                                  SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                  SERVICE_ERROR_NORMAL, sys_path, NULL, NULL, NULL, NULL,
                                  NULL);

    if (!ctx->service) {
        CloseServiceHandle(ctx->scm);
        return ERR(STATUS_ERR_SERVICE_CREATE, EMSG("service create failed"));
    }

    if (!StartServiceA(ctx->service, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            DeleteService(ctx->service);
            CloseServiceHandle(ctx->service);
            CloseServiceHandle(ctx->scm);
            return ERR(STATUS_ERR_SERVICE_START, EMSG("service start failed"));
        }
    }

    return OK_VOID;
}

Result Io_StopAndDelete(IoCtx *ctx)
{
    if (ctx->service) {
        SERVICE_STATUS ss;
        ControlService(ctx->service, SERVICE_CONTROL_STOP, &ss);
        DeleteService(ctx->service);
        CloseServiceHandle(ctx->service);
        ctx->service = NULL;
    }
    if (ctx->scm) {
        CloseServiceHandle(ctx->scm);
        ctx->scm = NULL;
    }
    return OK_VOID;
}
