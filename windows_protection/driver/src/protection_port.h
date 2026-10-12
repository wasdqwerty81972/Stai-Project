#ifndef STAI_PROTECTION_PORT_H
#define STAI_PROTECTION_PORT_H

#include <fltKernel.h>
#include "driver.h"

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN ShouldBlock
);

VOID StaiSendCompletionToService(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalIoStatus
);

#endif
