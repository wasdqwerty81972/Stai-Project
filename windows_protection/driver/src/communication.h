#ifndef STAI_COMMUNICATION_H
#define STAI_COMMUNICATION_H

#include <fltKernel.h>
#include "driver.h"

NTSTATUS StaiQueueInspection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath
);

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ ULONGLONG ProcessId,
    _In_ ULONGLONG ThreadId,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN ShouldBlock
);

VOID StaiSendCompletionToService(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalIoStatus
);

#endif
