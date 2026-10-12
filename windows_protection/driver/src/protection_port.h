#ifndef STAI_PROTECTION_PORT_H
#define STAI_PROTECTION_PORT_H

#include <fltKernel.h>
#include "driver.h"

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath
);

VOID StaiCompleteOutstandingRequest(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalStatus
);

VOID StaiCleanupOutstandingRequests(VOID);

NTSTATUS StaiWaitForServiceReply(
    _In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest,
    _In_ LONGLONG TimeoutMs
);

#endif