#include "protection_port.h"

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath
) {
    NTSTATUS status;
    PSTAI_REQUEST request;
    ULONG requestSize;
    ULONG pathSize;
    LARGE_INTEGER timeout;

    if (!g_FilterContext.ServiceConnected || !g_FilterContext.ClientPort) {
        return STATUS_PORT_DISCONNECTED;
    }

    pathSize = FilePath->Length;
    if (pathSize > STAI_MAX_PATH_UTF16_CHARS * sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }

    requestSize = sizeof(STAI_REQUEST) + pathSize;
    if (requestSize > STAI_MAX_PAYLOAD_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    request = ExAllocatePoolWithTag(NonPagedPool, requestSize, STAI_TAG);
    if (!request) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(request, requestSize);
    request->size = requestSize;
    request->version = STAI_PROTOCOL_VERSION;
    request->request_id = RequestId;
    request->operation = Operation;
    request->path_len = pathSize / sizeof(WCHAR);
    RtlCopyMemory(request->path, FilePath->Buffer, pathSize);

    timeout.QuadPart = -10000000LL * 5; // 5 seconds

    status = FltSendMessage(
        g_FilterContext.FilterHandle,
        &g_FilterContext.ClientPort,
        request,
        requestSize,
        NULL,
        0,
        &timeout
    );

    ExFreePoolWithTag(request, STAI_TAG);

    return status;
}

VOID StaiCompleteOutstandingRequest(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalStatus
) {
    PSTAI_OUTSTANDING_REQUEST request;

    request = StaiFindOutstandingRequest(RequestId);
    if (!request) {
        return;
    }

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    request->FinalStatus = FinalStatus;
    request->Completed = TRUE;
    KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
}

VOID StaiCleanupOutstandingRequests(VOID) {
    PLIST_ENTRY entry;
    PSTAI_OUTSTANDING_REQUEST request;

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    while (!IsListEmpty(&g_FilterContext.OutstandingRequests)) {
        entry = RemoveHeadList(&g_FilterContext.OutstandingRequests);
        request = CONTAINING_RECORD(entry, STAI_OUTSTANDING_REQUEST, ListEntry);
        request->FinalStatus = STATUS_CANCELLED;
        request->Completed = TRUE;
        KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
    }
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
}

NTSTATUS StaiWaitForServiceReply(
    _In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest,
    _In_ LONGLONG TimeoutMs
) {
    LARGE_INTEGER timeout;
    NTSTATUS status;

    timeout.QuadPart = -10000LL * TimeoutMs;

    status = KeWaitForSingleObject(
        &OutstandingRequest->CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        &timeout
    );

    if (status == STATUS_TIMEOUT) {
        return STATUS_TIMEOUT;
    }

    return OutstandingRequest->FinalStatus;
}