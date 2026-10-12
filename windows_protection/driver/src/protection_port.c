#include "protection_port.h"

#define STAI_REQUEST_TIMEOUT_MS 5000LL
#define STAI_MAX_OUTSTANDING_REQUESTS 32L
#define STAI_REPLY_STRING_MAX_BYTES \
    ((STAI_MAX_RULE_ID_UTF16_CHARS + STAI_MAX_RULE_VERSION_UTF16_CHARS) * sizeof(uint16_t))
#define STAI_REPLY_DATA_MAX_BYTES (STAI_REPLY_HEADER_SIZE + STAI_REPLY_STRING_MAX_BYTES)

typedef struct _STAI_KERNEL_REPLY_BUFFER {
    FILTER_REPLY_HEADER Header;
    UCHAR Payload[STAI_REPLY_DATA_MAX_BYTES];
} STAI_KERNEL_REPLY_BUFFER, *PSTAI_KERNEL_REPLY_BUFFER;

static BOOLEAN StaiAcquireClientPort(_Out_ PFLT_PORT *ClientPort) {
    BOOLEAN acquired = FALSE;

    *ClientPort = NULL;
    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    if (!g_FilterContext.PendingShutdown &&
        g_FilterContext.ServiceConnected &&
        g_FilterContext.ClientPort &&
        ExAcquireRundownProtection(&g_FilterContext.ClientPortRundown)) {
        *ClientPort = g_FilterContext.ClientPort;
        acquired = TRUE;
    }
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
    return acquired;
}

static VOID StaiReleaseClientPort(VOID) {
    ExReleaseRundownProtection(&g_FilterContext.ClientPortRundown);
}

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN ShouldBlock
) {
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    PSTAI_REQUEST request = NULL;
    PSTAI_KERNEL_REPLY_BUFFER replyBuffer = NULL;
    ULONG requestSize;
    ULONG pathSize;
    ULONG replyBufferSize;
    ULONG replyDataOffset;
    ULONG replyLength;
    LARGE_INTEGER timeout;
    PSTAI_REPLY reply;
    BOOLEAN portAcquired = FALSE;

    *ShouldBlock = FALSE;
    if (!FilePath || !FilePath->Buffer || RequestId == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (InterlockedIncrement(&g_FilterContext.OutstandingRequestCount) >
        STAI_MAX_OUTSTANDING_REQUESTS) {
        InterlockedDecrement(&g_FilterContext.OutstandingRequestCount);
        return STATUS_QUOTA_EXCEEDED;
    }

    pathSize = FilePath->Length;
    if ((pathSize % sizeof(WCHAR)) != 0 ||
        pathSize > STAI_MAX_PATH_UTF16_CHARS * sizeof(WCHAR)) {
        status = STATUS_NAME_TOO_LONG;
        goto Cleanup;
    }
    requestSize = STAI_REQUEST_HEADER_SIZE + pathSize;
    if (requestSize > STAI_MAX_PAYLOAD_SIZE) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto Cleanup;
    }

    if (!StaiAcquireClientPort(&clientPort)) {
        status = STATUS_PORT_DISCONNECTED;
        goto Cleanup;
    }
    portAcquired = TRUE;

    request = ExAllocatePoolWithTag(NonPagedPool, requestSize, STAI_TAG);
    replyBufferSize = FIELD_OFFSET(STAI_KERNEL_REPLY_BUFFER, Payload) + STAI_REPLY_DATA_MAX_BYTES;
    replyBuffer = ExAllocatePoolWithTag(NonPagedPool, replyBufferSize, STAI_TAG);
    if (!request || !replyBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    RtlZeroMemory(request, requestSize);
    request->size = requestSize;
    request->version = STAI_PROTOCOL_VERSION;
    request->request_id = RequestId;
    request->operation = Operation;
    request->path_len = pathSize / sizeof(WCHAR);
    RtlCopyMemory(request->path, FilePath->Buffer, pathSize);

    RtlZeroMemory(replyBuffer, replyBufferSize);
    replyDataOffset = FIELD_OFFSET(STAI_KERNEL_REPLY_BUFFER, Payload);
    replyLength = replyBufferSize;
    timeout.QuadPart = -10000LL * STAI_REQUEST_TIMEOUT_MS;

    status = FltSendMessage(
        g_FilterContext.FilterHandle,
        &clientPort,
        request,
        requestSize,
        replyBuffer,
        &replyLength,
        &timeout
    );

    /* STATUS_TIMEOUT is an NT-success code, but it is never a block verdict. */
    if (status != STATUS_SUCCESS) {
        goto Cleanup;
    }
    if (replyLength < replyDataOffset + STAI_REPLY_HEADER_SIZE ||
        replyLength > replyBufferSize ||
        replyBuffer->Header.Status != STATUS_SUCCESS) {
        status = STATUS_INVALID_BUFFER_SIZE;
        goto Cleanup;
    }

    reply = (PSTAI_REPLY)(replyBuffer->Payload);
    if (!stai_validate_reply(reply, replyLength - replyDataOffset) ||
        reply->request_id != RequestId) {
        status = STATUS_INVALID_PARAMETER;
        goto Cleanup;
    }

    *ShouldBlock = (reply->verdict == STAI_VERDICT_BLOCK);
    status = STATUS_SUCCESS;

Cleanup:
    if (replyBuffer) ExFreePoolWithTag(replyBuffer, STAI_TAG);
    if (request) ExFreePoolWithTag(request, STAI_TAG);
    if (portAcquired) StaiReleaseClientPort();
    InterlockedDecrement(&g_FilterContext.OutstandingRequestCount);
    return status;
}

VOID StaiSendCompletionToService(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalIoStatus
) {
    NTSTATUS status;
    PFLT_PORT clientPort = NULL;
    STAI_COMPLETION completion;
    LARGE_INTEGER timeout;

    if (RequestId == 0 || !StaiAcquireClientPort(&clientPort)) {
        return;
    }

    RtlZeroMemory(&completion, sizeof(completion));
    completion.size = STAI_COMPLETION_SIZE;
    completion.version = STAI_PROTOCOL_VERSION;
    completion.request_id = RequestId;
    completion.final_io_status = (uint32_t)FinalIoStatus;
    /* Completion is best-effort telemetry; it must not delay an already denied open. */
    timeout.QuadPart = 0;

    status = FltSendMessage(
        g_FilterContext.FilterHandle,
        &clientPort,
        &completion,
        STAI_COMPLETION_SIZE,
        NULL,
        NULL,
        &timeout
    );
    UNREFERENCED_PARAMETER(status);
    StaiReleaseClientPort();
}
