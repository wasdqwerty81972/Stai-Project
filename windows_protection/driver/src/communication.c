#include "communication.h"

#define STAI_REQUEST_TIMEOUT_MS 1000LL
#define STAI_MAX_OUTSTANDING_REQUESTS 32L
#define STAI_REPLY_STRING_MAX_BYTES \
    ((STAI_MAX_RULE_ID_UTF16_CHARS + STAI_MAX_RULE_VERSION_UTF16_CHARS) * sizeof(uint16_t))
#define STAI_REPLY_DATA_MAX_BYTES (STAI_REPLY_HEADER_SIZE + STAI_REPLY_STRING_MAX_BYTES)

typedef struct _STAI_KERNEL_REPLY_BUFFER {
    FILTER_REPLY_HEADER Header;
    UCHAR Payload[STAI_REPLY_DATA_MAX_BYTES];
} STAI_KERNEL_REPLY_BUFFER, *PSTAI_KERNEL_REPLY_BUFFER;

typedef struct _STAI_PENDING_INSPECTION {
    ULONG Operation;
    ULONG PathLength;
    ULONGLONG RequestId;
    ULONGLONG ProcessId;
    ULONGLONG ThreadId;
    WCHAR Path[ANYSIZE_ARRAY];
} STAI_PENDING_INSPECTION, *PSTAI_PENDING_INSPECTION;

static VOID StaiInspectionWorker(
    _In_ PFLT_DEFERRED_IO_WORKITEM WorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PVOID Context
);

static BOOLEAN StaiReserveQueueSlot(VOID) {
    BOOLEAN reserved = FALSE;
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_FilterContext.QueueStateLock, &oldIrql);
    if (!g_FilterContext.PendingShutdown &&
        g_FilterContext.OutstandingRequestCount < STAI_MAX_OUTSTANDING_REQUESTS) {
        if (g_FilterContext.OutstandingRequestCount == 0) {
            KeClearEvent(&g_FilterContext.QueueDrainEvent);
        }
        ++g_FilterContext.OutstandingRequestCount;
        reserved = TRUE;
    }
    KeReleaseSpinLock(&g_FilterContext.QueueStateLock, oldIrql);
    return reserved;
}

static VOID StaiReleaseQueueSlot(VOID) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_FilterContext.QueueStateLock, &oldIrql);
    if (g_FilterContext.OutstandingRequestCount > 0) {
        --g_FilterContext.OutstandingRequestCount;
        if (g_FilterContext.OutstandingRequestCount == 0) {
            KeSetEvent(&g_FilterContext.QueueDrainEvent, IO_NO_INCREMENT, FALSE);
        }
    }
    KeReleaseSpinLock(&g_FilterContext.QueueStateLock, oldIrql);
}

NTSTATUS StaiQueueInspection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath
) {
    NTSTATUS status;
    PFLT_DEFERRED_IO_WORKITEM workItem = NULL;
    PSTAI_PENDING_INSPECTION inspection = NULL;
    SIZE_T allocationSize;

    if (!Data || !FilePath || !FilePath->Buffer ||
        (FilePath->Length % sizeof(WCHAR)) != 0 ||
        FilePath->Length > STAI_MAX_PATH_UTF16_CHARS * sizeof(WCHAR)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!FLT_IS_IRP_OPERATION(Data)) {
        return STATUS_NOT_SUPPORTED;
    }

    allocationSize = FIELD_OFFSET(STAI_PENDING_INSPECTION, Path) + FilePath->Length;
    workItem = FltAllocateDeferredIoWorkItem();
    if (!workItem) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    inspection = ExAllocatePool2(POOL_FLAG_NON_PAGED, allocationSize, STAI_TAG);
    if (!inspection) {
        FltFreeDeferredIoWorkItem(workItem);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!StaiReserveQueueSlot()) {
        ExFreePoolWithTag(inspection, STAI_TAG);
        FltFreeDeferredIoWorkItem(workItem);
        return STATUS_QUOTA_EXCEEDED;
    }

    inspection->Operation = Operation;
    inspection->PathLength = FilePath->Length;
    inspection->RequestId = (ULONGLONG)InterlockedIncrement64(
        &g_FilterContext.RequestIdCounter
    );
    inspection->ProcessId = (ULONGLONG)(ULONG_PTR)PsGetCurrentProcessId();
    inspection->ThreadId = (ULONGLONG)(ULONG_PTR)PsGetCurrentThreadId();
    RtlCopyMemory(inspection->Path, FilePath->Buffer, FilePath->Length);

    /* The Filter Manager system queue is thread-safe. The global slot cap keeps
       this driver's queued and running work bounded even under I/O pressure. */
    status = FltQueueDeferredIoWorkItem(
        workItem,
        Data,
        StaiInspectionWorker,
        DelayedWorkQueue,
        inspection
    );
    if (!NT_SUCCESS(status)) {
        StaiReleaseQueueSlot();
        ExFreePoolWithTag(inspection, STAI_TAG);
        FltFreeDeferredIoWorkItem(workItem);
        return status;
    }

    return STATUS_PENDING;
}

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
    _In_ ULONGLONG ProcessId,
    _In_ ULONGLONG ThreadId,
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

    pathSize = FilePath->Length;
    if ((pathSize % sizeof(WCHAR)) != 0 ||
        pathSize > STAI_MAX_PATH_UTF16_CHARS * sizeof(WCHAR)) {
        return STATUS_NAME_TOO_LONG;
    }
    requestSize = STAI_REQUEST_HEADER_SIZE + pathSize;
    if (requestSize > STAI_MAX_PAYLOAD_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (!StaiAcquireClientPort(&clientPort)) {
        return STATUS_PORT_DISCONNECTED;
    }
    portAcquired = TRUE;

    request = ExAllocatePool2(POOL_FLAG_NON_PAGED, requestSize, STAI_TAG);
    replyBufferSize = FIELD_OFFSET(STAI_KERNEL_REPLY_BUFFER, Payload) + STAI_REPLY_DATA_MAX_BYTES;
    replyBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, replyBufferSize, STAI_TAG);
    if (!request || !replyBuffer) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    request->size = requestSize;
    request->version = STAI_PROTOCOL_VERSION;
    request->request_id = RequestId;
    request->operation = Operation;
    request->process_id = ProcessId;
    request->thread_id = ThreadId;
    request->path_len = pathSize / sizeof(WCHAR);
    RtlCopyMemory(request->path, FilePath->Buffer, pathSize);

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
    return status;
}

VOID StaiSendCompletionToService(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalIoStatus
) {
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
    timeout.QuadPart = 0;

    (VOID)FltSendMessage(
        g_FilterContext.FilterHandle,
        &clientPort,
        &completion,
        STAI_COMPLETION_SIZE,
        NULL,
        NULL,
        &timeout
    );
    StaiReleaseClientPort();
}

static VOID StaiInspectionWorker(
    _In_ PFLT_DEFERRED_IO_WORKITEM WorkItem,
    _In_ PFLT_CALLBACK_DATA Data,
    _In_opt_ PVOID Context
) {
    PSTAI_PENDING_INSPECTION inspection = (PSTAI_PENDING_INSPECTION)Context;
    UNICODE_STRING filePath;
    BOOLEAN shouldBlock = FALSE;
    NTSTATUS status;

    filePath.Buffer = inspection->Path;
    filePath.Length = (USHORT)inspection->PathLength;
    filePath.MaximumLength = (USHORT)inspection->PathLength;

    status = StaiSendRequestToService(
        inspection->RequestId,
        inspection->Operation,
        inspection->ProcessId,
        inspection->ThreadId,
        &filePath,
        &shouldBlock
    );

    if (status == STATUS_SUCCESS && shouldBlock) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        StaiSendCompletionToService(inspection->RequestId, STATUS_ACCESS_DENIED);
        FltCompletePendedPreOperation(Data, FLT_PREOP_COMPLETE, NULL);
    } else {
        /* A disconnected, saturated, malformed, or slow service is fail-open.
           The bounded timeout prevents a service outage from pinning I/O. */
        FltCompletePendedPreOperation(Data, FLT_PREOP_SUCCESS_NO_CALLBACK, NULL);
    }

    ExFreePoolWithTag(inspection, STAI_TAG);
    FltFreeDeferredIoWorkItem(WorkItem);
    StaiReleaseQueueSlot();
}
