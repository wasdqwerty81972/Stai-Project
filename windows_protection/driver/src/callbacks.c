#include "callbacks.h"

FLT_PREOP_CALLBACK_STATUS StaiPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN isReadOrExecute = FALSE;
    PSTAI_OUTSTANDING_REQUEST outstanding = NULL;
    PSTAI_COMPLETION_CONTEXT completionContext = NULL;
    ULONGLONG requestId;

    UNREFERENCED_PARAMETER(FltObjects);

    if (StaiIsServiceProcess(PsGetCurrentProcess())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!(Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess & (FILE_READ_DATA | FILE_EXECUTE))) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (Data->Iopb->Parameters.Create.Options & (FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Length) {
        if (nameInfo) FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestId = InterlockedIncrement64(&g_FilterContext.RequestIdCounter);
    
    status = StaiAllocateOutstandingRequest(requestId, &outstanding);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    completionContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(STAI_COMPLETION_CONTEXT), STAI_TAG);
    if (!completionContext) {
        StaiFreeOutstandingRequest(outstanding);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    completionContext->RequestId = requestId;
    completionContext->OutstandingRequest = outstanding;
    *CompletionContext = completionContext;

    status = StaiSendRequestToService(requestId, STAI_OP_CREATE, &nameInfo->Name);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(status)) {
        StaiCompleteOutstandingRequest(requestId, status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SYNCHRONIZE;
}

FLT_POSTOP_CALLBACK_STATUS StaiPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
) {
    PSTAI_COMPLETION_CONTEXT context = (PSTAI_COMPLETION_CONTEXT)CompletionContext;
    NTSTATUS finalStatus;

    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);

    if (!context) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    if (context->OutstandingRequest->Completed) {
        finalStatus = context->OutstandingRequest->FinalStatus;
    } else {
        finalStatus = STATUS_SUCCESS;
    }

    if (context->OutstandingRequest) {
        StaiRemoveOutstandingRequest(context->OutstandingRequest);
        StaiFreeOutstandingRequest(context->OutstandingRequest);
    }

    ExFreePoolWithTag(context, STAI_TAG);

    if (!NT_SUCCESS(finalStatus) && finalStatus == STATUS_ACCESS_DENIED) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS StaiPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PSTAI_OUTSTANDING_REQUEST outstanding = NULL;
    PSTAI_COMPLETION_CONTEXT completionContext = NULL;
    ULONGLONG requestId;

    UNREFERENCED_PARAMETER(FltObjects);

    if (StaiIsServiceProcess(PsGetCurrentProcess())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (!Data->Iopb->TargetFileObject || !Data->Iopb->TargetFileObject->FileName.Length) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || !nameInfo->Name.Length) {
        if (nameInfo) FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    requestId = InterlockedIncrement64(&g_FilterContext.RequestIdCounter);
    
    status = StaiAllocateOutstandingRequest(requestId, &outstanding);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    completionContext = ExAllocatePoolWithTag(NonPagedPool, sizeof(STAI_COMPLETION_CONTEXT), STAI_TAG);
    if (!completionContext) {
        StaiFreeOutstandingRequest(outstanding);
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    completionContext->RequestId = requestId;
    completionContext->OutstandingRequest = outstanding;
    *CompletionContext = completionContext;

    status = StaiSendRequestToService(requestId, STAI_OP_IMAGE_MAPPING, &nameInfo->Name);
    FltReleaseFileNameInformation(nameInfo);

    if (!NT_SUCCESS(status)) {
        StaiCompleteOutstandingRequest(requestId, status);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    return FLT_PREOP_SYNCHRONIZE;
}

BOOLEAN StaiIsServiceProcess(_In_ PEPROCESS Process) {
    BOOLEAN result = FALSE;

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    if (g_FilterContext.ServiceProcess && g_FilterContext.ServiceProcess == Process) {
        result = TRUE;
    }
    ExReleaseFastMutex(&g_FilterContext.ContextLock);

    return result;
}

NTSTATUS StaiAllocateOutstandingRequest(
    _In_ ULONGLONG RequestId,
    _Out_ PSTAI_OUTSTANDING_REQUEST *OutstandingRequest
) {
    PSTAI_OUTSTANDING_REQUEST request;

    request = ExAllocatePoolWithTag(NonPagedPool, sizeof(STAI_OUTSTANDING_REQUEST), STAI_TAG);
    if (!request) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(request, sizeof(STAI_OUTSTANDING_REQUEST));
    request->RequestId = RequestId;
    request->Timeout.QuadPart = -10000000LL * 5; // 5 second timeout
    request->FinalStatus = STATUS_PENDING;
    request->Completed = FALSE;

    KeInitializeEvent(&request->CompletionEvent, NotificationEvent, FALSE);

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    InsertTailList(&g_FilterContext.OutstandingRequests, &request->ListEntry);
    ExReleaseFastMutex(&g_FilterContext.ContextLock);

    *OutstandingRequest = request;
    return STATUS_SUCCESS;
}

VOID StaiFreeOutstandingRequest(_In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest) {
    // CompletionEvent is embedded in the structure; it is freed with the pool.
    ExFreePoolWithTag(OutstandingRequest, STAI_TAG);
}

PSTAI_OUTSTANDING_REQUEST StaiFindOutstandingRequest(_In_ ULONGLONG RequestId) {
    PLIST_ENTRY entry;
    PSTAI_OUTSTANDING_REQUEST request = NULL;

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    for (entry = g_FilterContext.OutstandingRequests.Flink;
         entry != &g_FilterContext.OutstandingRequests;
         entry = entry->Flink) {
        request = CONTAINING_RECORD(entry, STAI_OUTSTANDING_REQUEST, ListEntry);
        if (request->RequestId == RequestId) {
            break;
        }
        request = NULL;
    }
    ExReleaseFastMutex(&g_FilterContext.ContextLock);

    return request;
}

VOID StaiRemoveOutstandingRequest(_In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest) {
    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    RemoveEntryList(&OutstandingRequest->ListEntry);
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
}