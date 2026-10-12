#include "callbacks.h"
#include "protection_port.h"

static BOOLEAN StaiShouldInspectCreate(_In_ PFLT_CALLBACK_DATA Data) {
    ACCESS_MASK desiredAccess;

    if (!Data->Iopb->Parameters.Create.SecurityContext) {
        return FALSE;
    }
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    if (!(desiredAccess & (FILE_READ_DATA | FILE_EXECUTE))) {
        return FALSE;
    }
    if (Data->Iopb->Parameters.Create.Options & (FILE_DIRECTORY_FILE | FILE_OPEN_BY_FILE_ID)) {
        return FALSE;
    }
    return TRUE;
}

static FLT_PREOP_CALLBACK_STATUS StaiInspectFileOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG Operation
) {
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    UNICODE_STRING filePath;
    ULONGLONG requestId;
    BOOLEAN shouldBlock = FALSE;

    if (StaiIsServiceProcess(PsGetCurrentProcess())) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo
    );
    if (!NT_SUCCESS(status) || !nameInfo || !nameInfo->Name.Length) {
        if (nameInfo) FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltParseFileNameInformation(nameInfo);
    if (!NT_SUCCESS(status)) {
        FltReleaseFileNameInformation(nameInfo);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    filePath = nameInfo->Name;
    requestId = (ULONGLONG)InterlockedIncrement64(&g_FilterContext.RequestIdCounter);
    status = StaiSendRequestToService(requestId, Operation, &filePath, &shouldBlock);
    FltReleaseFileNameInformation(nameInfo);

    /* Every failure, timeout, malformed reply, or mismatched request is allow. */
    if (status != STATUS_SUCCESS || !shouldBlock) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    StaiSendCompletionToService(requestId, STATUS_ACCESS_DENIED);
    return FLT_PREOP_COMPLETE;
}

FLT_PREOP_CALLBACK_STATUS StaiPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;

    if (!StaiShouldInspectCreate(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return StaiInspectFileOperation(Data, STAI_OP_CREATE);
}

FLT_PREOP_CALLBACK_STATUS StaiPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!Data->Iopb->TargetFileObject || !Data->Iopb->TargetFileObject->FileName.Length) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    return StaiInspectFileOperation(Data, STAI_OP_IMAGE_MAPPING);
}

BOOLEAN StaiIsServiceProcess(_In_ PEPROCESS Process) {
    BOOLEAN result;

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    result = (g_FilterContext.ServiceProcess != NULL &&
              g_FilterContext.ServiceProcess == Process);
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
    return result;
}
