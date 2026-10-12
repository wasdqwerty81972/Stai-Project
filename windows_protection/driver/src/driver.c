#include "driver.h"

STAI_FILTER_CONTEXT g_FilterContext = { 0 };

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      StaiPreCreate,
      StaiPostCreate },
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
      0,
      StaiPreAcquireForSectionSynchronization,
      NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,
    NULL,
    Callbacks,
    StaiUnload,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR sd = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&g_FilterContext.ContextLock);
    InitializeListHead(&g_FilterContext.OutstandingRequests);
    g_FilterContext.RequestIdCounter = 0;
    g_FilterContext.ServiceConnected = FALSE;
    g_FilterContext.PendingShutdown = 0;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, STAI_PORT_NAME);

    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );

    status = FltCreateCommunicationPort(
        g_FilterContext.FilterHandle,
        &g_FilterContext.ServerPort,
        &oa,
        NULL,
        StaiConnectNotify,
        StaiDisconnectNotify,
        StaiMessageNotify,
        1
    );

    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    status = FltStartFiltering(g_FilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(g_FilterContext.ServerPort);
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS StaiUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);

    InterlockedIncrement(&g_FilterContext.PendingShutdown);

    StaiCleanupOutstandingRequests();
    StaiClosePort();
    FltUnregisterFilter(g_FilterContext.FilterHandle);

    return STATUS_SUCCESS;
}

NTSTATUS StaiConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
) {
    NTSTATUS status;
    PEPROCESS clientProcess;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    ExAcquireFastMutex(&g_FilterContext.ContextLock);

    if (g_FilterContext.ServiceConnected) {
        ExReleaseFastMutex(&g_FilterContext.ContextLock);
        return STATUS_ALREADY_COMMITTED;
    }

    clientProcess = PsGetCurrentProcess();
    g_FilterContext.ServiceProcess = clientProcess;
    ObReferenceObject(clientProcess);

    g_FilterContext.ClientPort = ClientPort;
    g_FilterContext.ServiceConnected = TRUE;

    ExReleaseFastMutex(&g_FilterContext.ContextLock);

    *ConnectionPortCookie = (PVOID)1;
    return STATUS_SUCCESS;
}

VOID StaiDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie) {
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    ExAcquireFastMutex(&g_FilterContext.ContextLock);

    if (g_FilterContext.ServiceProcess) {
        ObDereferenceObject(g_FilterContext.ServiceProcess);
        g_FilterContext.ServiceProcess = NULL;
    }

    g_FilterContext.ClientPort = NULL;
    g_FilterContext.ServiceConnected = FALSE;

    ExReleaseFastMutex(&g_FilterContext.ContextLock);
}

NTSTATUS StaiMessageNotify(
    _In_opt_ PVOID ConnectionPortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
) {
    PSTAI_REQUEST request;
    PSTAI_REPLY reply;
    ULONGLONG requestId;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(ConnectionPortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferSize);
    UNREFERENCED_PARAMETER(ReturnOutputBufferLength);

    if (!InputBuffer || InputBufferSize < sizeof(STAI_REQUEST)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    request = (PSTAI_REQUEST)InputBuffer;

    if (!stai_validate_request(request, InputBufferSize)) {
        return STATUS_INVALID_PARAMETER;
    }

    requestId = request->request_id;

    if (request->operation == STAI_OP_CREATE ||
        request->operation == STAI_OP_IMAGE_MAPPING) {
        UNICODE_STRING filePath;
        filePath.Length = (USHORT)(request->path_len * sizeof(WCHAR));
        filePath.MaximumLength = filePath.Length;
        filePath.Buffer = request->path;

        status = StaiSendRequestToService(requestId, request->operation, &filePath);
    }

    return status;
}

NTSTATUS StaiCreatePort(_In_ PFLT_FILTER FilterHandle) {
    UNREFERENCED_PARAMETER(FilterHandle);
    return STATUS_SUCCESS;
}

VOID StaiClosePort(VOID) {
    if (g_FilterContext.ServerPort) {
        FltCloseCommunicationPort(g_FilterContext.ServerPort);
        g_FilterContext.ServerPort = NULL;
    }
}