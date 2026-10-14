#include "driver.h"
#include "callbacks.h"

STAI_FILTER_CONTEXT g_FilterContext = { 0 };

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      StaiPreCreate,
      NULL },
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
    ExInitializeRundownProtection(&g_FilterContext.ClientPortRundown);
    KeInitializeEvent(&g_FilterContext.ClientPortDrainEvent, NotificationEvent, TRUE);
    g_FilterContext.RequestIdCounter = 0;
    g_FilterContext.OutstandingRequestCount = 0;
    g_FilterContext.ServiceConnected = FALSE;
    g_FilterContext.ClientPortDrainInProgress = FALSE;
    g_FilterContext.PendingShutdown = 0;

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &g_FilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, STAI_PORT_NAME);

    /* Development ACL: SYSTEM and administrators may connect. The service host
       must run as SYSTEM; a product-specific service SID ACL is still needed. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_CONNECT);
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
        NULL,
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

    InterlockedExchange(&g_FilterContext.PendingShutdown, 1);

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
    PEPROCESS clientProcess;

    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    ExAcquireFastMutex(&g_FilterContext.ContextLock);

    if (g_FilterContext.PendingShutdown ||
        g_FilterContext.ServiceConnected ||
        g_FilterContext.ClientPortDrainInProgress) {
        ExReleaseFastMutex(&g_FilterContext.ContextLock);
        return STATUS_ALREADY_COMMITTED;
    }

    ExReInitializeRundownProtection(&g_FilterContext.ClientPortRundown);
    KeClearEvent(&g_FilterContext.ClientPortDrainEvent);

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
    PFLT_PORT clientPort = NULL;
    PEPROCESS serviceProcess = NULL;
    BOOLEAN ownsDrain = FALSE;

    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    ExAcquireFastMutex(&g_FilterContext.ContextLock);

    if (g_FilterContext.ClientPort) {
        clientPort = g_FilterContext.ClientPort;
        serviceProcess = g_FilterContext.ServiceProcess;
        g_FilterContext.ServiceProcess = NULL;
        g_FilterContext.ClientPort = NULL;
        g_FilterContext.ServiceConnected = FALSE;
        g_FilterContext.ClientPortDrainInProgress = TRUE;
        KeClearEvent(&g_FilterContext.ClientPortDrainEvent);
        ownsDrain = TRUE;
    }

    ExReleaseFastMutex(&g_FilterContext.ContextLock);
    if (!ownsDrain) {
        return;
    }

    FltCloseClientPort(g_FilterContext.FilterHandle, &clientPort);
    ExWaitForRundownProtectionRelease(&g_FilterContext.ClientPortRundown);
    if (serviceProcess) {
        ObDereferenceObject(serviceProcess);
    }

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    g_FilterContext.ClientPortDrainInProgress = FALSE;
    KeSetEvent(&g_FilterContext.ClientPortDrainEvent, IO_NO_INCREMENT, FALSE);
    ExReleaseFastMutex(&g_FilterContext.ContextLock);
}

VOID StaiClosePort(VOID) {
    PFLT_PORT clientPort = NULL;
    PEPROCESS serviceProcess = NULL;
    BOOLEAN ownsDrain = FALSE;
    BOOLEAN waitForDrain = FALSE;

    if (g_FilterContext.ServerPort) {
        FltCloseCommunicationPort(g_FilterContext.ServerPort);
        g_FilterContext.ServerPort = NULL;
    }

    ExAcquireFastMutex(&g_FilterContext.ContextLock);
    if (g_FilterContext.ClientPort) {
        clientPort = g_FilterContext.ClientPort;
        serviceProcess = g_FilterContext.ServiceProcess;
        g_FilterContext.ClientPort = NULL;
        g_FilterContext.ServiceProcess = NULL;
        g_FilterContext.ServiceConnected = FALSE;
        g_FilterContext.ClientPortDrainInProgress = TRUE;
        KeClearEvent(&g_FilterContext.ClientPortDrainEvent);
        ownsDrain = TRUE;
    } else if (g_FilterContext.ClientPortDrainInProgress) {
        waitForDrain = TRUE;
    }
    ExReleaseFastMutex(&g_FilterContext.ContextLock);

    if (ownsDrain) {
        FltCloseClientPort(g_FilterContext.FilterHandle, &clientPort);
        ExWaitForRundownProtectionRelease(&g_FilterContext.ClientPortRundown);
        if (serviceProcess) {
            ObDereferenceObject(serviceProcess);
        }
        ExAcquireFastMutex(&g_FilterContext.ContextLock);
        g_FilterContext.ClientPortDrainInProgress = FALSE;
        KeSetEvent(&g_FilterContext.ClientPortDrainEvent, IO_NO_INCREMENT, FALSE);
        ExReleaseFastMutex(&g_FilterContext.ContextLock);
    } else if (waitForDrain) {
        KeWaitForSingleObject(
            &g_FilterContext.ClientPortDrainEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );
    }
}
