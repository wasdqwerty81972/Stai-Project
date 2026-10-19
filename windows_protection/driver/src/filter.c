#include "driver.h"
#include "callbacks.h"

STAI_FILTER_CONTEXT g_FilterContext = { 0 };

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,
      0,
      StaiPreCreate,
      NULL },
    { IRP_MJ_WRITE,
      FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
      StaiPreWrite,
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

static NTSTATUS StaiCreateSystemOnlyPortSecurity(
    _Outptr_ PSECURITY_DESCRIPTOR *SecurityDescriptor,
    _Outptr_ PACL *PortAcl
) {
    NTSTATUS status;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID systemSid = NULL;
    ULONG aclSize;

    *SecurityDescriptor = NULL;
    *PortAcl = NULL;

    systemSid = ExAllocatePool2(POOL_FLAG_PAGED, SECURITY_MAX_SID_SIZE, STAI_TAG);
    if (!systemSid) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = RtlInitializeSid(systemSid, &ntAuthority, 1);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(systemSid, STAI_TAG);
        return status;
    }
    *RtlSubAuthoritySid(systemSid, 0) = SECURITY_LOCAL_SYSTEM_RID;

    aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(ULONG) + RtlLengthSid(systemSid);
    *PortAcl = ExAllocatePool2(POOL_FLAG_PAGED, aclSize, STAI_TAG);
    *SecurityDescriptor = ExAllocatePool2(
        POOL_FLAG_PAGED,
        SECURITY_DESCRIPTOR_MIN_LENGTH,
        STAI_TAG
    );
    if (!*PortAcl || !*SecurityDescriptor) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    status = RtlCreateAcl(*PortAcl, aclSize, ACL_REVISION);
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlAddAccessAllowedAce(
        *PortAcl,
        ACL_REVISION,
        FLT_PORT_CONNECT,
        systemSid
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlCreateSecurityDescriptor(
        *SecurityDescriptor,
        SECURITY_DESCRIPTOR_REVISION
    );
    if (!NT_SUCCESS(status)) {
        goto Cleanup;
    }

    status = RtlSetDaclSecurityDescriptor(
        *SecurityDescriptor,
        TRUE,
        *PortAcl,
        FALSE
    );

Cleanup:
    ExFreePoolWithTag(systemSid, STAI_TAG);
    if (!NT_SUCCESS(status)) {
        if (*SecurityDescriptor) {
            ExFreePoolWithTag(*SecurityDescriptor, STAI_TAG);
            *SecurityDescriptor = NULL;
        }
        if (*PortAcl) {
            ExFreePoolWithTag(*PortAcl, STAI_TAG);
            *PortAcl = NULL;
        }
    }
    return status;
}

NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
) {
    NTSTATUS status;
    UNICODE_STRING portName;
    OBJECT_ATTRIBUTES oa;
    PSECURITY_DESCRIPTOR securityDescriptor = NULL;
    PACL portAcl = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    ExInitializeFastMutex(&g_FilterContext.ContextLock);
    ExInitializeRundownProtection(&g_FilterContext.ClientPortRundown);
    KeInitializeEvent(&g_FilterContext.ClientPortDrainEvent, NotificationEvent, TRUE);
    KeInitializeSpinLock(&g_FilterContext.QueueStateLock);
    KeInitializeEvent(&g_FilterContext.QueueDrainEvent, NotificationEvent, TRUE);
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
    status = StaiCreateSystemOnlyPortSecurity(&securityDescriptor, &portAcl);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        securityDescriptor
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

    if (portAcl) {
        ExFreePoolWithTag(portAcl, STAI_TAG);
    }
    if (securityDescriptor) {
        ExFreePoolWithTag(securityDescriptor, STAI_TAG);
    }

    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    status = FltStartFiltering(g_FilterContext.FilterHandle);
    if (!NT_SUCCESS(status)) {
        StaiClosePort();
        FltUnregisterFilter(g_FilterContext.FilterHandle);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS StaiUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    KIRQL oldIrql;

    UNREFERENCED_PARAMETER(Flags);

    KeAcquireSpinLock(&g_FilterContext.QueueStateLock, &oldIrql);
    InterlockedExchange(&g_FilterContext.PendingShutdown, 1);
    KeReleaseSpinLock(&g_FilterContext.QueueStateLock, oldIrql);

    StaiClosePort();
    KeWaitForSingleObject(
        &g_FilterContext.QueueDrainEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );
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
    *ConnectionPortCookie = NULL;

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
