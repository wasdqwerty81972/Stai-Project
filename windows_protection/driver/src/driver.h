#ifndef STAI_DRIVER_H
#define STAI_DRIVER_H

#include <fltKernel.h>
#include "protection_protocol.h"

#define STAI_TAG 'taTS'

typedef struct _STAI_FILTER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PEPROCESS ServiceProcess;
    FAST_MUTEX ContextLock;
    EX_RUNDOWN_REF ClientPortRundown;
    KEVENT ClientPortDrainEvent;
    BOOLEAN ServiceConnected;
    BOOLEAN ClientPortDrainInProgress;
    volatile LONG OutstandingRequestCount;
    LONG64 RequestIdCounter;
    LONG PendingShutdown;
} STAI_FILTER_CONTEXT, *PSTAI_FILTER_CONTEXT;

extern STAI_FILTER_CONTEXT g_FilterContext;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath);

NTSTATUS StaiUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS StaiConnectNotify(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie
);

VOID StaiDisconnectNotify(_In_opt_ PVOID ConnectionPortCookie);

VOID StaiClosePort(VOID);

NTSTATUS StaiSendRequestToService(
    _In_ ULONGLONG RequestId,
    _In_ ULONG Operation,
    _In_ PUNICODE_STRING FilePath,
    _Out_ PBOOLEAN ShouldBlock
);

VOID StaiSendCompletionToService(
    _In_ ULONGLONG RequestId,
    _In_ NTSTATUS FinalIoStatus
);

#endif
