#ifndef STAI_DRIVER_H
#define STAI_DRIVER_H

#include <fltKernel.h>
#include "protection_protocol.h"

#define STAI_PORT_NAME L"\\STAIProtectionPort"
#define STAI_TAG 'taTS'
#define STAI_MAX_OUTSTANDING_REQUESTS 256

typedef struct _STAI_FILTER_CONTEXT {
    PFLT_FILTER FilterHandle;
    PFLT_PORT ServerPort;
    PFLT_PORT ClientPort;
    PEPROCESS ServiceProcess;
    FAST_MUTEX ContextLock;
    BOOLEAN ServiceConnected;
    LIST_ENTRY OutstandingRequests;
    LONG64 RequestIdCounter;
    LONG PendingShutdown;
} STAI_FILTER_CONTEXT, *PSTAI_FILTER_CONTEXT;

typedef struct _STAI_OUTSTANDING_REQUEST {
    LIST_ENTRY ListEntry;
    ULONGLONG RequestId;
    LARGE_INTEGER Timeout;
    KEVENT CompletionEvent;
    NTSTATUS FinalStatus;
    BOOLEAN Completed;
} STAI_OUTSTANDING_REQUEST, *PSTAI_OUTSTANDING_REQUEST;

typedef struct _STAI_COMPLETION_CONTEXT {
    ULONGLONG RequestId;
    PSTAI_OUTSTANDING_REQUEST OutstandingRequest;
} STAI_COMPLETION_CONTEXT, *PSTAI_COMPLETION_CONTEXT;

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

NTSTATUS StaiMessageNotify(
    _In_opt_ PVOID ConnectionPortCookie,
    _In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
    _In_ ULONG InputBufferSize,
    _Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferSize,
    _Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS StaiCreatePort(_In_ PFLT_FILTER FilterHandle);
VOID StaiClosePort(VOID);

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

#endif