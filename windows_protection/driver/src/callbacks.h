#ifndef STAI_CALLBACKS_H
#define STAI_CALLBACKS_H

#include <fltKernel.h>
#include "driver.h"

FLT_PREOP_CALLBACK_STATUS StaiPreCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

FLT_POSTOP_CALLBACK_STATUS StaiPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS StaiPreAcquireForSectionSynchronization(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

BOOLEAN StaiIsServiceProcess(_In_ PEPROCESS Process);

NTSTATUS StaiAllocateOutstandingRequest(
    _In_ ULONGLONG RequestId,
    _Out_ PSTAI_OUTSTANDING_REQUEST *OutstandingRequest
);

VOID StaiFreeOutstandingRequest(_In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest);

PSTAI_OUTSTANDING_REQUEST StaiFindOutstandingRequest(_In_ ULONGLONG RequestId);

VOID StaiRemoveOutstandingRequest(_In_ PSTAI_OUTSTANDING_REQUEST OutstandingRequest);

#endif