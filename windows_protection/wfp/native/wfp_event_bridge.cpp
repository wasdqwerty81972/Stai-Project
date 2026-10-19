#define WIN32_LEAN_AND_MEAN
#include "wfp_event_bridge.h"

#include <rpcdce.h>
#include <cstring>

namespace {

SRWLOCK g_queueLock = SRWLOCK_INIT;
SVS_WFP_EVENT_RECORD g_queue[SVS_WFP_QUEUE_CAPACITY] = {};
std::uint64_t g_head = 0;
std::uint64_t g_tail = 0;
volatile LONG g_queued = 0;
volatile LONG64 g_sequence = 0;
volatile LONG64 g_dropped = 0;
volatile LONG g_callbackCount = 0;
volatile LONG g_state = SVS_WFP_STATE_STOPPED;
volatile LONG g_lastError = ERROR_SUCCESS;
HANDLE g_engineHandle = nullptr;
HANDLE g_eventsHandle = nullptr;

using Subscribe3Function = DWORD(WINAPI*)(
    HANDLE,
    const FWPM_NET_EVENT_SUBSCRIPTION0*,
    FWPM_NET_EVENT_CALLBACK3,
    void*,
    HANDLE*
);

bool HasFlag(const FWPM_NET_EVENT_HEADER3& header, std::uint32_t flag) {
    return (header.flags & flag) != 0;
}

bool NormalizeNetEvent(
    const FWPM_NET_EVENT4* event,
    SVS_WFP_EVENT_RECORD* output
) {
    if (event == nullptr || output == nullptr) {
        return false;
    }
    if (event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW &&
        event->type != FWPM_NET_EVENT_TYPE_CLASSIFY_DROP) {
        return false;
    }

    std::memset(output, 0, sizeof(*output));
    output->size = sizeof(*output);
    output->version = SVS_WFP_EVENT_ABI_VERSION;
    output->timestampFiletime =
        (static_cast<std::uint64_t>(event->header.timeStamp.dwHighDateTime) << 32) |
        event->header.timeStamp.dwLowDateTime;
    if (output->timestampFiletime != 0) {
        output->fieldFlags |= SVS_WFP_FIELD_TIMESTAMP;
    }

    const bool hasIpVersion = HasFlag(event->header, FWPM_NET_EVENT_FLAG_IP_VERSION_SET);
    if (hasIpVersion && event->header.ipVersion == FWP_IP_VERSION_V4) {
        output->ipVersion = 4;
        output->fieldFlags |= SVS_WFP_FIELD_IP_VERSION;
    } else if (hasIpVersion && event->header.ipVersion == FWP_IP_VERSION_V6) {
        output->ipVersion = 6;
        output->fieldFlags |= SVS_WFP_FIELD_IP_VERSION;
    }

    if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET)) {
        output->protocol = event->header.ipProtocol;
        output->fieldFlags |= SVS_WFP_FIELD_PROTOCOL;
    }

    if (output->fieldFlags & SVS_WFP_FIELD_IP_VERSION) {
        if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET)) {
            if (output->ipVersion == 4) {
                std::memcpy(output->localAddress, &event->header.localAddrV4, 4);
            } else {
                std::memcpy(output->localAddress, event->header.localAddrV6.byteArray16, 16);
            }
            output->fieldFlags |= SVS_WFP_FIELD_LOCAL_ADDRESS;
        }
        if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET)) {
            if (output->ipVersion == 4) {
                std::memcpy(output->remoteAddress, &event->header.remoteAddrV4, 4);
            } else {
                std::memcpy(output->remoteAddress, event->header.remoteAddrV6.byteArray16, 16);
            }
            output->fieldFlags |= SVS_WFP_FIELD_REMOTE_ADDRESS;
        }
    }

    if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET)) {
        output->localPort = event->header.localPort;
        output->fieldFlags |= SVS_WFP_FIELD_LOCAL_PORT;
    }
    if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET)) {
        output->remotePort = event->header.remotePort;
        output->fieldFlags |= SVS_WFP_FIELD_REMOTE_PORT;
    }

    if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_APP_ID_SET) &&
        event->header.appId.size > 0 && event->header.appId.data != nullptr) {
        const std::uint32_t copySize =
            event->header.appId.size > SVS_WFP_APP_ID_MAX_BYTES
                ? SVS_WFP_APP_ID_MAX_BYTES
                : event->header.appId.size;
        std::memcpy(output->appId, event->header.appId.data, copySize);
        output->appIdLength = copySize;
        output->fieldFlags |= SVS_WFP_FIELD_APP_ID;
        if (copySize != event->header.appId.size) {
            output->fieldFlags |= SVS_WFP_FIELD_APP_ID_TRUNCATED;
        }
    }

    if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_USER_ID_SET) &&
        event->header.userId != nullptr && IsValidSid(event->header.userId)) {
        const DWORD sidLength = GetLengthSid(event->header.userId);
        if (sidLength <= SVS_WFP_SID_MAX_BYTES) {
            std::memcpy(output->userSid, event->header.userId, sidLength);
            output->userSidLength = sidLength;
            output->fieldFlags |= SVS_WFP_FIELD_USER_SID;
        } else {
            output->fieldFlags |= SVS_WFP_FIELD_USER_SID_TRUNCATED;
        }
    }

    output->eventType = event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW
        ? SVS_WFP_EVENT_CLASSIFY_ALLOW
        : SVS_WFP_EVENT_CLASSIFY_DROP;

    if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW && event->classifyAllow != nullptr) {
        output->layerId = event->classifyAllow->layerId;
        output->fieldFlags |= SVS_WFP_FIELD_LAYER;
        if (event->classifyAllow->msFwpDirection == FWP_DIRECTION_INBOUND) {
            output->direction = SVS_WFP_DIRECTION_INBOUND;
            output->fieldFlags |= SVS_WFP_FIELD_DIRECTION;
        } else if (event->classifyAllow->msFwpDirection == FWP_DIRECTION_OUTBOUND) {
            output->direction = SVS_WFP_DIRECTION_OUTBOUND;
            output->fieldFlags |= SVS_WFP_FIELD_DIRECTION;
        }
        output->isLoopback = event->classifyAllow->isLoopback ? 1U : 0U;
        output->fieldFlags |= SVS_WFP_FIELD_LOOPBACK;
        if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET)) {
            output->reauthReason = event->classifyAllow->reauthReason;
            output->fieldFlags |= SVS_WFP_FIELD_REAUTH_REASON;
        }
    } else if (event->type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP && event->classifyDrop != nullptr) {
        output->layerId = event->classifyDrop->layerId;
        output->fieldFlags |= SVS_WFP_FIELD_LAYER;
        if (event->classifyDrop->msFwpDirection == FWP_DIRECTION_INBOUND) {
            output->direction = SVS_WFP_DIRECTION_INBOUND;
            output->fieldFlags |= SVS_WFP_FIELD_DIRECTION;
        } else if (event->classifyDrop->msFwpDirection == FWP_DIRECTION_OUTBOUND) {
            output->direction = SVS_WFP_DIRECTION_OUTBOUND;
            output->fieldFlags |= SVS_WFP_FIELD_DIRECTION;
        }
        output->isLoopback = event->classifyDrop->isLoopback ? 1U : 0U;
        output->fieldFlags |= SVS_WFP_FIELD_LOOPBACK;
        if (HasFlag(event->header, FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET)) {
            output->reauthReason = event->classifyDrop->reauthReason;
            output->fieldFlags |= SVS_WFP_FIELD_REAUTH_REASON;
        }
    }

    return true;
}

bool TryQueue(const SVS_WFP_EVENT_RECORD& record) {
    if (!TryAcquireSRWLockExclusive(&g_queueLock)) {
        InterlockedIncrement64(&g_dropped);
        return false;
    }
    if (g_tail - g_head >= SVS_WFP_QUEUE_CAPACITY) {
        ReleaseSRWLockExclusive(&g_queueLock);
        InterlockedIncrement64(&g_dropped);
        return false;
    }
    g_queue[g_tail % SVS_WFP_QUEUE_CAPACITY] = record;
    ++g_tail;
    InterlockedIncrement(&g_queued);
    ReleaseSRWLockExclusive(&g_queueLock);
    return true;
}

void PublishEvent(const FWPM_NET_EVENT4* event) {
    SVS_WFP_EVENT_RECORD record = {};
    if (!NormalizeNetEvent(event, &record)) {
        return;
    }
    record.sequence = static_cast<std::uint64_t>(InterlockedIncrement64(&g_sequence));
    TryQueue(record);
}

void CALLBACK NetEventCallback(void* context, const FWPM_NET_EVENT4* event) {
    UNREFERENCED_PARAMETER(context);
    InterlockedIncrement(&g_callbackCount);
    const LONG state = InterlockedCompareExchange(&g_state, 0, 0);
    if (state == SVS_WFP_STATE_RUNNING || state == SVS_WFP_STATE_STARTING) {
        PublishEvent(event);
    }
    InterlockedDecrement(&g_callbackCount);
}

void ResetQueueAndCounters() {
    AcquireSRWLockExclusive(&g_queueLock);
    std::memset(g_queue, 0, sizeof(g_queue));
    g_head = 0;
    g_tail = 0;
    InterlockedExchange(&g_queued, 0);
    InterlockedExchange64(&g_sequence, 0);
    InterlockedExchange64(&g_dropped, 0);
    InterlockedExchange(&g_lastError, ERROR_SUCCESS);
    ReleaseSRWLockExclusive(&g_queueLock);
}

}  // namespace

extern "C" DWORD WINAPI SvsWfpStart() {
    LONG expected = SVS_WFP_STATE_STOPPED;
    if (InterlockedCompareExchange(&g_state, SVS_WFP_STATE_STARTING, expected) != expected) {
        return ERROR_ALREADY_INITIALIZED;
    }
    ResetQueueAndCounters();

    FWPM_SESSION0 session = {};
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = const_cast<wchar_t*>(L"SVS-Cyber read-only WFP event session");
    HANDLE engine = nullptr;
    DWORD result = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine);
    if (result != ERROR_SUCCESS) {
        InterlockedExchange(&g_lastError, static_cast<LONG>(result));
        InterlockedExchange(&g_state, SVS_WFP_STATE_FAILED);
        return result;
    }

    HMODULE fwpuclnt = GetModuleHandleW(L"fwpuclnt.dll");
    if (fwpuclnt == nullptr) {
        fwpuclnt = LoadLibraryW(L"fwpuclnt.dll");
    }
    const auto subscribe = fwpuclnt == nullptr
        ? nullptr
        : reinterpret_cast<Subscribe3Function>(GetProcAddress(fwpuclnt, "FwpmNetEventSubscribe3"));
    if (subscribe == nullptr) {
        FwpmEngineClose0(engine);
        const DWORD error = GetLastError() == ERROR_SUCCESS ? ERROR_PROC_NOT_FOUND : GetLastError();
        InterlockedExchange(&g_lastError, static_cast<LONG>(error));
        InterlockedExchange(&g_state, SVS_WFP_STATE_FAILED);
        return error;
    }

    FWPM_NET_EVENT_SUBSCRIPTION0 subscription = {};
    HANDLE events = nullptr;
    result = subscribe(engine, &subscription, NetEventCallback, nullptr, &events);
    if (result != ERROR_SUCCESS) {
        FwpmEngineClose0(engine);
        InterlockedExchange(&g_lastError, static_cast<LONG>(result));
        InterlockedExchange(&g_state, SVS_WFP_STATE_FAILED);
        return result;
    }

    g_engineHandle = engine;
    g_eventsHandle = events;
    InterlockedExchange(&g_lastError, ERROR_SUCCESS);
    InterlockedExchange(&g_state, SVS_WFP_STATE_RUNNING);
    return ERROR_SUCCESS;
}

extern "C" DWORD WINAPI SvsWfpStop() {
    LONG state = InterlockedCompareExchange(&g_state, 0, 0);
    if (state == SVS_WFP_STATE_STOPPED) {
        return ERROR_SUCCESS;
    }
    if (state == SVS_WFP_STATE_STARTING) {
        return ERROR_BUSY;
    }
    InterlockedExchange(&g_state, SVS_WFP_STATE_STOPPING);

    if (g_engineHandle != nullptr && g_eventsHandle != nullptr) {
        const DWORD result = FwpmNetEventUnsubscribe0(g_engineHandle, g_eventsHandle);
        if (result != ERROR_SUCCESS) {
            InterlockedExchange(&g_lastError, static_cast<LONG>(result));
            InterlockedExchange(&g_state, SVS_WFP_STATE_FAILED);
            return result;
        }
        g_eventsHandle = nullptr;
    }

    const ULONGLONG deadline = GetTickCount64() + 5000;
    while (InterlockedCompareExchange(&g_callbackCount, 0, 0) != 0) {
        if (GetTickCount64() >= deadline) {
            InterlockedExchange(&g_lastError, ERROR_TIMEOUT);
            return ERROR_TIMEOUT;
        }
        Sleep(1);
    }

    if (g_engineHandle != nullptr) {
        const DWORD result = FwpmEngineClose0(g_engineHandle);
        if (result != ERROR_SUCCESS) {
            InterlockedExchange(&g_lastError, static_cast<LONG>(result));
            InterlockedExchange(&g_state, SVS_WFP_STATE_FAILED);
            return result;
        }
        g_engineHandle = nullptr;
    }
    InterlockedExchange(&g_lastError, ERROR_SUCCESS);
    InterlockedExchange(&g_state, SVS_WFP_STATE_STOPPED);
    return ERROR_SUCCESS;
}

extern "C" DWORD WINAPI SvsWfpReadNext(
    SVS_WFP_EVENT_RECORD* output,
    std::uint32_t outputSize
) {
    if (output == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    if (outputSize < sizeof(SVS_WFP_EVENT_RECORD)) {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    if (!TryAcquireSRWLockExclusive(&g_queueLock)) {
        return ERROR_BUSY;
    }
    if (g_head == g_tail) {
        ReleaseSRWLockExclusive(&g_queueLock);
        return ERROR_NO_MORE_ITEMS;
    }
    *output = g_queue[g_head % SVS_WFP_QUEUE_CAPACITY];
    ++g_head;
    InterlockedDecrement(&g_queued);
    ReleaseSRWLockExclusive(&g_queueLock);
    return ERROR_SUCCESS;
}

extern "C" DWORD WINAPI SvsWfpGetStats(SVS_WFP_STATS_RECORD* output) {
    if (output == nullptr || output->size < sizeof(SVS_WFP_STATS_RECORD)) {
        return ERROR_INVALID_PARAMETER;
    }
    if (output->version != SVS_WFP_STATS_ABI_VERSION) {
        return ERROR_REVISION_MISMATCH;
    }
    output->size = sizeof(SVS_WFP_STATS_RECORD);
    output->state = static_cast<std::uint32_t>(InterlockedCompareExchange(&g_state, 0, 0));
    output->queued = static_cast<std::uint32_t>(InterlockedCompareExchange(&g_queued, 0, 0));
    output->lastSequence = static_cast<std::uint64_t>(InterlockedCompareExchange64(&g_sequence, 0, 0));
    output->dropped = static_cast<std::uint64_t>(InterlockedCompareExchange64(&g_dropped, 0, 0));
    output->lastError = static_cast<std::uint32_t>(InterlockedCompareExchange(&g_lastError, 0, 0));
    return ERROR_SUCCESS;
}

#if defined(SVS_WFP_TESTING)
DWORD SvsWfpTestNormalize(const FWPM_NET_EVENT4* event, SVS_WFP_EVENT_RECORD* output) {
    if (!NormalizeNetEvent(event, output)) {
        return ERROR_NOT_SUPPORTED;
    }
    return ERROR_SUCCESS;
}

void SvsWfpTestResetQueue() {
    ResetQueueAndCounters();
}

DWORD SvsWfpTestEnqueue(const FWPM_NET_EVENT4* event) {
    if (event == nullptr) {
        return ERROR_INVALID_PARAMETER;
    }
    PublishEvent(event);
    return ERROR_SUCCESS;
}

DWORD SvsWfpTestReadNext(SVS_WFP_EVENT_RECORD* output, std::uint32_t outputSize) {
    return SvsWfpReadNext(output, outputSize);
}

DWORD SvsWfpTestHoldQueueLock(BOOL hold) {
    if (hold) {
        return TryAcquireSRWLockExclusive(&g_queueLock) ? ERROR_SUCCESS : ERROR_BUSY;
    }
    ReleaseSRWLockExclusive(&g_queueLock);
    return ERROR_SUCCESS;
}

void SvsWfpTestGetCounters(std::uint64_t* sequence, std::uint64_t* dropped) {
    if (sequence != nullptr) {
        *sequence = static_cast<std::uint64_t>(InterlockedCompareExchange64(&g_sequence, 0, 0));
    }
    if (dropped != nullptr) {
        *dropped = static_cast<std::uint64_t>(InterlockedCompareExchange64(&g_dropped, 0, 0));
    }
}
#endif
