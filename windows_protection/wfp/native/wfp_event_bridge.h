#pragma once

#include <windows.h>
#include <fwpmu.h>
#include <cstdint>

constexpr std::uint32_t SVS_WFP_EVENT_ABI_VERSION = 1;
constexpr std::uint32_t SVS_WFP_STATS_ABI_VERSION = 1;
constexpr std::uint32_t SVS_WFP_QUEUE_CAPACITY = 256;
constexpr std::uint32_t SVS_WFP_APP_ID_MAX_BYTES = 256;
constexpr std::uint32_t SVS_WFP_SID_MAX_BYTES = 68;

enum SVS_WFP_EVENT_FIELD : std::uint32_t {
    SVS_WFP_FIELD_TIMESTAMP = 1U << 0,
    SVS_WFP_FIELD_IP_VERSION = 1U << 1,
    SVS_WFP_FIELD_PROTOCOL = 1U << 2,
    SVS_WFP_FIELD_LOCAL_ADDRESS = 1U << 3,
    SVS_WFP_FIELD_REMOTE_ADDRESS = 1U << 4,
    SVS_WFP_FIELD_LOCAL_PORT = 1U << 5,
    SVS_WFP_FIELD_REMOTE_PORT = 1U << 6,
    SVS_WFP_FIELD_APP_ID = 1U << 7,
    SVS_WFP_FIELD_USER_SID = 1U << 8,
    SVS_WFP_FIELD_DIRECTION = 1U << 9,
    SVS_WFP_FIELD_LAYER = 1U << 10,
    SVS_WFP_FIELD_LOOPBACK = 1U << 11,
    SVS_WFP_FIELD_REAUTH_REASON = 1U << 12,
    SVS_WFP_FIELD_APP_ID_TRUNCATED = 1U << 13,
    SVS_WFP_FIELD_USER_SID_TRUNCATED = 1U << 14,
};

enum SVS_WFP_EVENT_KIND : std::uint32_t {
    SVS_WFP_EVENT_CLASSIFY_ALLOW = 1,
    SVS_WFP_EVENT_CLASSIFY_DROP = 2,
};

enum SVS_WFP_DIRECTION : std::uint32_t {
    SVS_WFP_DIRECTION_UNKNOWN = 0,
    SVS_WFP_DIRECTION_INBOUND = 1,
    SVS_WFP_DIRECTION_OUTBOUND = 2,
};

enum SVS_WFP_STATE : std::uint32_t {
    SVS_WFP_STATE_STOPPED = 0,
    SVS_WFP_STATE_STARTING = 1,
    SVS_WFP_STATE_RUNNING = 2,
    SVS_WFP_STATE_STOPPING = 3,
    SVS_WFP_STATE_FAILED = 4,
};

#pragma pack(push, 1)
struct SVS_WFP_EVENT_RECORD {
    std::uint32_t size;
    std::uint32_t version;
    std::uint64_t sequence;
    std::uint64_t timestampFiletime;
    std::uint32_t fieldFlags;
    std::uint32_t eventType;
    std::uint32_t ipVersion;
    std::uint32_t protocol;
    std::uint32_t direction;
    std::uint32_t layerId;
    std::uint32_t reauthReason;
    std::uint32_t isLoopback;
    std::uint16_t localPort;
    std::uint16_t remotePort;
    std::uint8_t localAddress[16];
    std::uint8_t remoteAddress[16];
    std::uint32_t appIdLength;
    std::uint8_t appId[SVS_WFP_APP_ID_MAX_BYTES];
    std::uint32_t userSidLength;
    std::uint8_t userSid[SVS_WFP_SID_MAX_BYTES];
};

struct SVS_WFP_STATS_RECORD {
    std::uint32_t size;
    std::uint32_t version;
    std::uint32_t state;
    std::uint32_t queued;
    std::uint64_t lastSequence;
    std::uint64_t dropped;
    std::uint32_t lastError;
};
#pragma pack(pop)

static_assert(sizeof(SVS_WFP_EVENT_RECORD) == 424, "WFP event ABI changed");
static_assert(sizeof(SVS_WFP_STATS_RECORD) == 36, "WFP stats ABI changed");

#if defined(SVS_WFP_TESTING)
DWORD SvsWfpTestNormalize(const FWPM_NET_EVENT4* event, SVS_WFP_EVENT_RECORD* output);
void SvsWfpTestResetQueue();
DWORD SvsWfpTestEnqueue(const FWPM_NET_EVENT4* event);
DWORD SvsWfpTestReadNext(SVS_WFP_EVENT_RECORD* output, std::uint32_t outputSize);
DWORD SvsWfpTestHoldQueueLock(BOOL hold);
void SvsWfpTestGetCounters(std::uint64_t* sequence, std::uint64_t* dropped);
#endif

extern "C" {
__declspec(dllexport) DWORD WINAPI SvsWfpStart();
__declspec(dllexport) DWORD WINAPI SvsWfpStop();
__declspec(dllexport) DWORD WINAPI SvsWfpReadNext(
    SVS_WFP_EVENT_RECORD* output,
    std::uint32_t outputSize
);
__declspec(dllexport) DWORD WINAPI SvsWfpGetStats(SVS_WFP_STATS_RECORD* output);
}
