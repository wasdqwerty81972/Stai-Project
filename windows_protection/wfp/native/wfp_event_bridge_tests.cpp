#define WIN32_LEAN_AND_MEAN
#include "wfp_event_bridge.h"

#include <cstdio>
#include <cstring>

namespace {

int Fail(const char* message) {
    std::fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

FWPM_NET_EVENT4 MakeAllowEvent(FWPM_NET_EVENT_CLASSIFY_ALLOW0* classify) {
    FWPM_NET_EVENT4 event = {};
    event.type = FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW;
    event.classifyAllow = classify;
    classify->layerId = 48;
    classify->msFwpDirection = FWP_DIRECTION_OUTBOUND;
    classify->isLoopback = FALSE;
    return event;
}

int TestNormalizationHonorsFlags() {
    FWPM_NET_EVENT_CLASSIFY_ALLOW0 classify = {};
    FWPM_NET_EVENT4 event = MakeAllowEvent(&classify);
    event.header.flags = FWPM_NET_EVENT_FLAG_IP_VERSION_SET |
        FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET |
        FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET |
        FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET |
        FWPM_NET_EVENT_FLAG_APP_ID_SET |
        FWPM_NET_EVENT_FLAG_REAUTH_REASON_SET;
    event.header.ipVersion = FWP_IP_VERSION_V4;
    event.header.ipProtocol = 17;
    event.header.localPort = 5353;
    const BYTE address[4] = {192, 0, 2, 42};
    std::memcpy(&event.header.localAddrV4, address, sizeof(address));
    const BYTE appId[3] = {0x41, 0x00, 0x42};
    event.header.appId.size = sizeof(appId);
    event.header.appId.data = const_cast<BYTE*>(appId);
    classify.reauthReason = 9;

    SVS_WFP_EVENT_RECORD normalized = {};
    if (SvsWfpTestNormalize(&event, &normalized) != ERROR_SUCCESS) {
        return Fail("valid classify event was rejected");
    }
    if (normalized.eventType != SVS_WFP_EVENT_CLASSIFY_ALLOW ||
        normalized.ipVersion != 4 || normalized.protocol != 17 ||
        normalized.localPort != 5353 || normalized.appIdLength != sizeof(appId) ||
        std::memcmp(normalized.localAddress, address, sizeof(address)) != 0) {
        return Fail("flagged event values were not copied");
    }
    if ((normalized.fieldFlags & SVS_WFP_FIELD_REMOTE_ADDRESS) != 0 ||
        (normalized.fieldFlags & SVS_WFP_FIELD_REMOTE_PORT) != 0 ||
        (normalized.fieldFlags & SVS_WFP_FIELD_USER_SID) != 0 ||
        (normalized.fieldFlags & SVS_WFP_FIELD_REAUTH_REASON) == 0) {
        return Fail("missing or unflagged event fields were reported");
    }
    if ((normalized.fieldFlags & SVS_WFP_FIELD_LAYER) == 0 ||
        normalized.layerId != 48 || normalized.direction != SVS_WFP_DIRECTION_OUTBOUND ||
        normalized.isLoopback != 0) {
        return Fail("classify metadata was not normalized");
    }

    event.header.flags = FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET;
    event.header.ipVersion = FWP_IP_VERSION_V4;
    event.header.ipProtocol = 6;
    event.header.localPort = 1234;
    if (SvsWfpTestNormalize(&event, &normalized) != ERROR_SUCCESS) {
        return Fail("classify event with sparse flags was rejected");
    }
    if ((normalized.fieldFlags & (SVS_WFP_FIELD_IP_VERSION |
            SVS_WFP_FIELD_LOCAL_ADDRESS | SVS_WFP_FIELD_PROTOCOL |
            SVS_WFP_FIELD_LOCAL_PORT | SVS_WFP_FIELD_APP_ID)) != 0) {
        return Fail("unflagged or contextless fields were exposed");
    }
    return 0;
}

int TestUnsupportedEventIsIgnored() {
    FWPM_NET_EVENT4 event = {};
    event.type = FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE;
    SVS_WFP_EVENT_RECORD output = {};
    if (SvsWfpTestNormalize(&event, &output) != ERROR_NOT_SUPPORTED) {
        return Fail("unsupported event type was accepted");
    }
    return 0;
}

int TestQueueIsBoundedAndReportsDrops() {
    SvsWfpTestResetQueue();
    FWPM_NET_EVENT_CLASSIFY_ALLOW0 classify = {};
    FWPM_NET_EVENT4 event = MakeAllowEvent(&classify);
    for (std::uint32_t index = 0; index < SVS_WFP_QUEUE_CAPACITY + 3; ++index) {
        if (SvsWfpTestEnqueue(&event) != ERROR_SUCCESS) {
            return Fail("synthetic enqueue unexpectedly failed");
        }
    }
    std::uint64_t sequence = 0;
    std::uint64_t dropped = 0;
    SvsWfpTestGetCounters(&sequence, &dropped);
    if (sequence != SVS_WFP_QUEUE_CAPACITY + 3 || dropped != 3) {
        return Fail("queue capacity or drop accounting is incorrect");
    }
    for (std::uint32_t index = 1; index <= SVS_WFP_QUEUE_CAPACITY; ++index) {
        SVS_WFP_EVENT_RECORD record = {};
        if (SvsWfpTestReadNext(&record, sizeof(record)) != ERROR_SUCCESS ||
            record.sequence != index) {
            return Fail("queued records are missing or out of order");
        }
    }
    SVS_WFP_EVENT_RECORD empty = {};
    if (SvsWfpTestReadNext(&empty, sizeof(empty)) != ERROR_NO_MORE_ITEMS) {
        return Fail("queue should be empty after draining");
    }
    return 0;
}

int TestCallbackQueueAttemptDoesNotWaitForConsumer() {
    SvsWfpTestResetQueue();
    FWPM_NET_EVENT_CLASSIFY_ALLOW0 classify = {};
    FWPM_NET_EVENT4 event = MakeAllowEvent(&classify);
    if (SvsWfpTestHoldQueueLock(TRUE) != ERROR_SUCCESS) {
        return Fail("could not hold synthetic queue lock");
    }
    const DWORD enqueueResult = SvsWfpTestEnqueue(&event);
    const DWORD releaseResult = SvsWfpTestHoldQueueLock(FALSE);
    std::uint64_t dropped = 0;
    SvsWfpTestGetCounters(nullptr, &dropped);
    if (enqueueResult != ERROR_SUCCESS || releaseResult != ERROR_SUCCESS || dropped != 1) {
        return Fail("producer did not drop immediately on lock contention");
    }
    return 0;
}

}  // namespace

int main() {
    if (TestNormalizationHonorsFlags() != 0 ||
        TestUnsupportedEventIsIgnored() != 0 ||
        TestQueueIsBoundedAndReportsDrops() != 0 ||
        TestCallbackQueueAttemptDoesNotWaitForConsumer() != 0) {
        return 1;
    }
    std::puts("WFP event bridge synthetic tests passed.");
    return 0;
}
