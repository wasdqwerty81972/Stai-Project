#ifndef STAI_PROTECTION_PROTOCOL_H
#define STAI_PROTECTION_PROTOCOL_H

#include <stdint.h>

#define STAI_PROTOCOL_VERSION 2U
#define STAI_MAX_PATH_UTF16_CHARS 32767U
#define STAI_MAX_RULE_ID_UTF16_CHARS 255U
#define STAI_MAX_RULE_VERSION_UTF16_CHARS 63U
#define STAI_MAX_PAYLOAD_SIZE (64U * 1024U)
#define STAI_PORT_NAME L"\\STAIProtectionPort"

#define STAI_REQUEST_HEADER_SIZE 40U
#define STAI_REPLY_HEADER_SIZE 26U
#define STAI_COMPLETION_SIZE 20U

typedef enum {
    STAI_OP_CREATE = 1,
    STAI_OP_IMAGE_MAPPING = 2,
    STAI_OP_WRITE = 3,
} STAI_OPERATION;

typedef enum {
    STAI_VERDICT_ALLOW = 0,
    STAI_VERDICT_BLOCK = 1,
    STAI_VERDICT_UNKNOWN = 2,
} STAI_VERDICT;

/* All protocol fields are little-endian and packed without C padding. */
#pragma pack(push, 1)
typedef struct _STAI_REQUEST {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t operation;
    uint64_t process_id;
    uint64_t thread_id;
    uint32_t path_len;
    uint16_t path[1];
} STAI_REQUEST, *PSTAI_REQUEST;

typedef struct _STAI_REPLY {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t verdict;
    uint32_t rule_id_len;
    uint16_t rule_version_len;
    uint16_t strings[1];
} STAI_REPLY, *PSTAI_REPLY;

typedef struct _STAI_COMPLETION {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t final_io_status;
} STAI_COMPLETION, *PSTAI_COMPLETION;
#pragma pack(pop)

static __inline int stai_has_no_nul(const uint16_t* text, uint32_t length) {
    uint32_t index;
    for (index = 0; index < length; ++index) {
        if (text[index] == 0) return 0;
    }
    return 1;
}

static __inline int stai_validate_request(const STAI_REQUEST* request, uint32_t payload_size) {
    uint32_t expected_size;
    if (!request || payload_size < STAI_REQUEST_HEADER_SIZE) return 0;
    if (request->version != STAI_PROTOCOL_VERSION) return 0;
    if (request->size != payload_size || request->size > STAI_MAX_PAYLOAD_SIZE) return 0;
    if (request->request_id == 0) return 0;
    if (request->operation != STAI_OP_CREATE &&
        request->operation != STAI_OP_IMAGE_MAPPING &&
        request->operation != STAI_OP_WRITE) return 0;
    if (request->path_len > STAI_MAX_PATH_UTF16_CHARS) return 0;
    expected_size = STAI_REQUEST_HEADER_SIZE + request->path_len * sizeof(uint16_t);
    if (expected_size != payload_size) return 0;
    return stai_has_no_nul(request->path, request->path_len);
}

static __inline int stai_validate_reply(const STAI_REPLY* reply, uint32_t payload_size) {
    uint32_t string_units;
    uint32_t expected_size;
    const uint16_t* rule_id;
    const uint16_t* rule_version;
    if (!reply || payload_size < STAI_REPLY_HEADER_SIZE) return 0;
    if (reply->version != STAI_PROTOCOL_VERSION) return 0;
    if (reply->size != payload_size || reply->size > STAI_MAX_PAYLOAD_SIZE) return 0;
    if (reply->request_id == 0 || reply->verdict > STAI_VERDICT_UNKNOWN) return 0;
    if (reply->rule_id_len > STAI_MAX_RULE_ID_UTF16_CHARS) return 0;
    if (reply->rule_version_len > STAI_MAX_RULE_VERSION_UTF16_CHARS) return 0;
    if (reply->verdict == STAI_VERDICT_BLOCK &&
        (reply->rule_id_len == 0 || reply->rule_version_len == 0)) return 0;
    string_units = reply->rule_id_len + reply->rule_version_len;
    expected_size = STAI_REPLY_HEADER_SIZE + string_units * sizeof(uint16_t);
    if (expected_size != payload_size) return 0;
    rule_id = reply->strings;
    rule_version = reply->strings + reply->rule_id_len;
    return stai_has_no_nul(rule_id, reply->rule_id_len) &&
           stai_has_no_nul(rule_version, reply->rule_version_len);
}

static __inline int stai_validate_completion(const STAI_COMPLETION* completion, uint32_t payload_size) {
    if (!completion) return 0;
    if (payload_size != STAI_COMPLETION_SIZE || completion->size != STAI_COMPLETION_SIZE) return 0;
    if (completion->version != STAI_PROTOCOL_VERSION || completion->request_id == 0) return 0;
    return 1;
}

#endif
