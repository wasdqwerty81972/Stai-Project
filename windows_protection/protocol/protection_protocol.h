#ifndef STAI_PROTECTION_PROTOCOL_H
#define STAI_PROTECTION_PROTOCOL_H

#include <stdint.h>

#define STAI_PROTOCOL_VERSION 1
#define STAI_MAX_PATH_UTF16_CHARS 32767
#define STAI_MAX_PAYLOAD_SIZE (64 * 1024)
#define STAI_PORT_NAME L"\\STAIProtectionPort"

typedef enum {
    STAI_OP_CREATE = 1,
    STAI_OP_IMAGE_MAPPING = 2,
} StaiOperation;

typedef enum {
    STAI_VERDICT_ALLOW = 0,
    STAI_VERDICT_BLOCK = 1,
    STAI_VERDICT_UNKNOWN = 2,
} StaiVerdict;

#pragma pack(push, 1)
typedef struct {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t operation;
    uint32_t path_len;
    wchar_t path[];
} StaiRequest;

typedef struct {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t verdict;
    uint32_t rule_id_len;
    wchar_t rule_id[];
} StaiReply;

typedef struct {
    uint32_t size;
    uint32_t version;
    uint64_t request_id;
    uint32_t final_io_status;
} StaiCompletion;
#pragma pack(pop)

#define STAI_REQUEST_MIN_SIZE (sizeof(StaiRequest))
#define STAI_REPLY_MIN_SIZE (sizeof(StaiReply))
#define STAI_COMPLETION_SIZE (sizeof(StaiCompletion))

static inline int stai_validate_request(const StaiRequest* req, uint32_t payload_size) {
    if (!req) return 0;
    if (req->version != STAI_PROTOCOL_VERSION) return 0;
    if (req->size != payload_size) return 0;
    if (req->size > STAI_MAX_PAYLOAD_SIZE) return 0;
    if (req->operation != STAI_OP_CREATE && req->operation != STAI_OP_IMAGE_MAPPING) return 0;
    if (req->path_len > STAI_MAX_PATH_UTF16_CHARS) return 0;
    return 1;
}

static inline int stai_validate_reply(const StaiReply* reply, uint32_t payload_size) {
    if (!reply) return 0;
    if (reply->version != STAI_PROTOCOL_VERSION) return 0;
    if (reply->size != payload_size) return 0;
    if (reply->size > STAI_MAX_PAYLOAD_SIZE) return 0;
    if (reply->verdict > STAI_VERDICT_UNKNOWN) return 0;
    return 1;
}

static inline int stai_validate_completion(const StaiCompletion* completion, uint32_t payload_size) {
    if (!completion) return 0;
    if (completion->version != STAI_PROTOCOL_VERSION) return 0;
    if (completion->size != payload_size) return 0;
    if (completion->size != STAI_COMPLETION_SIZE) return 0;
    return 1;
}

#endif