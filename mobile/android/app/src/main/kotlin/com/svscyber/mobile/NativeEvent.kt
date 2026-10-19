package com.svscyber.mobile

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/** Versioned, normalized observation stored before it is sent to Flutter. */
data class NativeEvent(
    val eventId: String = UUID.randomUUID().toString(),
    val capabilityId: String,
    val eventType: String = "observation",
    val occurredAtEpochMs: Long,
    val observedAtEpochMs: Long,
    val availability: String,
    val operation: String,
    val freshness: String,
    val evidence: Map<String, Any?>,
) {
    fun toChannelMap(): Map<String, Any?> = mapOf(
        "contractVersion" to CONTRACT_VERSION,
        "eventId" to eventId,
        "capabilityId" to capabilityId,
        "eventType" to eventType,
        "occurredAtEpochMs" to occurredAtEpochMs,
        "observedAtEpochMs" to observedAtEpochMs,
        "availability" to availability,
        "operation" to operation,
        "freshness" to freshness,
        "continuous" to false,
        "evidence" to evidence,
    )

    fun toJsonLine(): String = JSONObject(toChannelMap()).toString()

    companion object {
        const val CONTRACT_VERSION = 1

        fun fromJsonLine(line: String): Map<String, Any?>? = try {
            val record = JSONObject(line)
            require(record.get("contractVersion") == CONTRACT_VERSION)
            require(record.get("continuous") == false)
            require(record.get("eventId") is String && record.getString("eventId").isNotBlank())
            require(record.get("capabilityId") is String && Regex("AND-\\d{3}").matches(record.getString("capabilityId")))
            for (field in listOf("eventType", "availability", "operation", "freshness")) {
                require(record.get(field) is String && record.getString(field).isNotBlank())
            }
            for (field in listOf("occurredAtEpochMs", "observedAtEpochMs")) {
                require(record.get(field) is Long || record.get(field) is Int)
            }
            require(record.get("evidence") is JSONObject)
            record.toChannelValue()
        } catch (_: Exception) {
            null
        }
    }
}

private fun JSONObject.toChannelValue(): Map<String, Any?> {
    val result = linkedMapOf<String, Any?>()
    val keys = keys()
    while (keys.hasNext()) {
        val key = keys.next()
        result[key] = get(key).toChannelValue()
    }
    return result
}

private fun Any?.toChannelValue(): Any? = when (this) {
    JSONObject.NULL -> null
    is JSONObject -> toChannelValue()
    is JSONArray -> (0 until length()).map { get(it).toChannelValue() }
    else -> this
}
