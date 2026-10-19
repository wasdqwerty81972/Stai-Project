package com.svscyber.mobile

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.app.KeyguardManager
import android.os.Build
import android.os.PowerManager
import java.io.File

/** One-shot, permission-free baseline. This class does not start a monitor or background service. */
class AndroidDeviceBaselineCollector(private val context: Context) {
    fun collect(): List<NativeEvent> {
        val now = System.currentTimeMillis()
        return listOf(
            observation("AND-001", now, mapOf("release" to Build.VERSION.RELEASE, "sdkInt" to Build.VERSION.SDK_INT)),
            securityPatch(now),
            observation("AND-003", now, mapOf("manufacturer" to Build.MANUFACTURER)),
            observation("AND-004", now, mapOf("model" to Build.MODEL)),
            secureLock(now),
            battery(now),
            storage(now),
            thermal(now),
        )
    }

    private fun observation(id: String, now: Long, evidence: Map<String, Any?>) = NativeEvent(
        capabilityId = id,
        occurredAtEpochMs = now,
        observedAtEpochMs = now,
        availability = "available",
        operation = "completed",
        freshness = "fresh",
        evidence = evidence,
    )

    private fun unavailable(id: String, now: Long, reason: String, unsupported: Boolean = false) = NativeEvent(
        capabilityId = id,
        occurredAtEpochMs = now,
        observedAtEpochMs = now,
        availability = if (unsupported) "unsupported" else "temporarily_unavailable",
        operation = "failed",
        freshness = "unknown",
        evidence = mapOf("reason" to reason),
    )

    private fun failed(id: String, now: Long, error: Exception) = NativeEvent(
        capabilityId = id,
        occurredAtEpochMs = now,
        observedAtEpochMs = now,
        availability = "temporarily_unavailable",
        operation = "failed",
        freshness = "unknown",
        evidence = mapOf("errorType" to error.javaClass.simpleName),
    )

    private fun securityPatch(now: Long): NativeEvent {
        val patch = Build.VERSION.SECURITY_PATCH
        return if (patch.isBlank() || patch == Build.UNKNOWN) {
            unavailable("AND-002", now, "security_patch_unavailable")
        } else {
            observation("AND-002", now, mapOf("securityPatch" to patch))
        }
    }

    private fun secureLock(now: Long): NativeEvent {
        return try {
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            if (keyguard == null) unavailable("AND-008", now, "keyguard_service_unavailable")
            else observation("AND-008", now, mapOf("secureLockConfigured" to keyguard.isDeviceSecure))
        } catch (error: Exception) {
            failed("AND-008", now, error)
        }
    }

    private fun battery(now: Long): NativeEvent {
        return try {
            val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
            if (intent == null) unavailable("AND-113", now, "battery_state_unavailable")
            else {
                val level = intent.getIntExtra("level", -1)
                val scale = intent.getIntExtra("scale", -1)
                if (level < 0 || scale <= 0 || level > scale) unavailable("AND-113", now, "battery_level_unavailable")
                else observation("AND-113", now, mapOf("percent" to (level.toLong() * 100 / scale).toInt()))
            }
        } catch (error: Exception) {
            failed("AND-113", now, error)
        }
    }

    private fun storage(now: Long): NativeEvent {
        return try {
            val bytes = File(context.filesDir.absolutePath).usableSpace
            observation("AND-116", now, mapOf("appDataVolumeUsableBytes" to bytes))
        } catch (error: Exception) {
            failed("AND-116", now, error)
        }
    }

    private fun thermal(now: Long): NativeEvent {
        return try {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) unavailable("AND-115", now, "requires_api_29", unsupported = true)
            else {
                val power = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
                if (power == null) unavailable("AND-115", now, "power_service_unavailable")
                else observation("AND-115", now, mapOf("thermalStatus" to power.currentThermalStatus))
            }
        } catch (error: Exception) {
            failed("AND-115", now, error)
        }
    }
}
