package com.svscyber.mobile

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.CancellationSignal
import android.os.SystemClock
import java.io.File
import java.security.MessageDigest

/** Reads inert selected content. Never extracts, loads code, installs or uploads. */
class AndroidSelectedFileInspector(private val context: Context) {
    fun inspect(uri: Uri, apk: Boolean, cancellation: CancellationSignal,
                reportBytesRead: (Long) -> Unit): Map<String, Any?> {
        require(uri.scheme == "content")
        val started = SystemClock.elapsedRealtime()
        var bytesRead = 0L
        var temporary: File? = null
        var contentType: String? = null
        fun response(status: String, hash: String? = null,
                     metadata: Map<String, Any?>? = null, truncated: Boolean = false) = mapOf(
            "contractVersion" to NativeEvent.CONTRACT_VERSION,
            "apkRequested" to apk,
            "status" to status,
            "contentType" to contentType,
            "byteSize" to if (hash != null) bytesRead else null,
            "bytesRead" to bytesRead,
            "maxBytes" to MAX_BYTES,
            "sha256" to hash,
            "apkMetadata" to metadata,
            "metadataTruncated" to truncated,
        )
        try {
            cancellation.throwIfCanceled()
            contentType = boundedText(context.contentResolver.getType(uri), 255)
            if (apk) temporary = File.createTempFile("selected-apk-", ".apk", context.cacheDir)
            val digest = MessageDigest.getInstance("SHA-256")
            // The descriptor's temporary read grant is never persisted. Its
            // cancellation signal also interrupts cooperative document providers.
            val descriptor = context.contentResolver.openAssetFileDescriptor(uri, "r", cancellation)
                ?: throw java.io.IOException("Document is inaccessible")
            cancellation.setOnCancelListener {
                try { descriptor.close() } catch (_: Exception) { }
            }
            descriptor.use { asset ->
                asset.createInputStream().use { input ->
                    val output = temporary?.outputStream()
                    try {
                        val buffer = ByteArray(32 * 1024)
                        while (true) {
                            cancellation.throwIfCanceled()
                            if (SystemClock.elapsedRealtime() - started >= TIMEOUT_MS) return response("timedOut")
                            val allowed = minOf(buffer.size.toLong(), MAX_BYTES + 1 - bytesRead).toInt()
                            val count = input.read(buffer, 0, allowed)
                            if (count < 0) break
                            if (count == 0) continue
                            bytesRead += count
                            reportBytesRead(bytesRead)
                            if (bytesRead > MAX_BYTES) return response("overLimit")
                            digest.update(buffer, 0, count)
                            output?.write(buffer, 0, count)
                        }
                    } finally {
                        output?.close()
                    }
                }
            }
            cancellation.setOnCancelListener(null)
            cancellation.throwIfCanceled()
            val hash = hex(digest.digest())
            if (SystemClock.elapsedRealtime() - started >= TIMEOUT_MS) return response("timedOut")
            if (!apk) return response("complete", hash)
            val parsed = try {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageArchiveInfo(
                    temporary!!.absolutePath,
                    PackageManager.GET_PERMISSIONS or PackageManager.GET_SIGNING_CERTIFICATES,
                )
            } catch (_: RuntimeException) { null }
            cancellation.throwIfCanceled()
            if (SystemClock.elapsedRealtime() - started >= TIMEOUT_MS) return response("timedOut")
            val packageName = boundedText(parsed?.packageName, 255)
            if (parsed == null || packageName == null || parsed.longVersionCode < 0) return response("unsupported", hash)
            var truncated = false
            val permissions = mutableListOf<String>()
            for (permission in parsed.requestedPermissions.orEmpty().take(MAX_PERMISSIONS)) {
                val bounded = boundedText(permission, 255)
                if (bounded != null) permissions.add(bounded) else truncated = true
            }
            if (parsed.requestedPermissions.orEmpty().size > MAX_PERMISSIONS) truncated = true
            val signers = parsed.signingInfo?.apkContentsSigners.orEmpty()
            if (signers.size > MAX_SIGNERS) truncated = true
            val certificates = signers.take(MAX_SIGNERS).mapNotNull {
                val encoded = it.toByteArray()
                if (encoded.size > MAX_CERTIFICATE_BYTES) {
                    truncated = true
                    null
                } else {
                    hex(MessageDigest.getInstance("SHA-256").digest(encoded))
                }
            }
            val version = boundedText(parsed.versionName, 255)
            if (parsed.versionName != null && version == null) truncated = true
            return response("complete", hash, mapOf(
                "packageName" to packageName,
                "versionName" to version,
                "versionCode" to parsed.longVersionCode,
                "requestedPermissions" to permissions,
                // A signer fingerprint identifies observed certificate bytes;
                // it does not establish trust or a clean/safe verdict.
                "signatureStatus" to if (certificates.isEmpty()) "unknown" else "available",
                "certificateSha256" to certificates,
            ), truncated)
        } finally {
            cancellation.setOnCancelListener(null)
            // Also runs for revoked grants, parser errors, cancellation and limits.
            // Fail closed if cache cleanup cannot be confirmed.
            temporary?.let { if (it.exists() && !it.delete()) throw java.io.IOException("Cache cleanup failed") }
        }
    }

    private fun boundedText(value: String?, limit: Int): String? =
        value?.takeIf { it.isNotEmpty() && it.length <= limit && it.none { c -> c.code < 32 || c.code == 127 } }

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    companion object {
        const val MAX_BYTES = 64L * 1024 * 1024
        const val TIMEOUT_MS = 15_000L
        private const val MAX_PERMISSIONS = 256
        private const val MAX_SIGNERS = 16
        private const val MAX_CERTIFICATE_BYTES = 64 * 1024
    }
}
