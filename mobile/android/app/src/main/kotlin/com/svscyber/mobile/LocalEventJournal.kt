package com.svscyber.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** App-private durable event journal. Implementations must finish append before delivery. */
interface LocalEventJournal {
    @Throws(IOException::class)
    fun append(event: NativeEvent)

    @Throws(IOException::class)
    fun read(afterEpochMs: Long?, limit: Int): List<Map<String, Any?>>

    fun status(): JournalStatus
}

data class JournalStatus(
    val available: Boolean,
    val eventCount: Int,
    val sizeBytes: Long,
    val encryptedAtRest: Boolean,
    val retentionDays: Int,
    val maxBytes: Long,
    val warning: String?,
)

/** JSON Lines journal in internal app storage; no storage permission or external path is used. */
class JsonLinesLocalEventJournal(context: Context) : LocalEventJournal {
    private val directory = File(context.filesDir, "mobile-events")
    private val journalFile = File(directory, "events-v1.jsonl")
    private val keyAlias = "svscyber.mobile.event-journal.v1"
    private val maxBytes = 8L * 1024L * 1024L
    private val retainForMs = 30L * 24L * 60L * 60L * 1000L
    private val compactionIntervalMs = 6L * 60L * 60L * 1000L
    private var lastCompactionEpochMs = 0L

    @Synchronized
    override fun append(event: NativeEvent) {
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Could not create the private event-journal directory")
        }
        val plain = event.toJsonLine()
        if (NativeEvent.fromJsonLine(plain) == null) throw IOException("Invalid native event contract")
        val line = try {
            encrypt(plain.toByteArray(Charsets.UTF_8)) + "\n"
        } catch (error: Exception) {
            throw IOException("Could not encrypt an event-journal record", error)
        }
        if (line.toByteArray(Charsets.UTF_8).size > maxBytes) {
            throw IOException("Event is larger than the event journal capacity")
        }
        compactExpiredIfDue(force = journalFile.length() + line.toByteArray(Charsets.UTF_8).size > maxBytes)
        if (journalFile.length() + line.toByteArray(Charsets.UTF_8).size > maxBytes) {
            throw IOException("Event journal is full; older retained events were preserved")
        }
        FileOutputStream(journalFile, true).use { output ->
            output.write(line.toByteArray(Charsets.UTF_8))
            output.flush()
            output.fd.sync()
        }
    }

    @Synchronized
    override fun read(afterEpochMs: Long?, limit: Int): List<Map<String, Any?>> {
        if (!journalFile.exists() || limit <= 0) return emptyList()
        compactExpiredIfDue()
        val cutoff = System.currentTimeMillis() - retainForMs
        val key = getOrCreateKey()
        val result = ArrayList<Map<String, Any?>>(minOf(limit, 128))
        journalFile.bufferedReader(Charsets.UTF_8).useLines { lines ->
            lines.forEach { line ->
                if (result.size >= limit) return@forEach
                val plain = try {
                    decrypt(line, key)
                } catch (error: Exception) {
                    throw IOException("Could not decrypt an event-journal record", error)
                }
                val event = NativeEvent.fromJsonLine(plain)
                    ?: throw IOException("Malformed event-journal record")
                val observedAt = (event["observedAtEpochMs"] as? Number)?.toLong()
                    ?: throw IOException("Event-journal record has no observation timestamp")
                if (observedAt >= cutoff && (afterEpochMs == null || observedAt > afterEpochMs)) result.add(event)
            }
        }
        return result
    }

    @Synchronized
    override fun status(): JournalStatus {
        return try {
            val key = getOrCreateKey()
            compactExpiredIfDue()
            val count = if (!journalFile.exists()) 0 else journalFile.useLines { lines ->
                lines.count { line ->
                    if (NativeEvent.fromJsonLine(decrypt(line, key)) == null) {
                        throw IOException("Malformed event-journal record")
                    }
                    true
                }
            }
            val size = journalFile.length()
            val writable = if (directory.exists()) {
                directory.isDirectory && directory.canWrite() && (!journalFile.exists() || journalFile.canWrite())
            } else {
                directory.parentFile?.canWrite() == true
            }
            JournalStatus(
                available = writable && size < maxBytes,
                eventCount = count,
                sizeBytes = size,
                encryptedAtRest = true,
                retentionDays = 30,
                maxBytes = maxBytes,
                warning = when {
                    !writable -> "journal_unwritable"
                    size >= maxBytes -> "journal_full"
                    size > maxBytes * 9 / 10 -> "journal_near_capacity"
                    else -> null
                },
            )
        } catch (_: Exception) {
            JournalStatus(
                available = false,
                eventCount = -1,
                sizeBytes = journalFile.length(),
                encryptedAtRest = true,
                retentionDays = 30,
                maxBytes = maxBytes,
                warning = "keystore_or_journal_unavailable",
            )
        }
    }

    private fun compactExpired() {
        if (!journalFile.exists()) {
            lastCompactionEpochMs = System.currentTimeMillis()
            return
        }
        val cutoff = System.currentTimeMillis() - retainForMs
        val key = getOrCreateKey()
        val temp = File(directory, "events-v1.jsonl.tmp")
        try {
            FileOutputStream(temp, false).use { output ->
                journalFile.bufferedReader(Charsets.UTF_8).useLines { lines ->
                    lines.forEach { line ->
                        val plain = decrypt(line, key)
                        val event = NativeEvent.fromJsonLine(plain)
                            ?: throw IOException("Malformed event-journal record")
                        val time = (event["observedAtEpochMs"] as? Number)?.toLong()
                            ?: throw IOException("Event-journal record has no observation timestamp")
                        if (time >= cutoff) {
                            output.write((line + "\n").toByteArray(Charsets.UTF_8))
                        }
                    }
                }
                output.flush()
                output.fd.sync()
            }
            Files.move(
                temp.toPath(),
                journalFile.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE,
            )
            lastCompactionEpochMs = System.currentTimeMillis()
        } catch (error: Exception) {
            temp.delete()
            throw IOException("Could not compact the private event journal", error)
        }
    }

    private fun compactExpiredIfDue(force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (force || lastCompactionEpochMs == 0L || now < lastCompactionEpochMs || now - lastCompactionEpochMs >= compactionIntervalMs) {
            compactExpired()
        }
    }

    private fun encrypt(plainText: ByteArray): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val payload = android.util.Base64.encodeToString(cipher.doFinal(plainText), android.util.Base64.NO_WRAP)
        val iv = android.util.Base64.encodeToString(cipher.iv, android.util.Base64.NO_WRAP)
        return "{\"version\":1,\"iv\":\"$iv\",\"ciphertext\":\"$payload\"}"
    }

    private fun decrypt(line: String, key: SecretKey): String {
        val record = org.json.JSONObject(line)
        if (record.optInt("version", -1) != 1) throw IOException("Unsupported encrypted journal record version")
        val iv = android.util.Base64.decode(record.getString("iv"), android.util.Base64.NO_WRAP)
        val ciphertext = android.util.Base64.decode(record.getString("ciphertext"), android.util.Base64.NO_WRAP)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        return String(cipher.doFinal(ciphertext), Charsets.UTF_8)
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = keyStore.getKey(keyAlias, null) as? SecretKey
        if (existing != null) return existing
        if (journalFile.exists() && journalFile.length() > 0L) {
            throw IOException("Event-journal key is missing; refusing to replace it and orphan existing events")
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                keyAlias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }
}
