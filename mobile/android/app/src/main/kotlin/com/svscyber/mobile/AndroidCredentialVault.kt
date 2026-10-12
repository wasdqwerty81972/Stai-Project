package com.svscyber.mobile

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.io.IOException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Android Keystore-backed storage for user-provided credentials; secrets are never returned. */
class AndroidCredentialVault(context: Context) {
    private val preferences: SharedPreferences = context.applicationContext.getSharedPreferences(
        "mobile_provider_credentials_v1",
        Context.MODE_PRIVATE,
    )

    @Synchronized
    @Throws(IOException::class)
    fun store(providerId: String, secret: String, replace: Boolean): Map<String, Any?> {
        validateProviderId(providerId)
        validateSecret(secret)
        val exists = preferences.contains(providerId)
        if (exists && !replace) throw VaultException("CREDENTIAL_ALREADY_EXISTS", "Credential already exists")
        if (!exists && replace) throw VaultException("CREDENTIAL_NOT_FOUND", "Credential is not configured")

        val updatedAt = System.currentTimeMillis()
        val encryptedRecord = encrypt(providerId, secret, updatedAt)
        if (!preferences.edit().putString(providerId, encryptedRecord).commit()) {
            throw IOException("Could not persist encrypted credential metadata")
        }
        return metadata(providerId, updatedAt)
    }

    @Synchronized
    @Throws(IOException::class)
    fun delete(providerId: String): Map<String, Any?> {
        validateProviderId(providerId)
        val deleted = preferences.contains(providerId)
        if (deleted && !preferences.edit().remove(providerId).commit()) {
            throw IOException("Could not delete encrypted credential")
        }
        return mapOf("deleted" to deleted)
    }

    @Synchronized
    fun listMetadata(): List<Map<String, Any?>> {
        val key = try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(KEY_ALIAS, null) as? SecretKey
        } catch (_: Exception) {
            null
        }
        return preferences.all.keys.sorted().mapNotNull { providerId ->
            val raw = preferences.getString(providerId, null) ?: return@mapNotNull null
            val updatedAt = try {
                JSONObject(raw).optLong("updatedAtEpochMs", 0L).takeIf { it > 0L }
            } catch (_: Exception) {
                null
            } ?: return@mapNotNull mapOf(
                "providerId" to providerId,
                "configured" to false,
                "updatedAtEpochMs" to 0L,
            )
            metadata(providerId, updatedAt, key != null && canDecrypt(providerId, raw, key))
        }
    }

    private fun encrypt(providerId: String, secret: String, updatedAt: Long): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        cipher.updateAAD(providerId.toByteArray(Charsets.UTF_8))
        val cipherText = cipher.doFinal(secret.toByteArray(Charsets.UTF_8))
        return JSONObject()
            .put("version", 1)
            .put("updatedAtEpochMs", updatedAt)
            .put("iv", Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
            .put("ciphertext", Base64.encodeToString(cipherText, Base64.NO_WRAP))
            .toString()
    }

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existing != null) return existing
        if (preferences.all.isNotEmpty()) {
            throw IOException("Credential key is missing; refusing to replace it and orphan existing credentials")
        }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun canDecrypt(providerId: String, raw: String, key: SecretKey): Boolean = try {
        val record = JSONObject(raw)
        require(record.getInt("version") == 1)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            key,
            GCMParameterSpec(128, Base64.decode(record.getString("iv"), Base64.NO_WRAP)),
        )
        cipher.updateAAD(providerId.toByteArray(Charsets.UTF_8))
        val plain = cipher.doFinal(Base64.decode(record.getString("ciphertext"), Base64.NO_WRAP))
        val configured = plain.isNotEmpty()
        plain.fill(0)
        configured
    } catch (_: Exception) {
        false
    }

    private fun validateProviderId(providerId: String) {
        if (!PROVIDER_ID.matches(providerId)) {
            throw VaultException("INVALID_PROVIDER_ID", "Provider ID must use lowercase letters, digits, dots, underscores, or hyphens")
        }
    }

    private fun validateSecret(secret: String) {
        if (secret.isBlank()) throw VaultException("EMPTY_SECRET", "Credential value cannot be empty")
        if (secret.length > MAX_SECRET_LENGTH) {
            throw VaultException("SECRET_TOO_LARGE", "Credential exceeds the supported size")
        }
    }

    private fun metadata(providerId: String, updatedAt: Long, keyAvailable: Boolean = true): Map<String, Any?> = mapOf(
        "providerId" to providerId,
        "configured" to keyAvailable,
        "updatedAtEpochMs" to updatedAt,
    )

    class VaultException(val code: String, message: String) : IOException(message)

    companion object {
        private const val KEY_ALIAS = "svscyber.mobile.provider-credentials.v1"
        private const val MAX_SECRET_LENGTH = 8192
        private val PROVIDER_ID = Regex("[a-z][a-z0-9_.-]{0,63}")
    }
}
