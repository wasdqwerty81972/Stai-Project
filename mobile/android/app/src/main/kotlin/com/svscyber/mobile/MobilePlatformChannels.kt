package com.svscyber.mobile

import android.os.Handler
import android.os.Looper
import android.content.Context
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.IOException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/** Version 1 Flutter bridge. Every event is journaled before a method/event response is delivered. */
class MobilePlatformChannels(
    binaryMessenger: BinaryMessenger,
    context: Context,
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val worker = STORAGE_WORKER
    private val journal: LocalEventJournal = JsonLinesLocalEventJournal(context.applicationContext)
    private val collector = AndroidDeviceBaselineCollector(context.applicationContext)
    private val appInventoryCollector = AndroidVisibleAppInventoryCollector(context.applicationContext)
    private val credentialVault = AndroidCredentialVault(context.applicationContext)
    private val privacyPreferences = context.applicationContext.getSharedPreferences(
        PRIVACY_PREFERENCES,
        Context.MODE_PRIVATE,
    )
    private var eventSink: EventChannel.EventSink? = null
    private var attached = false

    private val methods = MethodChannel(binaryMessenger, METHOD_CHANNEL)
    private val credentialMethods = MethodChannel(binaryMessenger, CREDENTIAL_CHANNEL)
    private val privacySetupMethods = MethodChannel(binaryMessenger, PRIVACY_SETUP_CHANNEL)
    private val events = EventChannel(binaryMessenger, EVENT_CHANNEL)

    fun attach() {
        attached = true
        methods.setMethodCallHandler(this)
        credentialMethods.setMethodCallHandler(::onCredentialMethodCall)
        privacySetupMethods.setMethodCallHandler(::onPrivacySetupMethodCall)
        events.setStreamHandler(this)
    }

    fun detach() {
        attached = false
        methods.setMethodCallHandler(null)
        credentialMethods.setMethodCallHandler(null)
        privacySetupMethods.setMethodCallHandler(null)
        events.setStreamHandler(null)
        eventSink = null
    }

    // An accepted storage operation may finish after engine teardown. Never send
    // its callback to that engine; reads can replay any saved events next time.
    private fun deliver(callback: () -> Unit) {
        mainHandler.post { if (attached) callback() }
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getContract" -> result.success(
                mapOf(
                    "contractVersion" to NativeEvent.CONTRACT_VERSION,
                    "platform" to "android",
                    "methodChannel" to METHOD_CHANNEL,
                    "eventChannel" to EVENT_CHANNEL,
                    "credentialVaultChannel" to CREDENTIAL_CHANNEL,
                    "methods" to listOf("getContract", "collectDeviceBaseline", "readEvents", "getJournalStatus"),
                    "continuousMonitoring" to false,
                ),
            )
            "collectDeviceBaseline" -> collectBaseline(result)
            "collectVisibleApplicationInventory" -> collectVisibleApplications(call, result)
            "readEvents" -> readEvents(call, result)
            "getJournalStatus" -> getJournalStatus(result)
            else -> result.notImplemented()
        }
    }

    private fun onPrivacySetupMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isPrivacySetupComplete" -> worker.execute {
                try {
                    val complete = privacyPreferences.getBoolean(PRIVACY_SETUP_COMPLETE, false)
                    deliver { result.success(complete) }
                } catch (error: Exception) {
                    deliver { result.error("PRIVACY_SETUP_READ_FAILED", error.javaClass.simpleName, null) }
                }
            }
            "completePrivacySetup" -> worker.execute {
                try {
                    val saved = privacyPreferences.edit()
                        .putBoolean(PRIVACY_SETUP_COMPLETE, true)
                        .commit()
                    deliver {
                        if (saved) result.success(null)
                        else result.error("PRIVACY_SETUP_SAVE_FAILED", "Could not save privacy setup state.", null)
                    }
                } catch (error: Exception) {
                    deliver { result.error("PRIVACY_SETUP_SAVE_FAILED", error.javaClass.simpleName, null) }
                }
            }
            else -> result.notImplemented()
        }
    }

    private fun collectBaseline(result: MethodChannel.Result) {
        worker.execute {
            try {
                val collected = collector.collect()
                collected.forEach { journal.append(it) }
                val payload = mapOf(
                    "contractVersion" to NativeEvent.CONTRACT_VERSION,
                    "collectedAtEpochMs" to System.currentTimeMillis(),
                    "continuousMonitoring" to false,
                    "events" to collected.map { it.toChannelMap() },
                )
                deliver {
                    collected.forEach { eventSink?.success(it.toChannelMap()) }
                    result.success(payload)
                }
            } catch (error: IOException) {
                deliver {
                    result.error("JOURNAL_WRITE_FAILED", error.message, null)
                }
            } catch (error: Exception) {
                deliver {
                    result.error("BASELINE_COLLECTION_FAILED", error.javaClass.simpleName, null)
                }
            }
        }
    }

    private fun collectVisibleApplications(call: MethodCall, result: MethodChannel.Result) {
        val arguments = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
        val requestedLimit = (arguments["limit"] as? Number)?.toInt() ?: 100
        val limit = requestedLimit.coerceIn(1, AndroidVisibleAppInventoryCollector.MAX_APPLICATIONS)
        worker.execute {
            try {
                val collected = appInventoryCollector.collect(limit)
                collected.events.forEach { journal.append(it) }
                val payload = mapOf(
                    "contractVersion" to NativeEvent.CONTRACT_VERSION,
                    "observedAtEpochMs" to collected.observedAtEpochMs,
                    "scope" to collected.scope,
                    "visibilityMayBeFiltered" to collected.visibilityMayBeFiltered,
                    "truncated" to collected.truncated,
                    "applications" to collected.applications,
                    "events" to collected.events.map { it.toChannelMap() },
                )
                deliver {
                    collected.events.forEach { eventSink?.success(it.toChannelMap()) }
                    result.success(payload)
                }
            } catch (error: IOException) {
                deliver { result.error("JOURNAL_WRITE_FAILED", error.message, null) }
            } catch (error: Exception) {
                deliver { result.error("APP_INVENTORY_COLLECTION_FAILED", error.javaClass.simpleName, null) }
            }
        }
    }

    private fun readEvents(call: MethodCall, result: MethodChannel.Result) {
        val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
        val after = (args["afterEpochMs"] as? Number)?.toLong()
        val requestedLimit = (args["limit"] as? Number)?.toInt() ?: 100
        val limit = requestedLimit.coerceIn(1, 500)
        worker.execute {
            try {
                val records = journal.read(after, limit)
                deliver {
                    result.success(mapOf("contractVersion" to NativeEvent.CONTRACT_VERSION, "events" to records))
                }
            } catch (error: IOException) {
                deliver { result.error("JOURNAL_READ_FAILED", error.javaClass.simpleName, null) }
            } catch (error: Exception) {
                deliver { result.error("JOURNAL_READ_FAILED", error.javaClass.simpleName, null) }
            }
        }
    }

    private fun getJournalStatus(result: MethodChannel.Result) {
        worker.execute {
            try {
                val status = journal.status()
                deliver {
                    result.success(
                        mapOf(
                            "contractVersion" to NativeEvent.CONTRACT_VERSION,
                            "available" to status.available,
                            "eventCount" to status.eventCount,
                            "sizeBytes" to status.sizeBytes,
                            "encryptedAtRest" to status.encryptedAtRest,
                            "retentionDays" to status.retentionDays,
                            "maxBytes" to status.maxBytes,
                            "warning" to status.warning,
                        ),
                    )
                }
            } catch (error: Exception) {
                deliver { result.error("JOURNAL_STATUS_FAILED", error.javaClass.simpleName, null) }
            }
        }
    }

    private fun onCredentialMethodCall(call: MethodCall, result: MethodChannel.Result) {
        worker.execute {
            try {
                val response = when (call.method) {
                    "storeKey", "replaceKey" -> {
                        val args = call.arguments as? Map<*, *>
                            ?: throw AndroidCredentialVault.VaultException("INVALID_ARGUMENTS", "Expected a providerId and secret map")
                        val providerId = args["providerId"] as? String
                            ?: throw AndroidCredentialVault.VaultException("INVALID_PROVIDER_ID", "Provider ID is required")
                        val secret = args["secret"] as? String
                            ?: throw AndroidCredentialVault.VaultException("INVALID_SECRET", "Credential value is required")
                        credentialVault.store(providerId, secret, call.method == "replaceKey")
                    }
                    "deleteKey" -> {
                        val args = call.arguments as? Map<*, *>
                            ?: throw AndroidCredentialVault.VaultException("INVALID_ARGUMENTS", "Expected a providerId map")
                        val providerId = args["providerId"] as? String
                            ?: throw AndroidCredentialVault.VaultException("INVALID_PROVIDER_ID", "Provider ID is required")
                        credentialVault.delete(providerId)
                    }
                    "listKeyMetadata" -> credentialVault.listMetadata()
                    else -> null
                }
                deliver {
                    if (response == null) result.notImplemented() else result.success(response)
                }
            } catch (error: AndroidCredentialVault.VaultException) {
                deliver { result.error(error.code, error.message, null) }
            } catch (error: Exception) {
                deliver { result.error("CREDENTIAL_VAULT_FAILED", error.javaClass.simpleName, null) }
            }
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    companion object {
        // Serialize journal/vault work across Activity/engine recreation so an
        // old engine cannot compact the same file while its successor appends.
        private val STORAGE_WORKER: ExecutorService = Executors.newSingleThreadExecutor { task ->
            Thread(task, "mobile-local-storage")
        }
        const val METHOD_CHANNEL = "svs_cyber/mobile/platform/v1"
        const val EVENT_CHANNEL = "svs_cyber/mobile/events/v1"
        const val CREDENTIAL_CHANNEL = "com.svscyber.mobile/credential_vault.v1"
        const val PRIVACY_SETUP_CHANNEL = "com.svscyber.mobile/privacy_setup.v1"
        private const val PRIVACY_PREFERENCES = "svs_mobile_privacy_setup"
        private const val PRIVACY_SETUP_COMPLETE = "complete_v1"
    }
}
