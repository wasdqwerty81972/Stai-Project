package com.svscyber.mobile

import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    private var mobileChannels: MobilePlatformChannels? = null
    private var selectionCallback: ((Uri?, Boolean) -> Unit)? = null
    private var vpnConsentCallback: ((Map<String, Any>) -> Unit)? = null

    private val vpnEnabledForBuild: Boolean
        get() = try {
            @Suppress("DEPRECATION")
            packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
                .metaData?.getBoolean("com.svscyber.mobile.VPN_CONSENT_ENABLED", false) == true
        } catch (_: Exception) {
            false
        }

    private fun vpnStatus(
        enabled: Boolean,
        granted: Boolean = false,
        reasonCode: String? = null,
        unavailable: Boolean = !enabled,
    ): Map<String, Any> = buildMap {
        val status = when {
            unavailable -> "unavailable"
            !granted -> "consent_required"
            else -> "backend_unavailable"
        }
        put("contractVersion", NativeEvent.CONTRACT_VERSION)
        put("enabledForBuild", enabled)
        put("consentGranted", granted)
        put("tunnelActive", false)
        put("monitoringActive", false)
        put("state", status)
        put("torState", "unavailable")
        put("bridgeReady", false)
        put("dnsReady", false)
        put("coverage", "none")
        val reason = reasonCode ?: when (status) {
            "backend_unavailable" -> "tor_data_plane_not_integrated"
            "unavailable" -> "vpn_not_enabled_for_build"
            else -> null
        }
        if (reason != null) put("reasonCode", reason)
    }

    private fun getVpnStatus(): Map<String, Any> {
        val enabled = vpnEnabledForBuild
        return try {
            // Recheck platform consent each time; no locally cached grant.
            val intent = VpnService.prepare(this)
            vpnStatus(enabled, granted = enabled && intent == null)
        } catch (_: Exception) {
            vpnStatus(enabled, reasonCode = "consent_unavailable", unavailable = true)
        }
    }

    private fun requestVpnConsent(callback: (Map<String, Any>) -> Unit) {
        val enabled = vpnEnabledForBuild
        val intent = try {
            VpnService.prepare(this)
        } catch (_: Exception) {
            callback(vpnStatus(enabled, reasonCode = "consent_unavailable", unavailable = true))
            return
        }
        if (!enabled || intent == null) {
            callback(vpnStatus(enabled, granted = enabled && intent == null))
            return
        }
        if (isFinishing || isDestroyed || vpnConsentCallback != null || selectionCallback != null) {
            callback(vpnStatus(enabled, reasonCode = "consent_unavailable", unavailable = true))
            return
        }
        vpnConsentCallback = callback
        try {
            // Only this explicit Flutter method can open the consent dialog.
            @Suppress("DEPRECATION")
            startActivityForResult(intent, VPN_CONSENT_REQUEST)
        } catch (_: Exception) {
            vpnConsentCallback = null
            callback(vpnStatus(enabled, reasonCode = "consent_unavailable", unavailable = true))
        }
    }

    private fun cancelPendingVpnConsent() {
        val callback = vpnConsentCallback ?: return
        vpnConsentCallback = null
        callback(vpnStatus(vpnEnabledForBuild, reasonCode = "consent_unavailable", unavailable = true))
    }

    private fun selectDocument(apk: Boolean, callback: (Uri?, Boolean) -> Unit) {
        check(selectionCallback == null)
        check(vpnConsentCallback == null)
        selectionCallback = callback
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = if (apk) "application/vnd.android.package-archive" else "*/*"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            // No multiple-selection, tree, write or persistable grant requested.
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(intent, DOCUMENT_REQUEST)
        } catch (error: Exception) {
            selectionCallback = null
            throw error
        }
    }

    @Deprecated("The FlutterActivity embedding forwards activity results through this API")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_CONSENT_REQUEST) {
            val callback = vpnConsentCallback ?: return
            vpnConsentCallback = null
            val status = getVpnStatus()
            callback(if (resultCode == Activity.RESULT_OK) status
                else vpnStatus(vpnEnabledForBuild, reasonCode = "user_denied"))
            return
        }
        if (requestCode != DOCUMENT_REQUEST) return
        val callback = selectionCallback ?: return
        selectionCallback = null
        callback(if (resultCode == Activity.RESULT_OK) data?.data else null,
            resultCode == Activity.RESULT_CANCELED)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        cancelPendingVpnConsent()
        mobileChannels?.detach()
        mobileChannels = MobilePlatformChannels(
            flutterEngine.dartExecutor.binaryMessenger, applicationContext, ::selectDocument,
            ::getVpnStatus, ::requestVpnConsent,
        ).also {
            it.attach()
        }
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        cancelPendingVpnConsent()
        mobileChannels?.detach()
        selectionCallback = null
        mobileChannels = null
        super.cleanUpFlutterEngine(flutterEngine)
    }

    override fun onDestroy() {
        cancelPendingVpnConsent()
        super.onDestroy()
    }

    companion object {
        private const val DOCUMENT_REQUEST = 7142
        private const val VPN_CONSENT_REQUEST = 7143
    }
}
