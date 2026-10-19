package com.svscyber.mobile

import android.content.Intent
import android.net.VpnService

/** Internal consent scaffold only. This service never creates a tunnel. */
class VpnConsentOnlyService : VpnService() {
    override fun onCreate() {
        super.onCreate()
        stopSelf()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        stopSelf(startId)
        return START_NOT_STICKY
    }
}
