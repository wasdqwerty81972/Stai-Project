package com.svscyber.mobile

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine

class MainActivity : FlutterActivity() {
    private var mobileChannels: MobilePlatformChannels? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        mobileChannels?.detach()
        mobileChannels = MobilePlatformChannels(flutterEngine.dartExecutor.binaryMessenger, applicationContext).also {
            it.attach()
        }
    }

    override fun cleanUpFlutterEngine(flutterEngine: FlutterEngine) {
        mobileChannels?.detach()
        mobileChannels = null
        super.cleanUpFlutterEngine(flutterEngine)
    }
}
