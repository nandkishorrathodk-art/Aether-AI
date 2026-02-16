package com.aether.ai

import android.os.Bundle
import com.facebook.react.ReactActivity
import com.facebook.react.ReactActivityDelegate
import com.facebook.react.defaults.DefaultNewArchitectureEntryPoint.fabricEnabled
import com.facebook.react.defaults.DefaultReactActivityDelegate

class MainActivity : ReactActivity() {

    /**
     * Returns the name of the main component registered from JavaScript.
     * This is used to schedule rendering of the component.
     */
    override fun getMainComponentName(): String = "AetherAI"

    /**
     * Returns the instance of the [ReactActivityDelegate]. We use [DefaultReactActivityDelegate]
     * which allows you to enable New Architecture with a single boolean flag [fabricEnabled]
     */
    override fun createReactActivityDelegate(): ReactActivityDelegate =
        DefaultReactActivityDelegate(this, mainComponentName, fabricEnabled)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Request voice permissions on startup
        requestPermissions(
            arrayOf(
                android.Manifest.permission.RECORD_AUDIO,
                android.Manifest.permission.MODIFY_AUDIO_SETTINGS
            ),
            REQUEST_VOICE_PERMISSION
        )
    }

    companion object {
        private const val REQUEST_VOICE_PERMISSION = 1001
    }
}
