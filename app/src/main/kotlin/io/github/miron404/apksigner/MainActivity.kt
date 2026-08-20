package io.github.miron404.apksigner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import io.github.miron404.apksigner.ui.ApkSignerTheme
import io.github.miron404.apksigner.ui.AppNavHost
import io.github.miron404.apksigner.ui.LockScreen
import io.github.miron404.apksigner.ui.VaultViewModel

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Keep certificate details and file names out of screenshots and the recents thumbnail.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()

        setContent {
            ApkSignerTheme {
                val vaultModel: VaultViewModel = viewModel()
                val state by vaultModel.state.collectAsStateWithLifecycle()

                val lifecycleOwner = LocalLifecycleOwner.current
                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        when (event) {
                            Lifecycle.Event.ON_START -> vaultModel.onForegrounded()
                            Lifecycle.Event.ON_STOP -> vaultModel.onBackgrounded()
                            else -> Unit
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
                }

                // The lock is an opaque overlay rather than a replacement, so a trip through the
                // system file picker does not tear down the screen the user was working on.
                Box(Modifier.fillMaxSize()) {
                    AppNavHost(vaultModel = vaultModel)
                    if (state.lockOnLaunch && !state.unlocked) {
                        LockScreen(state = state, onUnlock = vaultModel::unlockApp)
                    }
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        container.authenticator.attach(this)
    }

    override fun onPause() {
        container.authenticator.detach(this)
        super.onPause()
    }
}
