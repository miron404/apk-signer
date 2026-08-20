package io.github.miron404.apksigner

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
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
                        if (event == Lifecycle.Event.ON_RESUME) vaultModel.onResumed()
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
                }

                if (state.lockOnLaunch && !state.unlocked) {
                    LockScreen(state = state, onUnlock = vaultModel::unlockApp)
                } else {
                    AppNavHost(vaultModel = vaultModel)
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
