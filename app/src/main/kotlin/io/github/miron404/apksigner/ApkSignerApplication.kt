package io.github.miron404.apksigner

import android.app.Application
import android.content.Context
import io.github.miron404.apksigner.core.AppSettings
import io.github.miron404.apksigner.core.Bc
import io.github.miron404.apksigner.core.MasterKey
import io.github.miron404.apksigner.core.SystemAuthenticator
import io.github.miron404.apksigner.core.Vault

/** Hand-rolled service locator; the graph is small enough that a DI framework would be noise. */
class AppContainer(context: Context) {
    val settings = AppSettings(context)
    val authenticator = SystemAuthenticator()
    val masterKey = MasterKey(authenticator)
    val vault = Vault(context, masterKey, settings)
}

class ApkSignerApplication : Application() {

    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        // Android's built-in "BC" provider is a stripped subset; swap in the full build before any
        // crypto runs so PKCS#12 writing and certificate building resolve to it.
        Bc.install()
        container = AppContainer(this)
        // Finish any rekey that a previous run was interrupted mid-way through.
        runCatching { container.vault.repair() }
    }
}

val Context.container: AppContainer
    get() = (applicationContext as ApkSignerApplication).container
