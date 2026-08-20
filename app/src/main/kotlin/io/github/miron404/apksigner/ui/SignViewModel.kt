package io.github.miron404.apksigner.ui

import android.app.Application
import android.net.Uri
import android.provider.OpenableColumns
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.miron404.apksigner.container
import io.github.miron404.apksigner.core.ApkInfo
import io.github.miron404.apksigner.core.ApkSigningService
import io.github.miron404.apksigner.core.AuthCancelledException
import io.github.miron404.apksigner.core.IdentityMeta
import io.github.miron404.apksigner.core.SignOptions
import io.github.miron404.apksigner.core.SignatureSchemes
import io.github.miron404.apksigner.core.VerificationReport
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class SignUiState(
    val sourceName: String? = null,
    val apkInfo: ApkInfo? = null,
    val selectedIdentityId: String? = null,
    val schemes: SignatureSchemes = SignatureSchemes(),
    val realign: Boolean = true,
    val report: VerificationReport? = null,
    val signedReady: Boolean = false,
    val idsigReady: Boolean = false,
    val suggestedName: String = "signed.apk",
    val busy: String? = null,
    val message: String? = null,
    val error: String? = null,
)

/**
 * Signing works on private copies in the cache directory: apksig needs seekable files, and SAF
 * only hands out streams. The copies are deleted as soon as the result has been written back out.
 */
class SignViewModel(application: Application) : AndroidViewModel(application) {

    private val container = application.container
    private val workDir = File(application.cacheDir, "signing").apply { mkdirs() }
    private val inputFile = File(workDir, "input.apk")
    private val outputFile = File(workDir, "output.apk")
    private val idsigFile = File(workDir, "output.apk.idsig")

    private val _state = MutableStateFlow(SignUiState(schemes = container.settings.defaultSchemes))
    val state: StateFlow<SignUiState> = _state.asStateFlow()

    fun consumeMessage() = _state.update { it.copy(message = null, error = null) }

    fun selectIdentity(id: String?) {
        _state.update { it.copy(selectedIdentityId = id) }
        invalidateResult()
    }

    fun setSchemes(schemes: SignatureSchemes) {
        container.settings.defaultSchemes = schemes
        _state.update { it.copy(schemes = schemes) }
        invalidateResult()
    }

    fun setRealign(value: Boolean) {
        _state.update { it.copy(realign = value) }
        invalidateResult()
    }

    /** A signed output belongs to the settings that produced it; changing them discards it. */
    private fun invalidateResult() {
        if (_state.value.report == null) return
        discardOutputs()
        _state.update { it.copy(report = null, signedReady = false, idsigReady = false) }
    }

    fun loadApk(source: Uri) = run("Reading APK") {
        discardOutputs()
        val name = displayName(source) ?: "input.apk"
        copyIntoWorkspace(source)
        val info = withContext(Dispatchers.IO) {
            runCatching { ApkSigningService.inspect(inputFile) }.getOrNull()
        }
        if (info == null) {
            // Leave no trace of a rejected file: the button goes back to inviting a choice rather
            // than naming something the app refused.
            inputFile.delete()
            _state.update {
                it.copy(
                    sourceName = null,
                    apkInfo = null,
                    report = null,
                    signedReady = false,
                    idsigReady = false,
                )
            }
            error("That file is not a valid APK")
        }
        _state.update {
            it.copy(
                sourceName = name,
                apkInfo = info,
                report = null,
                signedReady = false,
                idsigReady = false,
                suggestedName = name.removeSuffix(".apk") + "-signed.apk",
            )
        }
    }

    fun sign(identity: IdentityMeta) = run("Signing") {
        if (!inputFile.isFile) error("Pick an APK first")
        val options = SignOptions(schemes = _state.value.schemes, realign = _state.value.realign)
        if (!options.schemes.any) error("Select at least one signature scheme")

        discardOutputs()
        container.vault.unlock(identity).use { unlocked ->
            withContext(Dispatchers.Default) {
                ApkSigningService.sign(
                    identity = unlocked,
                    input = inputFile,
                    output = outputFile,
                    v4Output = if (options.schemes.v4) idsigFile else null,
                    options = options,
                )
            }
        }
        val report = withContext(Dispatchers.Default) {
            ApkSigningService.verify(outputFile, idsigFile.takeIf { it.isFile })
        }
        _state.update {
            it.copy(
                report = report,
                signedReady = report.verified,
                idsigReady = idsigFile.isFile,
                // Success speaks for itself through the report card, which is on screen and says
                // more than a snackbar could. A failure still interrupts.
                error = if (report.verified) null else "Signed, but the result did not verify",
            )
        }
        if (!report.verified) outputFile.delete()
    }

    fun saveSignedApk(target: Uri) = run("Saving") {
        if (!outputFile.isFile) error("Nothing to save")
        copyToUri(outputFile, target)
        _state.update {
            it.copy(
                message = if (it.idsigReady) {
                    "Saved. Save the .idsig file too for v4 verification."
                } else {
                    "Saved"
                }
            )
        }
    }

    fun saveIdsig(target: Uri) = run("Saving v4 signature") {
        if (!idsigFile.isFile) error("No v4 signature was produced")
        copyToUri(idsigFile, target)
        _state.update { it.copy(message = "Saved v4 signature") }
    }

    override fun onCleared() {
        discardOutputs()
        inputFile.delete()
        super.onCleared()
    }

    private suspend fun copyIntoWorkspace(source: Uri) = withContext(Dispatchers.IO) {
        getApplication<Application>().contentResolver.openInputStream(source)?.use { stream ->
            inputFile.outputStream().use { stream.copyTo(it) }
        } ?: error("Could not read the selected file")
    }

    private fun discardOutputs() {
        outputFile.delete()
        idsigFile.delete()
    }

    private suspend fun copyToUri(file: File, target: Uri) = withContext(Dispatchers.IO) {
        getApplication<Application>().contentResolver.openOutputStream(target, "wt")?.use { out ->
            file.inputStream().use { it.copyTo(out) }
        } ?: error("Could not open the destination for writing")
    }

    private fun displayName(uri: Uri): String? =
        getApplication<Application>().contentResolver
            .query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null }

    private fun run(busy: String, block: suspend () -> Unit) = viewModelScope.launch {
        _state.update { it.copy(busy = busy, error = null, message = null) }
        try {
            block()
        } catch (_: AuthCancelledException) {
            _state.update { it.copy(error = "Authentication cancelled") }
        } catch (throwable: Throwable) {
            _state.update { it.copy(error = throwable.message ?: throwable.javaClass.simpleName) }
        } finally {
            _state.update { it.copy(busy = null) }
        }
    }
}
