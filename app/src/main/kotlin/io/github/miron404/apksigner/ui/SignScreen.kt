package io.github.miron404.apksigner.ui

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle

@OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)
@Composable
fun SignScreen(vaultModel: VaultViewModel, signModel: SignViewModel, onBack: () -> Unit) {
    val vault by vaultModel.state.collectAsStateWithLifecycle()
    val state by signModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    MessageEffect(state.message, state.error, snackbar, signModel::consumeMessage)

    val pickApk = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(signModel::loadApk)
    }
    val saveApk = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")
    ) { uri: Uri? -> uri?.let(signModel::saveSignedApk) }
    val saveIdsig = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream")
    ) { uri: Uri? -> uri?.let(signModel::saveIdsig) }

    val selected = vault.identities.firstOrNull { it.id == state.selectedIdentityId }
    val busy = state.busy != null

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Sign an APK") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            if (busy) {
                LinearProgressIndicator(Modifier.fillMaxWidth())
                Text(state.busy.orEmpty(), style = MaterialTheme.typography.labelMedium)
            }

            SectionCard("Input") {
                OutlinedButton(
                    onClick = {
                        pickApk.launch(
                            arrayOf("application/vnd.android.package-archive", "application/zip", "*/*")
                        )
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(state.sourceName ?: "Choose an APK") }

                state.apkInfo?.let { info ->
                    KeyValueRow("Package", info.packageName ?: "unknown")
                    KeyValueRow("Version code", info.versionCode.toString())
                    KeyValueRow("Min SDK", info.minSdkVersion.toString())
                    if (info.debuggable) {
                        Text(
                            "This APK is marked debuggable.",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }

            SectionCard("Identity") {
                if (vault.identities.isEmpty()) {
                    Text(
                        "Create a signing identity first.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                vault.identities.forEach { identity ->
                    Row(
                        Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = identity.id == state.selectedIdentityId,
                            onClick = { signModel.selectIdentity(identity.id) },
                        )
                        Column {
                            Text(identity.label, style = MaterialTheme.typography.bodyLarge)
                            Text(
                                "${identity.algorithm} ${identity.keySize} · " +
                                    identity.fingerprintSha256.take(29),
                                style = MaterialTheme.typography.labelSmall
                                    .copy(fontFamily = FontFamily.Monospace),
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
            }

            SectionCard("Signature schemes") {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    SchemeChip("v1 (JAR)", state.schemes.v1) {
                        signModel.setSchemes(state.schemes.copy(v1 = it))
                    }
                    SchemeChip("v2", state.schemes.v2) {
                        signModel.setSchemes(state.schemes.copy(v2 = it))
                    }
                    SchemeChip("v3", state.schemes.v3) {
                        signModel.setSchemes(state.schemes.copy(v3 = it))
                    }
                    SchemeChip("v4", state.schemes.v4) {
                        signModel.setSchemes(state.schemes.copy(v4 = it))
                    }
                }
                Row(
                    Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Re-align entries", style = MaterialTheme.typography.bodyMedium)
                        Text(
                            "Equivalent to zipalign; keeps uncompressed libraries page aligned.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = state.realign, onCheckedChange = signModel::setRealign)
                }
                if (state.schemes.v4) {
                    Text(
                        "v4 writes a separate .idsig file that must travel with the APK.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            Button(
                enabled = !busy && selected != null && state.apkInfo != null,
                onClick = { selected?.let(signModel::sign) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Sign") }

            state.report?.let { report ->
                SectionCard(if (report.verified) "Verified" else "Verification failed") {
                    KeyValueRow(
                        "Schemes",
                        listOfNotNull(
                            "v1".takeIf { report.v1 },
                            "v2".takeIf { report.v2 },
                            "v3".takeIf { report.v3 },
                            "v4".takeIf { report.v4 },
                        ).joinToString(", ").ifEmpty { "none" },
                    )
                    report.signers.forEach { signer ->
                        LabeledValue(signer.subject, signer.fingerprintSha256, monospace = true)
                    }
                    report.errors.forEach {
                        Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    report.warnings.take(10).forEach {
                        Text(
                            it,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }

            if (state.signedReady) {
                Button(
                    onClick = { saveApk.launch(state.suggestedName) },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Save signed APK") }
            }
            if (state.idsigReady) {
                OutlinedButton(
                    onClick = { saveIdsig.launch(state.suggestedName + ".idsig") },
                    modifier = Modifier.fillMaxWidth(),
                ) { Text("Save .idsig (v4)") }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SchemeChip(label: String, selected: Boolean, onChange: (Boolean) -> Unit) {
    FilterChip(selected = selected, onClick = { onChange(!selected) }, label = { Text(label) })
}
