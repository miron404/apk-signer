package io.github.miron404.apksigner.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController

object Routes {
    const val IDENTITIES = "identities"
    const val CREATE = "create"
    const val DETAIL = "detail"
    const val SIGN = "sign"
    const val SETTINGS = "settings"
}

@Composable
fun AppNavHost(vaultModel: VaultViewModel) {
    val navController = rememberNavController()
    NavHost(navController = navController, startDestination = Routes.IDENTITIES) {
        composable(Routes.IDENTITIES) {
            IdentitiesScreen(
                model = vaultModel,
                onCreate = { navController.navigate(Routes.CREATE) },
                onOpen = { id -> navController.navigate("${Routes.DETAIL}/$id") },
                onSign = { navController.navigate(Routes.SIGN) },
                onSettings = { navController.navigate(Routes.SETTINGS) },
            )
        }
        composable(Routes.CREATE) {
            CreateIdentityScreen(model = vaultModel, onDone = { navController.popBackStack() })
        }
        composable("${Routes.DETAIL}/{id}") { entry ->
            IdentityDetailScreen(
                model = vaultModel,
                identityId = entry.arguments?.getString("id").orEmpty(),
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.SIGN) {
            SignScreen(
                vaultModel = vaultModel,
                signModel = viewModel(),
                onBack = { navController.popBackStack() },
            )
        }
        composable(Routes.SETTINGS) {
            SettingsScreen(model = vaultModel, onBack = { navController.popBackStack() })
        }
    }
}

@Composable
fun LockScreen(state: VaultUiState, onUnlock: () -> Unit) {
    Surface(Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp, Alignment.CenterVertically),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(
                Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(56.dp),
                tint = MaterialTheme.colorScheme.primary,
            )
            Text("APK Signer", style = MaterialTheme.typography.headlineSmall)
            Text(
                "Signing keys are held in the secure element and stay locked until you authenticate.",
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (state.busy != null) {
                CircularProgressIndicator()
            } else {
                Button(onClick = onUnlock) { Text("Unlock") }
            }
            state.error?.let {
                Text(it, color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
            }
        }
    }
}
