package com.testvpn.app

import android.app.Activity
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { AppTheme { AppScreen() } }
    }
}

private val Green = Color(0xFF1E6B52)

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) {
        darkColorScheme(primary = Color(0xFF7FD3B0), secondary = Color(0xFF7FD3B0))
    } else {
        lightColorScheme(primary = Green, secondary = Green)
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

private enum class Tab(val title: String, val icon: ImageVector) {
    Home("VPN", Icons.Filled.Home),
    Profiles("Профили", Icons.Filled.List),
    Exclusions("Правила", Icons.Filled.Lock),
    Settings("Настройки", Icons.Filled.Settings),
    Logs("Журнал", Icons.Filled.Info),
}

@Composable
private fun AppScreen() {
    val ctx = LocalContext.current
    var tab by rememberSaveable { mutableIntStateOf(0) }
    // Bumped after profile or settings changes so that screens re-read Repo.
    var version by remember { mutableIntStateOf(0) }

    // VpnService.prepare() asks the user once to allow this app to create a VPN.
    val vpnPermission = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) TestVpnService.connect(ctx)
        else VpnState.log("разрешение на VPN не выдано")
    }
    val connect = {
        val intent = VpnService.prepare(ctx)
        if (intent != null) vpnPermission.launch(intent) else TestVpnService.connect(ctx)
    }

    Scaffold(
        bottomBar = {
            NavigationBar {
                Tab.entries.forEachIndexed { i, t ->
                    NavigationBarItem(
                        selected = tab == i,
                        onClick = { tab = i },
                        icon = { Icon(t.icon, contentDescription = null) },
                        label = { Text(t.title, maxLines = 1) },
                    )
                }
            }
        },
    ) { padding ->
        val m = Modifier.padding(padding)
        when (Tab.entries[tab]) {
            Tab.Home -> HomeScreen(m, version, onConnect = { connect() }, onDisconnect = { TestVpnService.disconnect(ctx) })
            Tab.Profiles -> ProfilesScreen(m, version) { version++ }
            Tab.Exclusions -> ExclusionsScreen(m, version) { version++ }
            Tab.Settings -> SettingsScreen(m, version) { version++ }
            Tab.Logs -> LogsScreen(m)
        }
    }
}
