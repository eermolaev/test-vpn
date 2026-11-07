package com.testvpn.app

import android.content.Intent
import android.provider.Settings as SystemSettings
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testvpn.core.vpncore.Vpncore
import org.json.JSONObject

private val ipv4 = Regex("""^((25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(25[0-5]|2[0-4]\d|1?\d?\d)$""")

/** Saves settings and applies them to a running tunnel without reconnecting. */
private fun saveSettings(s: Settings): String? {
    Repo.updateSettings(s)
    return runCatching { TestVpnService.instance?.applySettings() }.exceptionOrNull()?.message
}

/** Checks a rule list with the Go core; returns the error lines or null. */
private fun checkRules(text: String): String? {
    val o = JSONObject(Vpncore.validateExclusions(text))
    val errs = o.optJSONArray("errors") ?: return null
    if (errs.length() == 0) return null
    return (0 until errs.length()).joinToString("\n") {
        val e = errs.getJSONObject(it)
        "строка ${e.optInt("line")}: ${e.optString("text")} — ${e.optString("error")}"
    }
}

@Composable
fun ExclusionsScreen(modifier: Modifier, version: Int, changed: () -> Unit) {
    val initial = remember(version) { Repo.settings }
    var exclusions by remember(version) { mutableStateOf(initial.exclusions) }
    var tunnelOnly by remember(version) { mutableStateOf(initial.tunnelOnly) }
    var message by remember { mutableStateOf("") }
    Column(
        modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("Исключения — всегда напрямую", style = MaterialTheme.typography.titleMedium)
        Text(
            "По одному на строку: домен (example.ru), зона (ru), IPv4-адрес или подсеть (10.0.0.0/8).",
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
        )
        OutlinedTextField(
            exclusions, { exclusions = it },
            modifier = Modifier.fillMaxWidth().weight(1f),
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        Text("Список VPN — только эти сайты через VPN", style = MaterialTheme.typography.titleMedium)
        Text(
            "Пусто или * — через VPN идёт всё, кроме исключений.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
        )
        OutlinedTextField(
            tunnelOnly, { tunnelOnly = it },
            modifier = Modifier.fillMaxWidth().weight(0.6f),
            textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
        )
        if (message.isNotBlank()) Text(message, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
        Button(modifier = Modifier.fillMaxWidth(), onClick = {
            val err = checkRules(exclusions)?.let { "Исключения:\n$it" }
                ?: checkRules(tunnelOnly.lines().filter { it.trim() != "*" }.joinToString("\n"))?.let { "Список VPN:\n$it" }
            if (err != null) {
                message = err
            } else {
                message = saveSettings(Repo.settings.copy(exclusions = exclusions, tunnelOnly = tunnelOnly)) ?: ""
                changed()
            }
        }) { Text("Сохранить") }
    }
}

@Composable
fun SettingsScreen(modifier: Modifier, version: Int, changed: () -> Unit) {
    val ctx = LocalContext.current
    val initial = remember(version) { Repo.settings }
    var dns by remember(version) { mutableStateOf(initial.dnsServers) }
    var blockQuic by remember(version) { mutableStateOf(initial.blockQuic) }
    var message by remember { mutableStateOf("") }
    Column(
        modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("DNS-серверы", style = MaterialTheme.typography.titleMedium)
        Text(
            "IPv4, по одному на строку (до 4). Запросы идут через VPN, для исключений — напрямую.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
        )
        OutlinedTextField(dns, { dns = it }, modifier = Modifier.fillMaxWidth(), minLines = 2)
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Блокировать QUIC в VLESS")
                Text(
                    "Браузеры и YouTube перейдут на TCP — обычно так быстрее.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
                )
            }
            Switch(blockQuic, { blockQuic = it })
        }
        if (message.isNotBlank()) Text(message, color = MaterialTheme.colorScheme.error, fontSize = 13.sp)
        Button(modifier = Modifier.fillMaxWidth(), onClick = {
            val list = Settings.lines(dns)
            val bad = list.firstOrNull { !ipv4.matches(it) }
            if (bad != null || list.size > 4) {
                message = if (bad != null) "«$bad» — не IPv4-адрес" else "Не больше 4 серверов"
                return@Button
            }
            message = saveSettings(Repo.settings.copy(dnsServers = dns, blockQuic = blockQuic)) ?: ""
            if (message.isBlank() && TestVpnService.instance != null) {
                message = "Новые DNS-серверы для системы вступят в силу после переподключения."
            }
            changed()
        }) { Text("Сохранить") }

        Text("Постоянный VPN и kill switch", style = MaterialTheme.typography.titleMedium)
        Text(
            "Включите «Постоянная VPN» и «Блокировать соединения без VPN» для TestVPN: " +
                "VPN будет подключаться при загрузке, а без него интернет будет закрыт.",
            color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp,
        )
        OutlinedButton(onClick = { ctx.startActivity(Intent(SystemSettings.ACTION_VPN_SETTINGS)) }) {
            Text("Открыть настройки VPN")
        }
    }
}

@Composable
fun LogsScreen(modifier: Modifier) {
    val logs by VpnState.logs.collectAsStateWithLifecycle()
    val list = rememberLazyListState()
    LaunchedEffect(logs.size) { if (logs.isNotEmpty()) list.scrollToItem(logs.size - 1) }
    if (logs.isEmpty()) {
        Text("Журнал пуст", modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        return
    }
    SelectionContainer(modifier.fillMaxSize()) {
        LazyColumn(state = list, contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp)) {
            items(logs) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
        }
    }
}
