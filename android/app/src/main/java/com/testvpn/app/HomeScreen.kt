package com.testvpn.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

fun stateText(state: String) = when (state) {
    "connecting" -> "Подключение…"
    "connected" -> "Подключено"
    "reconnecting" -> "Переподключение (трафик заблокирован)"
    "failed" -> "Ошибка (трафик заблокирован)"
    else -> "Отключено"
}

fun bytes(n: Long): String = when {
    n >= 1L shl 30 -> "%.2f ГБ".format(n / (1L shl 30).toDouble())
    n >= 1L shl 20 -> "%.1f МБ".format(n / (1L shl 20).toDouble())
    n >= 1L shl 10 -> "%.0f КБ".format(n / 1024.0)
    else -> "$n Б"
}

@Composable
fun HomeScreen(modifier: Modifier, version: Int, onConnect: () -> Unit, onDisconnect: () -> Unit) {
    val st by VpnState.status.collectAsStateWithLifecycle()
    val profile = remember(version) { Repo.selected() }
    Column(
        modifier.fillMaxSize().padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(24.dp))
        Text(stateText(st.state), fontSize = 26.sp, fontWeight = FontWeight.SemiBold)
        Text(
            profile?.name ?: "Нет профиля — импортируйте на вкладке «Профили»",
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (st.active) {
            OutlinedButton(onClick = onDisconnect, modifier = Modifier.size(width = 220.dp, height = 56.dp)) {
                Text("Отключить", fontSize = 18.sp)
            }
        } else {
            Button(
                onClick = onConnect,
                enabled = profile != null,
                modifier = Modifier.size(width = 220.dp, height = 56.dp),
                colors = ButtonDefaults.buttonColors(),
            ) { Text("Подключить", fontSize = 18.sp) }
        }
        if (st.error.isNotBlank()) {
            Text(st.error, color = MaterialTheme.colorScheme.error)
        }
        if (st.active) {
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Row2("Транспорт", st.transport.ifBlank { "—" })
                    Row2("Через VPN", "↑ ${bytes(st.bytesUp)}   ↓ ${bytes(st.bytesDown)}")
                    Row2("Напрямую", bytes(st.directBytes))
                    Row2("Соединений", st.flows.toString())
                    if (st.dnsFailed > 0) Row2("Ошибок DNS", st.dnsFailed.toString())
                }
            }
        }
    }
}

@Composable
private fun Row2(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value)
    }
}
