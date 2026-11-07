package com.testvpn.app

import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Box
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** "VLESS + REALITY · raw+vision, AmneziaWG" from the profile summary. */
private fun transports(summary: String): String = runCatching {
    val arr = JSONObject(summary).getJSONArray("transports")
    (0 until arr.length()).joinToString(", ") {
        val t = arr.getJSONObject(it)
        listOf(t.optString("kind"), t.optString("detail")).filter { s -> s.isNotBlank() }.joinToString(" · ")
    }
}.getOrDefault("")

@Composable
fun ProfilesScreen(modifier: Modifier, version: Int, changed: () -> Unit) {
    val profiles = remember(version) { Repo.profiles }
    val selected = remember(version) { Repo.selected()?.id }
    var importing by remember { mutableStateOf(false) }

    Box(modifier.fillMaxSize()) {
        if (profiles.isEmpty()) {
            Text(
                "Профилей нет.\nНажмите «Импорт»: вставьте vless://-ссылку, ключ vpn:// или .conf, отсканируйте QR-код или выберите его из галереи.",
                modifier = Modifier.align(Alignment.Center).padding(32.dp),
            )
        }
        LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(bottom = 96.dp)) {
            items(profiles, key = { it.id }) { p ->
                Row(
                    Modifier.fillMaxWidth().clickable { Repo.select(p.id); changed() }.padding(horizontal = 8.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = p.id == selected, onClick = { Repo.select(p.id); changed() })
                    Column(Modifier.weight(1f)) {
                        Text(p.name, style = MaterialTheme.typography.titleMedium)
                        Text(transports(p.summary), style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    IconButton(onClick = { Repo.delete(p.id); changed() }) {
                        Icon(Icons.Filled.Delete, contentDescription = "Удалить")
                    }
                }
            }
        }
        ExtendedFloatingActionButton(
            onClick = { importing = true },
            icon = { Icon(Icons.Filled.Add, contentDescription = null) },
            text = { Text("Импорт") },
            modifier = Modifier.align(Alignment.BottomEnd).padding(16.dp),
        )
    }
    if (importing) ImportDialog(onDone = { importing = false; changed() }, onCancel = { importing = false })
}

@Composable
private fun ImportDialog(onDone: () -> Unit, onCancel: () -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var error by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }

    // A decoded QR code is imported at once; on failure its text stays in the
    // field with the error, so the user sees what was read.
    fun importText(value: String) {
        text = value
        runCatching { Repo.import(value) }
            .onSuccess { VpnState.log("импортирован профиль «${it.name}»"); onDone() }
            .onFailure { error = it.message ?: "не удалось разобрать профиль" }
    }

    val scanQr = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { importText(it) } // null: the user closed the scanner
    }
    val pickImage = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        busy = true
        error = ""
        scope.launch {
            val decoded = withContext(Dispatchers.Default) { runCatching { QrDecoder.decode(ctx, uri) }.getOrNull() }
            busy = false
            if (decoded == null) error = "На изображении не найден QR-код" else importText(decoded)
        }
    }
    val pickFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            text = runCatching { ctx.contentResolver.openInputStream(uri)?.use { it.readBytes().decodeToString() } ?: "" }
                .getOrElse { error = "не удалось прочитать файл: ${it.message}"; "" }
        }
    }
    AlertDialog(
        onDismissRequest = onCancel,
        title = { Text("Импорт профиля") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = text,
                    onValueChange = { text = it; error = "" },
                    label = { Text("Ссылка, ключ или конфиг") },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 120.dp, max = 240.dp),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = {
                        val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        text = cm.primaryClip?.getItemAt(0)?.coerceToText(ctx)?.toString() ?: ""
                    }) { Text("Из буфера") }
                    TextButton(onClick = { pickFile.launch(arrayOf("*/*")) }) { Text("Из файла") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = {
                        scanQr.launch(
                            ScanOptions()
                                .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                                .setPrompt("Наведите камеру на QR-код")
                                .setBeepEnabled(false)
                                .setOrientationLocked(false),
                        )
                    }) { Text("Сканировать QR") }
                    TextButton(onClick = {
                        pickImage.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                    }) { Text("QR из галереи") }
                }
                if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
                if (error.isNotBlank()) Text(error, color = MaterialTheme.colorScheme.error)
            }
        },
        confirmButton = {
            Button(enabled = text.isNotBlank() && !busy, onClick = { importText(text) }) { Text("Добавить") }
        },
        dismissButton = { TextButton(onClick = onCancel) { Text("Отмена") } },
    )
}
