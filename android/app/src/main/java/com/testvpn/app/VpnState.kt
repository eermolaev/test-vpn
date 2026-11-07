package com.testvpn.app

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Parsed tunnel.Status of the Go core. */
data class Status(
    val state: String = "stopped",
    val transport: String = "",
    val error: String = "",
    val bytesUp: Long = 0,
    val bytesDown: Long = 0,
    val directBytes: Long = 0,
    val flows: Int = 0,
    val dnsFailed: Long = 0,
) {
    val active get() = state != "stopped"

    companion object {
        fun parse(json: String): Status = runCatching {
            val o = JSONObject(json)
            val s = o.optJSONObject("stats") ?: JSONObject()
            Status(
                state = o.optString("state", "stopped"),
                transport = o.optString("transportKind"),
                error = o.optString("errorMessage"),
                bytesUp = s.optLong("bytesTunnelUp"),
                bytesDown = s.optLong("bytesTunnelDown"),
                directBytes = s.optLong("bytesDirectUp") + s.optLong("bytesDirectDown"),
                flows = s.optInt("activeFlows"),
                dnsFailed = s.optLong("dnsFailed"),
            )
        }.getOrDefault(Status())
    }
}

/** State shared by the service and the UI (same process). */
object VpnState {
    private val _status = MutableStateFlow(Status())
    val status: StateFlow<Status> = _status.asStateFlow()

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private val time = SimpleDateFormat("HH:mm:ss", Locale.ROOT)

    fun setStatus(s: Status) { _status.value = s }

    /** Lines from the core are already redacted (no keys or server addresses). */
    fun log(line: String) {
        val stamped = time.format(Date()) + " " + line.trim()
        _logs.update { (it + stamped).takeLast(500) }
    }
}
