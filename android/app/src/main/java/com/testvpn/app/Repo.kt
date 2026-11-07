package com.testvpn.app

import android.content.Context
import com.testvpn.core.vpncore.Vpncore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** A saved profile. [json] contains secrets; it never leaves app storage. */
data class Profile(val id: String, val name: String, val json: String, val summary: String)

/** User settings applied to the tunnel (tunnel.Settings in the Go core). */
data class Settings(
    val exclusions: String = "",
    val tunnelOnly: String = "",
    val dnsServers: String = "8.8.8.8\n8.8.4.4",
    val blockQuic: Boolean = true,
) {
    fun dnsList(): List<String> = lines(dnsServers).ifEmpty { listOf("8.8.8.8", "8.8.4.4") }

    /** JSON accepted by Tunnel.updateSettings and inside the start config. */
    fun toJson(): JSONObject = JSONObject()
        .put("exclusions", JSONArray(lines(exclusions)))
        .put("tunnelOnly", JSONArray(lines(tunnelOnly)))
        .put("dnsServers", JSONArray(dnsList()))
        .put("exclusionDNSMode", "public")
        .put("blockQUIC", blockQuic)

    companion object {
        fun lines(s: String) = s.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }
    }
}

/** Profiles and settings in app-private storage (readable only by this app). */
object Repo {
    private lateinit var file: File
    private val lock = Any()

    var profiles: List<Profile> = emptyList()
        private set
    var selectedId: String? = null
        private set
    var settings = Settings()
        private set

    fun init(ctx: Context) {
        file = File(ctx.filesDir, "state.json")
        load()
    }

    fun selected(): Profile? = profiles.firstOrNull { it.id == selectedId } ?: profiles.firstOrNull()

    /** Parses a link, config file or key with the Go core and saves it. */
    fun import(text: String): Profile {
        val json = Vpncore.parseProfile(text)
        val summary = Vpncore.summarizeProfile(json)
        val name = JSONObject(summary).optString("name").ifBlank { "Профиль ${profiles.size + 1}" }
        val p = Profile(UUID.randomUUID().toString().take(8), name, json, summary)
        synchronized(lock) {
            profiles = profiles + p
            if (selectedId == null) selectedId = p.id
            save()
        }
        return p
    }

    fun select(id: String) = synchronized(lock) { selectedId = id; save() }

    fun delete(id: String) = synchronized(lock) {
        profiles = profiles.filterNot { it.id == id }
        if (selectedId == id) selectedId = profiles.firstOrNull()?.id
        save()
    }

    fun updateSettings(s: Settings) = synchronized(lock) { settings = s; save() }

    private fun load() {
        if (!file.exists()) return
        runCatching {
            val o = JSONObject(file.readText())
            val arr = o.optJSONArray("profiles") ?: JSONArray()
            profiles = (0 until arr.length()).map {
                val p = arr.getJSONObject(it)
                Profile(p.getString("id"), p.getString("name"), p.getString("json"), p.optString("summary"))
            }
            selectedId = o.optString("selected").ifBlank { null }
            o.optJSONObject("settings")?.let { s ->
                settings = Settings(
                    exclusions = s.optString("exclusions"),
                    tunnelOnly = s.optString("tunnelOnly"),
                    dnsServers = s.optString("dnsServers", Settings().dnsServers),
                    blockQuic = s.optBoolean("blockQuic", true),
                )
            }
        }
    }

    private fun save() {
        val arr = JSONArray()
        profiles.forEach {
            arr.put(JSONObject().put("id", it.id).put("name", it.name).put("json", it.json).put("summary", it.summary))
        }
        val s = JSONObject()
            .put("exclusions", settings.exclusions)
            .put("tunnelOnly", settings.tunnelOnly)
            .put("dnsServers", settings.dnsServers)
            .put("blockQuic", settings.blockQuic)
        val o = JSONObject().put("profiles", arr).put("selected", selectedId ?: "").put("settings", s)
        val tmp = File(file.parentFile, "state.json.tmp")
        tmp.writeText(o.toString())
        tmp.renameTo(file)
    }
}
