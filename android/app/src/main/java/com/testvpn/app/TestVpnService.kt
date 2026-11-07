package com.testvpn.app

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import com.testvpn.core.vpncore.Logger
import com.testvpn.core.vpncore.StatusListener
import com.testvpn.core.vpncore.Store
import com.testvpn.core.vpncore.Tunnel
import com.testvpn.core.vpncore.Vpncore
import org.json.JSONObject
import kotlin.concurrent.thread

/**
 * Runs the Go core on the TUN interface of VpnService.
 *
 * All traffic of other apps (IPv4 and IPv6) goes into the interface; the core
 * sends it through the VPN, connects excluded domains directly and drops
 * IPv6. This app itself is excluded from the VPN, so the core's own sockets
 * (to the server and to excluded domains) use the physical network without
 * per-socket protect(). While the core cannot reach the server it keeps the
 * interface and rejects connections, so nothing leaks (kill switch).
 */
class TestVpnService : VpnService() {
    private var tunnel: Tunnel? = null
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    private val lock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            // ACTION_CONNECT from the app, SERVICE_INTERFACE from "Always-on VPN".
            else -> thread(name = "vpn-start") { startTunnel() }
        }
        return START_STICKY
    }

    private fun startTunnel() = synchronized(lock) {
        stopTunnelLocked()
        val profile = Repo.selected()
        if (profile == null) {
            VpnState.log("нет профиля: импортируйте его в приложении")
            VpnState.setStatus(Status(state = "failed", error = "Нет профиля"))
            stopSelf()
            return
        }
        val settings = Repo.settings
        val builder = Builder()
            .setSession(profile.name)
            .setMtu(MTU)
            .addAddress("10.255.0.2", 32)
            .addRoute("0.0.0.0", 0)
            // IPv6 is captured too and dropped by the core: the servers have none.
            .addAddress("fd00:255::2", 128)
            .addRoute("::", 0)
            .addDisallowedApplication(packageName)
            .setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        settings.dnsList().forEach { runCatching { builder.addDnsServer(it) } }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            VpnState.log("не удалось создать интерфейс: ${e.message}")
            null
        }
        if (pfd == null) {
            // Not prepared (permission revoked) or another app took the VPN.
            VpnState.setStatus(Status(state = "failed", error = "Нет разрешения на VPN"))
            stopSelf()
            return
        }
        val config = settings.toJson()
            .put("profile", JSONObject(profile.json))
            .put("mtu", MTU)
            .put("networkID", currentNetworkId())
        try {
            // The core owns the descriptor from now on.
            tunnel = Vpncore.startWithFD(config.toString(), pfd.detachFd(), listener, logger, MemoryStore(this))
            watchNetwork()
        } catch (e: Exception) {
            pfd.close()
            VpnState.log("ошибка запуска: ${e.message}")
            VpnState.setStatus(Status(state = "failed", error = e.message ?: "ошибка"))
            stopSelf()
        }
    }

    /** Applies settings to the running tunnel without reconnecting. */
    fun applySettings() = synchronized(lock) {
        tunnel?.updateSettings(Repo.settings.toJson().toString())
    }

    private fun stopTunnel() = synchronized(lock) { stopTunnelLocked() }

    private fun stopTunnelLocked() {
        main.removeCallbacks(retry)
        netCallback?.let { runCatching { connectivity().unregisterNetworkCallback(it) } }
        netCallback = null
        tunnel?.stop()
        tunnel = null
        VpnState.setStatus(Status())
    }

    private fun connectivity() = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private fun currentNetworkId(): String = connectivity().activeNetwork?.toString() ?: ""

    /** Tells the core about network switches (Wi-Fi ↔ mobile), so it reconnects at once. */
    private fun watchNetwork() {
        var last = currentNetworkId()
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                setUnderlyingNetworks(arrayOf(network))
                // The first callback reports the network the tunnel started on.
                if (network.toString() != last) {
                    last = network.toString()
                    tunnel?.networkChanged(last, 0, "")
                }
            }
        }
        connectivity().registerDefaultNetworkCallback(cb)
        netCallback = cb
    }

    override fun onRevoke() {
        // Another VPN app took over or the user turned us off in system settings.
        stopTunnel()
        stopSelf()
    }

    override fun onDestroy() {
        stopTunnel()
        instance = null
        super.onDestroy()
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
    }

    private val main = Handler(Looper.getMainLooper())

    /**
     * After all attempts fail the core stays in "failed" (traffic blocked) and
     * waits; like the desktop daemon, retry every 30 seconds.
     */
    private val retry = object : Runnable {
        override fun run() {
            val t = synchronized(lock) { tunnel } ?: return
            if (VpnState.status.value.state == "failed") {
                VpnState.log("повторная попытка подключения")
                t.reconnect()
                main.postDelayed(this, RETRY_MS)
            }
        }
    }

    private val listener = StatusListener { json ->
        val st = Status.parse(json)
        VpnState.setStatus(st)
        main.post {
            main.removeCallbacks(retry)
            if (st.state == "failed") main.postDelayed(retry, RETRY_MS)
        }
    }
    private val logger = Logger { line -> VpnState.log(line) }

    /** Per-network transport memory of the core in SharedPreferences. */
    private class MemoryStore(ctx: Context) : Store {
        private val prefs = ctx.getSharedPreferences("core", Context.MODE_PRIVATE)
        override fun load(key: String): String = prefs.getString(key, "") ?: ""
        override fun save(key: String, value: String) = prefs.edit().putString(key, value).apply()
    }

    companion object {
        const val ACTION_CONNECT = "com.testvpn.app.CONNECT"
        const val ACTION_DISCONNECT = "com.testvpn.app.DISCONNECT"
        private const val MTU = 9000
        private const val RETRY_MS = 30_000L

        @Volatile
        var instance: TestVpnService? = null
            private set

        fun connect(ctx: Context) = ctx.startService(Intent(ctx, TestVpnService::class.java).setAction(ACTION_CONNECT))
        fun disconnect(ctx: Context) = ctx.startService(Intent(ctx, TestVpnService::class.java).setAction(ACTION_DISCONNECT))
    }
}
