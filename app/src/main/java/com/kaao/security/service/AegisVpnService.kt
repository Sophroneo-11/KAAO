package com.kaao.security.service

import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.ServiceCompat
import com.kaao.security.core.notification.KaaoNotificationChannels
import com.kaao.security.data.local.prefs.KaaoPreferencesRepository
import com.kaao.security.domain.model.AegisVpnMode
import com.kaao.security.domain.model.DohProvider
import com.kaao.security.engine.network.AegisVpnController
import com.kaao.security.engine.network.DnsPacketParser
import com.kaao.security.engine.network.DohClient
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okhttp3.OkHttpClient
import java.io.FileInputStream
import java.io.FileOutputStream
import javax.inject.Inject

/**
 * Zero-root local VpnService supporting:
 * 1) Split-routed RFC 8484 DNS-over-HTTPS phishing/malware/adware sinkhole (routes ONLY virtual DNS 10.111.222.2/32).
 * 2) Game Mode background bandwidth firewall (routes 0.0.0.0/0 & ::/0 into TUN drain while excluding active game via addDisallowedApplication).
 */
@AndroidEntryPoint
class AegisVpnService : VpnService() {

    @Inject lateinit var vpnController: AegisVpnController
    @Inject lateinit var dohClient: DohClient
    @Inject lateinit var prefs: KaaoPreferencesRepository

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val tunWriteMutex = Mutex()

    private var vpnInterface: ParcelFileDescriptor? = null
    private var packetLoopJob: Job? = null
    private var protectedOkHttp: OkHttpClient? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP_VPN -> {
                teardownTunnelAndStop()
                return START_NOT_STICKY
            }

            ACTION_START_GAME_FIREWALL -> {
                val gamePkg = intent.getStringExtra(EXTRA_GAME_PACKAGE)
                val gameName = intent.getStringExtra(EXTRA_GAME_NAME) ?: gamePkg ?: "Active Game"
                val exceptions = intent.getStringArrayListExtra(EXTRA_EXCEPTION_PACKAGES)?.toSet()
                    ?: emptySet()
                if (gamePkg.isNullOrBlank()) {
                    teardownTunnelAndStop()
                    return START_NOT_STICKY
                }
                val excLabel = if (exceptions.isNotEmpty()) {
                    " + ${exceptions.size} voice/app exception(s)"
                } else {
                    ""
                }
                promoteToForeground(
                    title = "KAAO Game Firewall Active",
                    subtitle = "Prioritizing $gameName$excLabel • Background apps blocked"
                )
                serviceScope.launch {
                    startGameFirewallTunnel(gamePkg, gameName, exceptions)
                }
            }

            else -> {
                val providerId = intent?.getStringExtra(EXTRA_DOH_PROVIDER_ID)
                promoteToForeground(
                    title = "KAAO Aegis DNS Shield Active",
                    subtitle = "Split-routed RFC 8484 DoH phishing & malware filter"
                )
                serviceScope.launch {
                    val settings = prefs.getSettings()
                    val provider = providerId?.let { id ->
                        DohProvider.entries.firstOrNull { it.id == id }
                    } ?: settings.dohProvider
                    startSplitRouteDnsTunnel(provider)
                }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        teardownTunnelAndStop()
        super.onRevoke()
    }

    override fun onDestroy() {
        closeTunnelInternal()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun promoteToForeground(title: String, subtitle: String) {
        val notification = KaaoNotificationChannels.buildOngoingShieldNotification(
            context = this,
            title = title,
            subtitle = subtitle
        )
        val fgType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, KaaoNotificationChannels.NOTIF_ID_VPN, notification, fgType)
    }

    private suspend fun startSplitRouteDnsTunnel(provider: DohProvider) {
        closeTunnelInternal()
        vpnController.reloadMatcherRules()

        val builder = Builder()
            .setSession("KAAO Aegis DoH Shield")
            .setMtu(1500)
            .addAddress(TUN_LOCAL_IPV4, 32)
            .addDnsServer(TUN_VIRTUAL_DNS_IPV4)
            // Split-route ONLY the virtual DNS server so non-DNS traffic incurs zero VPN overhead
            .addRoute(TUN_VIRTUAL_DNS_IPV4, 32)

        runCatching { builder.addDisallowedApplication(packageName) }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val tunFd = runCatching { builder.establish() }.getOrNull()
        if (tunFd == null) {
            vpnController.updateServiceState(
                mode = AegisVpnMode.OFF,
                dohProvider = provider,
                lastError = "VPN permission revoked or unavailable"
            )
            stopSelf()
            return
        }

        vpnInterface = tunFd
        val client = dohClient.createProtectedClient(this)
        protectedOkHttp = client
        vpnController.updateServiceState(
            mode = AegisVpnMode.DNS_SHIELD,
            dohProvider = provider
        )

        packetLoopJob = serviceScope.launch {
            runDnsPacketLoop(tunFd, client, provider)
        }
    }

    private suspend fun startGameFirewallTunnel(
        activeGamePackage: String,
        gameName: String,
        exceptionPackages: Set<String>
    ) {
        closeTunnelInternal()
        val settings = prefs.getSettings()

        val builder = Builder()
            .setSession("KAAO Game Firewall: $gameName")
            .setMtu(1500)
            .addAddress(TUN_LOCAL_IPV4, 32)
            .addAddress(TUN_LOCAL_IPV6, 128)
            // Route all background app traffic into TUN drain
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)

        // Exclude the active game, KAAO itself, and user-approved voice-chat/companion apps
        runCatching { builder.addDisallowedApplication(activeGamePackage) }
        runCatching { builder.addDisallowedApplication(packageName) }
        exceptionPackages.forEach { exceptionPkg ->
            if (exceptionPkg.isNotBlank()) {
                runCatching { builder.addDisallowedApplication(exceptionPkg) }
            }
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setMetered(false)
        }

        val tunFd = runCatching { builder.establish() }.getOrNull()
        if (tunFd == null) {
            vpnController.updateServiceState(
                mode = AegisVpnMode.OFF,
                dohProvider = settings.dohProvider,
                lastError = "Unable to establish Game Firewall VPN"
            )
            stopSelf()
            return
        }

        vpnInterface = tunFd
        vpnController.updateServiceState(
            mode = AegisVpnMode.GAME_FIREWALL,
            dohProvider = settings.dohProvider,
            activeGamePackage = activeGamePackage,
            activeGameName = gameName
        )

        packetLoopJob = serviceScope.launch {
            drainBackgroundPackets(tunFd)
        }
    }

    private suspend fun runDnsPacketLoop(
        tunFd: ParcelFileDescriptor,
        httpClient: OkHttpClient,
        provider: DohProvider
    ) {
        val input = FileInputStream(tunFd.fileDescriptor)
        val output = FileOutputStream(tunFd.fileDescriptor)
        val buffer = ByteArray(4096)

        while (serviceScope.isActive) {
            val bytesRead = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (bytesRead <= 0) break

            val packetCopy = buffer.copyOf(bytesRead)
            val parsed = DnsPacketParser.parseIpv4UdpDnsQuery(packetCopy, bytesRead) ?: continue

            serviceScope.launch {
                val startMs = SystemClock.elapsedRealtime()
                val decision = vpnController.matcher.evaluate(parsed.queryDomain)

                val dnsResponsePayload = if (decision.blocked) {
                    DnsPacketParser.buildSinkholeDnsPayload(parsed)
                } else {
                    dohClient.resolveWireQuery(httpClient, provider, parsed.dnsPayload)
                }

                if (dnsResponsePayload != null) {
                    val responseIpPacket = DnsPacketParser.buildIpv4UdpResponsePacket(
                        originalQuery = parsed,
                        dnsResponsePayload = dnsResponsePayload
                    )
                    tunWriteMutex.withLock {
                        runCatching { output.write(responseIpPacket) }
                    }
                }

                val latencyMs = (SystemClock.elapsedRealtime() - startMs).coerceAtLeast(0L)
                vpnController.recordDnsQuery(
                    domain = parsed.queryDomain,
                    queryType = parsed.queryTypeLabel,
                    blocked = decision.blocked,
                    category = decision.category,
                    latencyMs = latencyMs
                )
            }
        }
    }

    private fun drainBackgroundPackets(tunFd: ParcelFileDescriptor) {
        val input = FileInputStream(tunFd.fileDescriptor)
        val buffer = ByteArray(4096)
        while (serviceScope.isActive) {
            val read = runCatching { input.read(buffer) }.getOrDefault(-1)
            if (read <= 0) break
            // Silently discard background traffic from non-excluded apps to preserve game bandwidth
        }
    }

    private fun closeTunnelInternal() {
        packetLoopJob?.cancel()
        packetLoopJob = null
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        protectedOkHttp = null
    }

    private fun teardownTunnelAndStop() {
        closeTunnelInternal()
        vpnController.updateServiceState(
            mode = AegisVpnMode.OFF,
            dohProvider = vpnController.vpnState.value.dohProvider
        )
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        const val ACTION_START_DNS_SHIELD = "com.kaao.security.action.START_DNS_SHIELD"
        const val ACTION_START_GAME_FIREWALL = "com.kaao.security.action.START_GAME_FIREWALL"
        const val ACTION_STOP_VPN = "com.kaao.security.action.STOP_VPN"

        const val EXTRA_DOH_PROVIDER_ID = "extra_doh_provider_id"
        const val EXTRA_GAME_PACKAGE = "extra_game_package"
        const val EXTRA_GAME_NAME = "extra_game_name"
        const val EXTRA_EXCEPTION_PACKAGES = "extra_exception_packages"

        private const val TUN_LOCAL_IPV4 = "10.111.222.1"
        private const val TUN_VIRTUAL_DNS_IPV4 = "10.111.222.2"
        private const val TUN_LOCAL_IPV6 = "fd00:1:ca00::1"
    }
}
