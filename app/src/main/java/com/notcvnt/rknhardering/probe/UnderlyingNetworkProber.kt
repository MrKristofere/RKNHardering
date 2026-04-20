package com.notcvnt.rknhardering.probe

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.notcvnt.rknhardering.network.DnsResolverConfig
import com.notcvnt.rknhardering.network.NetworkInterfaceNameNormalizer
import com.notcvnt.rknhardering.network.ResolverBinding
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class PerTargetProbe(
    val targetHost: String,
    val targetGroup: com.notcvnt.rknhardering.model.TargetGroup,
    val directIp: String? = null,
    val vpnIp: String? = null,
    val comparison: PublicIpNetworkComparison? = null,
    val error: String? = null,
)

/**
 * Detects whether a non-VPN (underlying) network is reachable from this app.
 *
 * When VPN runs in split-tunnel / per-app mode, apps excluded from the tunnel
 * (or any app that can bind to the underlying network) can reach the VPN gateway
 * and any external host directly, leaking the real IP and confirming VPN usage.
 *
 * The probe enumerates all networks, finds one without TRANSPORT_VPN, binds an
 * HTTPS request to it, and fetches the public IP. Success means split-tunnel
 * vulnerability is present.
 */
object UnderlyingNetworkProber {
    private data class BoundNetwork(
        val network: Network,
        val interfaceName: String?,
    )

    data class ProbeResult(
        val vpnActive: Boolean,
        val underlyingReachable: Boolean = false,
        val ruTarget: PerTargetProbe = PerTargetProbe(
            targetHost = "",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
        ),
        val nonRuTarget: PerTargetProbe = PerTargetProbe(
            targetHost = "",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
        ),
        val vpnError: String? = null,
        val underlyingError: String? = null,
        val dnsPathMismatch: Boolean = false,
        val vpnNetwork: android.net.Network? = null,
        val underlyingNetwork: android.net.Network? = null,
        val activeNetworkIsVpn: Boolean? = null,
        val tunProbeDiagnostics: TunProbeDiagnostics? = null,
    ) {
        val vpnIp: String? get() = ruTarget.vpnIp ?: nonRuTarget.vpnIp
        val underlyingIp: String? get() = ruTarget.directIp ?: nonRuTarget.directIp
        val vpnIpComparison: PublicIpNetworkComparison?
            get() = ruTarget.comparison ?: nonRuTarget.comparison
        val underlyingIpComparison: PublicIpNetworkComparison?
            get() = ruTarget.comparison ?: nonRuTarget.comparison
    }

    private const val RU_PROBE_HOST = "ifconfig.yandex.ru"
    private const val NON_RU_PROBE_HOST = "api.ipify.org"

    @Suppress("DEPRECATION")
    suspend fun probe(
        context: Context,
        resolverConfig: DnsResolverConfig = DnsResolverConfig.system(),
        debugEnabled: Boolean = false,
        modeOverride: TunProbeModeOverride = TunProbeModeOverride.AUTO,
    ): ProbeResult = withContext(Dispatchers.IO) {
        NativeCurlBridge.initIfNeeded(context)
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val activeNetwork = cm.activeNetwork
        val activeNetworkIsVpn = activeNetwork
            ?.let(cm::getNetworkCapabilities)
            ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

        val allNetworks = cm.allNetworks
        var vpnNetwork: BoundNetwork? = null
        val nonVpnNetworks = mutableListOf<BoundNetwork>()

        for (network in allNetworks) {
            val caps = cm.getNetworkCapabilities(network) ?: continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val boundNetwork = BoundNetwork(
                network = network,
                interfaceName = NetworkInterfaceNameNormalizer.canonicalName(
                    cm.getLinkProperties(network)?.interfaceName,
                ),
            )
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                vpnNetwork = boundNetwork
            } else {
                nonVpnNetworks.add(boundNetwork)
            }
        }

        if (vpnNetwork == null) {
            return@withContext ProbeResult(
                vpnActive = false,
                underlyingReachable = false,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = false,
                    underlyingNetworkPresent = nonVpnNetworks.isNotEmpty(),
                    vpnInterfaceName = null,
                    vpnComparison = null,
                    underlyingInterfaceName = nonVpnNetworks.firstOrNull()?.interfaceName,
                    underlyingComparison = null,
                ),
            )
        }

        val ruVpnComparison = fetchIpViaNetworkComparison(vpnNetwork, resolverConfig, debugEnabled, modeOverride, RU_PROBE_HOST)
        val nonRuVpnComparison = fetchIpViaNetworkComparison(vpnNetwork, resolverConfig, debugEnabled, modeOverride, NON_RU_PROBE_HOST)
        val vpnError = ruVpnComparison.selectedError ?: nonRuVpnComparison.selectedError

        val ruVpnProbe = PerTargetProbe(
            targetHost = RU_PROBE_HOST,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = ruVpnComparison.selectedIp,
            comparison = ruVpnComparison,
            error = ruVpnComparison.selectedError,
        )
        val nonRuVpnProbe = PerTargetProbe(
            targetHost = NON_RU_PROBE_HOST,
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = nonRuVpnComparison.selectedIp,
            comparison = nonRuVpnComparison,
            error = nonRuVpnComparison.selectedError,
        )

        if (nonVpnNetworks.isEmpty()) {
            return@withContext ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                ruTarget = ruVpnProbe,
                nonRuTarget = nonRuVpnProbe,
                vpnError = vpnError,
                dnsPathMismatch = ruVpnComparison.dnsPathMismatch,
                vpnNetwork = vpnNetwork.network,
                activeNetworkIsVpn = activeNetworkIsVpn,
                tunProbeDiagnostics = buildTunProbeDiagnostics(
                    debugEnabled = debugEnabled,
                    modeOverride = modeOverride,
                    activeNetworkIsVpn = activeNetworkIsVpn,
                    vpnNetworkPresent = true,
                    underlyingNetworkPresent = false,
                    vpnInterfaceName = vpnNetwork.interfaceName,
                    vpnComparison = ruVpnComparison,
                    underlyingInterfaceName = null,
                    underlyingComparison = null,
                ),
            )
        }

        var ruUnderlyingIp: String? = null
        var ruUnderlyingError: String? = null
        var nonRuUnderlyingIp: String? = null
        var nonRuUnderlyingError: String? = null
        var usedNetwork: Network? = null
        var usedBoundNetwork: BoundNetwork? = null
        var ruUnderlyingComparison: PublicIpNetworkComparison? = null
        var nonRuUnderlyingComparison: PublicIpNetworkComparison? = null
        var lastUnderlyingNetwork: BoundNetwork? = null

        for (network in nonVpnNetworks) {
            lastUnderlyingNetwork = network

            // Probe RU target
            val ruResult = fetchIpViaNetworkComparison(network, resolverConfig, debugEnabled, modeOverride, RU_PROBE_HOST)
            ruUnderlyingComparison = ruResult
            ruUnderlyingIp = ruResult.selectedIp
            ruUnderlyingError = ruResult.selectedError ?: ruUnderlyingError

            // Probe non-RU target
            val nonRuResult = fetchIpViaNetworkComparison(network, resolverConfig, debugEnabled, modeOverride, NON_RU_PROBE_HOST)
            nonRuUnderlyingComparison = nonRuResult
            nonRuUnderlyingIp = nonRuResult.selectedIp
            nonRuUnderlyingError = nonRuResult.selectedError ?: nonRuUnderlyingError

            // Consider both targets successful if either reached
            if (ruUnderlyingIp != null || nonRuUnderlyingIp != null) {
                usedNetwork = network.network
                usedBoundNetwork = network
                break
            }
        }

        val ruTarget = ruVpnProbe.copy(
            directIp = ruUnderlyingIp,
            comparison = ruUnderlyingComparison ?: ruVpnComparison,
            error = if (ruUnderlyingIp == null && ruUnderlyingError != null) ruUnderlyingError else ruVpnComparison.selectedError,
        )
        val nonRuTarget = nonRuVpnProbe.copy(
            directIp = nonRuUnderlyingIp,
            comparison = nonRuUnderlyingComparison ?: nonRuVpnComparison,
            error = if (nonRuUnderlyingIp == null && nonRuUnderlyingError != null) nonRuUnderlyingError else nonRuVpnComparison.selectedError,
        )

        ProbeResult(
            vpnActive = true,
            underlyingReachable = ruUnderlyingIp != null || nonRuUnderlyingIp != null,
            ruTarget = ruTarget,
            nonRuTarget = nonRuTarget,
            vpnError = vpnError,
            underlyingError = ruUnderlyingError ?: nonRuUnderlyingError,
            dnsPathMismatch = ruVpnComparison.dnsPathMismatch ||
                nonRuVpnComparison.dnsPathMismatch ||
                (ruUnderlyingComparison?.dnsPathMismatch == true) ||
                (nonRuUnderlyingComparison?.dnsPathMismatch == true),
            vpnNetwork = vpnNetwork.network,
            underlyingNetwork = usedNetwork,
            activeNetworkIsVpn = activeNetworkIsVpn,
            tunProbeDiagnostics = buildTunProbeDiagnostics(
                debugEnabled = debugEnabled,
                modeOverride = modeOverride,
                activeNetworkIsVpn = activeNetworkIsVpn,
                vpnNetworkPresent = true,
                underlyingNetworkPresent = true,
                vpnInterfaceName = vpnNetwork.interfaceName,
                vpnComparison = ruVpnComparison,
                underlyingInterfaceName = (usedBoundNetwork ?: lastUnderlyingNetwork)?.interfaceName,
                underlyingComparison = ruUnderlyingComparison ?: nonRuUnderlyingComparison,
            ),
        )
    }

    private suspend fun fetchIpViaNetworkComparison(
        boundNetwork: BoundNetwork,
        resolverConfig: DnsResolverConfig,
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        targetHost: String? = null,
    ): PublicIpNetworkComparison {
        val fallbackBinding = boundNetwork.interfaceName
            ?.takeIf { it.isNotBlank() }
            ?.let { ResolverBinding.OsDeviceBinding(it, dnsMode = ResolverBinding.DnsMode.SYSTEM) }

        return IfconfigClient.fetchIpViaNetworkComparison(
            primaryBinding = ResolverBinding.AndroidNetworkBinding(boundNetwork.network),
            fallbackBinding = fallbackBinding,
            resolverConfig = resolverConfig,
            modeOverride = modeOverride,
            collectTrace = debugEnabled,
            targetHost = targetHost,
        )
    }

    internal fun buildTunProbeDiagnostics(
        debugEnabled: Boolean,
        modeOverride: TunProbeModeOverride,
        activeNetworkIsVpn: Boolean?,
        vpnNetworkPresent: Boolean,
        underlyingNetworkPresent: Boolean,
        vpnInterfaceName: String?,
        vpnComparison: PublicIpNetworkComparison?,
        underlyingInterfaceName: String?,
        underlyingComparison: PublicIpNetworkComparison?,
    ): TunProbeDiagnostics? {
        if (!debugEnabled) return null

        return TunProbeDiagnostics(
            enabled = true,
            modeOverride = modeOverride,
            activeNetworkIsVpn = activeNetworkIsVpn,
            vpnNetworkPresent = vpnNetworkPresent,
            underlyingNetworkPresent = underlyingNetworkPresent,
            vpnPath = vpnComparison?.toPathDiagnostics(vpnInterfaceName),
            underlyingPath = underlyingComparison?.toPathDiagnostics(underlyingInterfaceName),
        )
    }
}
