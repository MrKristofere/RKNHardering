package com.notcvnt.rknhardering.probe

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class UnderlyingNetworkProberTest {

    @Test
    fun `build diagnostics returns null when debug disabled`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = false,
            modeOverride = TunProbeModeOverride.AUTO,
            activeNetworkIsVpn = true,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = true,
            vpnInterfaceName = "tun0",
            vpnComparison = successfulComparison("198.51.100.10"),
            underlyingInterfaceName = "wlan0",
            underlyingComparison = successfulComparison("203.0.113.10"),
        )

        assertNull(diagnostics)
    }

    @Test
    fun `build diagnostics keeps override and both paths`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = true,
            modeOverride = TunProbeModeOverride.CURL_COMPATIBLE,
            activeNetworkIsVpn = false,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = true,
            vpnInterfaceName = "tun0",
            vpnComparison = successfulComparison("198.51.100.10"),
            underlyingInterfaceName = "wlan0",
            underlyingComparison = successfulComparison("203.0.113.10"),
        )

        assertNotNull(diagnostics)
        assertEquals(TunProbeModeOverride.CURL_COMPATIBLE, diagnostics?.modeOverride)
        assertEquals("tun0", diagnostics?.vpnPath?.interfaceName)
        assertEquals("wlan0", diagnostics?.underlyingPath?.interfaceName)
        assertFalse(diagnostics?.vpnPath?.dnsPathMismatch ?: true)
    }

    @Test
    fun `build diagnostics preserves auto mismatch on vpn path`() {
        val diagnostics = UnderlyingNetworkProber.buildTunProbeDiagnostics(
            debugEnabled = true,
            modeOverride = TunProbeModeOverride.AUTO,
            activeNetworkIsVpn = true,
            vpnNetworkPresent = true,
            underlyingNetworkPresent = false,
            vpnInterfaceName = "tun0",
            vpnComparison = PublicIpNetworkComparison(
                strict = PublicIpModeProbeResult(
                    mode = PublicIpProbeMode.STRICT_SAME_PATH,
                    status = PublicIpProbeStatus.FAILED,
                    error = "strict timeout",
                ),
                curlCompatible = PublicIpModeProbeResult(
                    mode = PublicIpProbeMode.CURL_COMPATIBLE,
                    status = PublicIpProbeStatus.SUCCEEDED,
                    ip = "198.51.100.10",
                ),
                selectedMode = PublicIpProbeMode.CURL_COMPATIBLE,
                selectedIp = "198.51.100.10",
                dnsPathMismatch = true,
            ),
            underlyingInterfaceName = null,
            underlyingComparison = null,
        )

        assertTrue(diagnostics?.vpnPath?.dnsPathMismatch == true)
        assertNull(diagnostics?.underlyingPath)
    }

    @Test
    fun `probe returns both targets when both succeed`() {
        val ruComparison = successfulComparison("198.51.100.10")
        val nonRuComparison = successfulComparison("203.0.113.10")

        val ruTarget = PerTargetProbe(
            targetHost = "ifconfig.yandex.ru",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = "198.51.100.10",
            directIp = "203.0.113.1",
            comparison = ruComparison,
        )
        val nonRuTarget = PerTargetProbe(
            targetHost = "api.ipify.org",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = "203.0.113.10",
            directIp = "203.0.113.2",
            comparison = nonRuComparison,
        )

        assertEquals("198.51.100.10", ruTarget.vpnIp)
        assertEquals("203.0.113.10", nonRuTarget.vpnIp)
        assertEquals("203.0.113.1", ruTarget.directIp)
        assertEquals("203.0.113.2", nonRuTarget.directIp)
    }

    @Test
    fun `probe survives ru target failure`() {
        val ruFailure = PublicIpNetworkComparison(
            strict = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.FAILED,
                error = "RU endpoint timeout",
            ),
            curlCompatible = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = "Disabled by override",
            ),
            selectedMode = null,
            selectedIp = null,
            selectedError = "RU endpoint timeout",
        )
        val nonRuComparison = successfulComparison("203.0.113.10")

        val ruTarget = PerTargetProbe(
            targetHost = "ifconfig.yandex.ru",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = null,
            comparison = ruFailure,
            error = "RU endpoint timeout",
        )
        val nonRuTarget = PerTargetProbe(
            targetHost = "api.ipify.org",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = "203.0.113.10",
            comparison = nonRuComparison,
        )

        assertNull(ruTarget.vpnIp)
        assertNotNull(ruTarget.error)
        assertEquals("RU endpoint timeout", ruTarget.error)
        assertEquals("203.0.113.10", nonRuTarget.vpnIp)
    }

    @Test
    fun `probe flags divergence when vpn ips differ across targets`() {
        val ruComparison = successfulComparison("198.51.100.10")
        val nonRuComparison = successfulComparison("203.0.113.10")

        val ruTarget = PerTargetProbe(
            targetHost = "ifconfig.yandex.ru",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.RU,
            vpnIp = "198.51.100.10",
            comparison = ruComparison,
        )
        val nonRuTarget = PerTargetProbe(
            targetHost = "api.ipify.org",
            targetGroup = com.notcvnt.rknhardering.model.TargetGroup.NON_RU,
            vpnIp = "203.0.113.10",
            comparison = nonRuComparison,
        )

        assertNotNull(ruTarget.vpnIp)
        assertNotNull(nonRuTarget.vpnIp)
        assertFalse(ruTarget.vpnIp == nonRuTarget.vpnIp)
        assertTrue(ruTarget.vpnIp != nonRuTarget.vpnIp)
    }

    private fun successfulComparison(ip: String): PublicIpNetworkComparison {
        return PublicIpNetworkComparison(
            strict = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.STRICT_SAME_PATH,
                status = PublicIpProbeStatus.SUCCEEDED,
                ip = ip,
            ),
            curlCompatible = PublicIpModeProbeResult(
                mode = PublicIpProbeMode.CURL_COMPATIBLE,
                status = PublicIpProbeStatus.SKIPPED,
                error = "Disabled by override",
            ),
            selectedMode = PublicIpProbeMode.STRICT_SAME_PATH,
            selectedIp = ip,
        )
    }
}
