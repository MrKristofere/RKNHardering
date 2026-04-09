package com.notcvnt.rknhardering.checker

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.notcvnt.rknhardering.model.EvidenceItem
import com.notcvnt.rknhardering.model.EvidenceSource
import com.notcvnt.rknhardering.model.Finding
import com.notcvnt.rknhardering.probe.UnderlyingNetworkProber
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

@RunWith(RobolectricTestRunner::class)
class BypassCheckerTest {

    private val context: Context = ApplicationProvider.getApplicationContext()

    @Test
    fun `explicit vpn network binding on non vpn default network is detected`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "185.220.1.10",
                underlyingIp = "91.198.174.192",
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(detected)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertTrue(findings.any { it.description.contains("VPN network binding") })
    }

    @Test
    fun `underlying reachability is treated as gateway leak only when default network is vpn`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "185.220.1.10",
                underlyingIp = "91.198.174.192",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(detected)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK })
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
    }

    @Test
    fun `tun probe success is reported as informational finding`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "185.220.1.10",
                underlyingIp = null,
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("185.220.1.10")
            },
        )
    }

    @Test
    fun `vpn network binding requires verified underlying internet path`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = "185.220.1.10",
                underlyingIp = null,
                activeNetworkIsVpn = false,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(detected)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_NETWORK_BINDING && it.detected })
        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.VPN_NETWORK_BINDING &&
                    it.description.contains("185.220.1.10")
            },
        )
    }

    @Test
    fun `tun probe failure is recorded when vpn active but fetch returned null`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = false,
                vpnIp = null,
                underlyingIp = null,
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(
            findings.any {
                it.isInformational &&
                    it.source == EvidenceSource.TUN_ACTIVE_PROBE &&
                    it.description.contains("unavailable")
            },
        )
    }

    @Test
    fun `gateway leak remains detected when underlying path works but vpn ip probe fails`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = null,
                underlyingIp = "91.198.174.192",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertTrue(detected)
        assertTrue(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(
            findings.any {
                it.source == EvidenceSource.VPN_GATEWAY_LEAK &&
                    it.detected &&
                    it.description.contains("91.198.174.192")
            },
        )
    }

    @Test
    fun `gateway leak not detected when vpn ip and underlying ip are the same`() {
        val findings = mutableListOf<Finding>()
        val evidence = mutableListOf<EvidenceItem>()

        val detected = BypassChecker.reportUnderlyingNetworkResult(
            context = context,
            result = UnderlyingNetworkProber.ProbeResult(
                vpnActive = true,
                underlyingReachable = true,
                vpnIp = "128.71.10.5",
                underlyingIp = "128.71.10.5",
                activeNetworkIsVpn = true,
            ),
            findings = findings,
            evidence = evidence,
        )

        assertFalse(detected)
        assertFalse(evidence.any { it.source == EvidenceSource.VPN_GATEWAY_LEAK && it.detected })
        assertTrue(findings.any { it.isInformational && it.source == EvidenceSource.VPN_GATEWAY_LEAK })
    }
}
