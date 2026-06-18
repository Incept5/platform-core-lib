package org.incept5.platform.core.ratelimit.ip

import org.assertj.core.api.Assertions.assertThat
import org.incept5.platform.core.ratelimit.config.ClientIpStrategy
import org.junit.jupiter.api.Test

class ClientIpResolutionTest {

    // --- AC1: spoof resistance with the trusted-proxy-hop default (ALB + Kong = 2 hops) ---

    @Test
    fun `AC1 - spoofed leftmost XFF values do not change the resolved client IP`() {
        // Topology: client -> ALB -> Kong -> app. Trusted proxies append on the right, so the
        // genuine client IP is the 2nd-from-right entry regardless of how many values the
        // attacker prepends.
        val genuineClient = "203.0.113.7"
        val alb = "10.0.0.1"

        // Request 1: attacker prepends one random value
        val ip1 = resolveTrustedHops("66.66.66.66, $genuineClient, $alb")
        // Request 2: attacker prepends three different random values
        val ip2 = resolveTrustedHops("1.1.1.1, 2.2.2.2, 3.3.3.3, $genuineClient, $alb")

        assertThat(ip1).isEqualTo(genuineClient)
        assertThat(ip2).isEqualTo(genuineClient)
        assertThat(ip1).isEqualTo(ip2) // same bucket -> the limit holds
    }

    @Test
    fun `AC2 - genuine proxied client IP is preserved for a normal request`() {
        // Normal request through ALB + Kong: XFF = "<client>, <alb>"
        val ip = resolveTrustedHops("203.0.113.7, 10.0.0.1")
        assertThat(ip).isEqualTo("203.0.113.7")
    }

    @Test
    fun `trusted hops clamps to leftmost when the chain is shorter than configured`() {
        // Dev/local: only one entry present though 2 hops configured -> take what's there.
        val ip = resolveTrustedHops("203.0.113.7")
        assertThat(ip).isEqualTo("203.0.113.7")
    }

    @Test
    fun `trusted hops handles whitespace and empty segments`() {
        val ip = resolveTrustedHops("  spoof ,  203.0.113.7 ,  10.0.0.1  ")
        assertThat(ip).isEqualTo("203.0.113.7")
    }

    @Test
    fun `trusted hops falls back to X-Real-IP then remote when XFF absent`() {
        assertThat(
            ClientIpResolution.resolve(null, "198.51.100.9", "10.9.9.9", ClientIpStrategy.TRUSTED_PROXY_HOPS, 2)
        ).isEqualTo("198.51.100.9")

        assertThat(
            ClientIpResolution.resolve(null, null, "10.9.9.9", ClientIpStrategy.TRUSTED_PROXY_HOPS, 2)
        ).isEqualTo("10.9.9.9")
    }

    @Test
    fun `trusted hops with a single trusted proxy takes the rightmost entry`() {
        // 1 hop (ALB only): client is the last/rightmost XFF value.
        val ip = ClientIpResolution.resolve("203.0.113.7", null, null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 1)
        assertThat(ip).isEqualTo("203.0.113.7")

        val spoofed = ClientIpResolution.resolve("9.9.9.9, 203.0.113.7", null, null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 1)
        assertThat(spoofed).isEqualTo("203.0.113.7")
    }

    // --- other strategies ---

    @Test
    fun `LEFTMOST_XFF returns the leftmost value (legacy, spoofable)`() {
        val ip = ClientIpResolution.resolve("66.66.66.66, 203.0.113.7, 10.0.0.1", null, null, ClientIpStrategy.LEFTMOST_XFF, 2)
        assertThat(ip).isEqualTo("66.66.66.66")
    }

    @Test
    fun `X_REAL_IP uses the header and falls back to remote`() {
        assertThat(
            ClientIpResolution.resolve("1.2.3.4", "198.51.100.9", "10.0.0.1", ClientIpStrategy.X_REAL_IP, 2)
        ).isEqualTo("198.51.100.9")
        assertThat(
            ClientIpResolution.resolve("1.2.3.4", "  ", "10.0.0.1", ClientIpStrategy.X_REAL_IP, 2)
        ).isEqualTo("10.0.0.1")
    }

    @Test
    fun `REMOTE_ADDR ignores forwarding headers`() {
        val ip = ClientIpResolution.resolve("66.66.66.66, 203.0.113.7", "198.51.100.9", "10.0.0.1", ClientIpStrategy.REMOTE_ADDR, 2)
        assertThat(ip).isEqualTo("10.0.0.1")
    }

    @Test
    fun `returns unknown when nothing resolvable`() {
        assertThat(
            ClientIpResolution.resolve(null, null, null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 2)
        ).isEqualTo(ClientIpResolution.UNKNOWN)
        assertThat(
            ClientIpResolution.resolve("   ", "  ", null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 2)
        ).isEqualTo(ClientIpResolution.UNKNOWN)
    }

    @Test
    fun `trusted hops coerces a zero or negative hop count to one`() {
        val ip = ClientIpResolution.resolve("203.0.113.7, 10.0.0.1", null, null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 0)
        assertThat(ip).isEqualTo("10.0.0.1") // 1 hop -> rightmost
    }

    private fun resolveTrustedHops(xff: String): String =
        ClientIpResolution.resolve(xff, null, null, ClientIpStrategy.TRUSTED_PROXY_HOPS, 2)
}
