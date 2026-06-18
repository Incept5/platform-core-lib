package org.incept5.platform.core.ratelimit.ip

import org.incept5.platform.core.ratelimit.config.ClientIpStrategy

/**
 * Pure, side-effect-free client-IP resolution. Kept separate from the CDI [ClientIpResolver]
 * bean so the resolution rules can be unit-tested directly from header strings without a
 * container or HTTP request.
 */
object ClientIpResolution {

    const val UNKNOWN = "unknown"

    /**
     * Resolve the client IP from the raw request inputs according to [strategy].
     *
     * @param xForwardedFor raw `X-Forwarded-For` header value (may be null/blank/multi-valued)
     * @param xRealIp raw `X-Real-IP` header value (may be null/blank)
     * @param remoteHost the TCP remote address host (may be null)
     * @param strategy the configured resolution strategy
     * @param trustedProxyHops number of trusted proxies that append to XFF (used by
     *        [ClientIpStrategy.TRUSTED_PROXY_HOPS]); coerced to at least 1
     */
    fun resolve(
        xForwardedFor: String?,
        xRealIp: String?,
        remoteHost: String?,
        strategy: ClientIpStrategy,
        trustedProxyHops: Int,
    ): String {
        val resolved = when (strategy) {
            ClientIpStrategy.REMOTE_ADDR -> remoteHost
            ClientIpStrategy.X_REAL_IP -> xRealIp?.trim()?.ifBlank { null } ?: remoteHost
            ClientIpStrategy.LEFTMOST_XFF -> leftmostXff(xForwardedFor) ?: realIpOrRemote(xRealIp, remoteHost)
            ClientIpStrategy.TRUSTED_PROXY_HOPS ->
                trustedHopXff(xForwardedFor, trustedProxyHops) ?: realIpOrRemote(xRealIp, remoteHost)
        }
        return resolved?.trim()?.ifBlank { null } ?: UNKNOWN
    }

    private fun realIpOrRemote(xRealIp: String?, remoteHost: String?): String? =
        xRealIp?.trim()?.ifBlank { null } ?: remoteHost

    private fun leftmostXff(xForwardedFor: String?): String? =
        parseXff(xForwardedFor).firstOrNull()

    /**
     * Take the Nth-from-right XFF entry, where N = [trustedProxyHops]. Trusted proxies append
     * on the right, so this ignores any spoofed values a caller prepends. If the chain is
     * shorter than expected (e.g. local/dev with fewer proxies) the index clamps to the
     * leftmost present entry rather than failing.
     */
    private fun trustedHopXff(xForwardedFor: String?, trustedProxyHops: Int): String? {
        val parts = parseXff(xForwardedFor)
        if (parts.isEmpty()) return null
        val hops = trustedProxyHops.coerceAtLeast(1)
        val index = (parts.size - hops).coerceAtLeast(0)
        return parts[index]
    }

    private fun parseXff(xForwardedFor: String?): List<String> {
        if (xForwardedFor.isNullOrBlank()) return emptyList()
        return xForwardedFor.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }
}
