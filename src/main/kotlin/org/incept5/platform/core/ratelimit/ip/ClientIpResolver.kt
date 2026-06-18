package org.incept5.platform.core.ratelimit.ip

import io.vertx.core.http.HttpServerRequest
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.incept5.platform.core.ratelimit.config.RateLimitConfig
import org.slf4j.LoggerFactory

/**
 * Resolves the genuine client IP for a request, honouring the configured
 * [org.incept5.platform.core.ratelimit.config.ClientIpStrategy].
 *
 * Shared bean: used by the [org.incept5.platform.core.ratelimit.interceptor.RateLimitInterceptor]
 * to key `@RateLimit` buckets, and intended for reuse by consumers that throttle programmatically
 * (e.g. EPIC-46 STORY-01 `/confirm` and STORY-02's card-testing velocity guard) so every limiter
 * buckets on the same spoof-resistant identity.
 */
@ApplicationScoped
class ClientIpResolver @Inject constructor(
    private val config: RateLimitConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    /**
     * Resolve the client IP from a Vert.x request. Never throws — returns
     * [ClientIpResolution.UNKNOWN] if extraction fails for any reason.
     */
    fun resolve(request: HttpServerRequest?): String {
        if (request == null) return ClientIpResolution.UNKNOWN
        return try {
            val clientIp = config.clientIp()
            ClientIpResolution.resolve(
                xForwardedFor = request.getHeader("X-Forwarded-For"),
                xRealIp = request.getHeader("X-Real-IP"),
                remoteHost = request.remoteAddress()?.host(),
                strategy = clientIp.strategy(),
                trustedProxyHops = clientIp.trustedProxyHops(),
            )
        } catch (e: Exception) {
            logger.warn("Failed to resolve client IP: {}", e.message)
            ClientIpResolution.UNKNOWN
        }
    }
}
