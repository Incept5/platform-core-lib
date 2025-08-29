package org.incept5.platform.core.ratelimit.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault

/**
 * Configuration properties for rate limiting feature.
 * Allows global configuration and per-endpoint overrides.
 */
@ConfigMapping(prefix = "rate-limit")
interface RateLimitConfig {

    /**
     * Whether rate limiting is enabled globally.
     * Default: true
     */
    @WithDefault("true")
    fun enabled(): Boolean

    /**
     * Default rate limit for all endpoints (requests per minute).
     * Can be overridden by annotation or endpoint-specific configuration.
     * Default: 100
     */
    @WithDefault("100")
    fun defaultRequestsPerMinute(): Int

    /**
     * Payment session specific rate limiting configuration.
     */
    fun paymentSession(): PaymentSessionRateLimitConfig

    /**
     * Payment session rate limiting configuration.
     */
    interface PaymentSessionRateLimitConfig {

        /**
         * Rate limit for payment session cancellation endpoint (requests per minute per IP).
         * Default: 10
         */
        @WithDefault("10")
        fun cancellationRequestsPerMinute(): Int

        /**
         * Whether to include rate limit headers in response.
         * Headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
         * Default: true
         */
        @WithDefault("true")
        fun includeHeaders(): Boolean
    }
}
