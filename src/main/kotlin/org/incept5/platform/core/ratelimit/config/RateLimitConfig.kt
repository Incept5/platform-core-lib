package org.incept5.platform.core.ratelimit.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault
import java.time.Duration

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
     * Per-key request-per-minute overrides, resolved by the `key` on the `@RateLimit`
     * annotation. Lets limits be tuned via config without a code change/redeploy of the
     * annotation value; the annotation's `requestsPerMinute` is used as the fallback when a
     * key is not present here.
     *
     * Configure as e.g. `rate-limit.limits."payment-session-cancel"=10`
     * (quote keys containing dashes/dots).
     */
    fun limits(): Map<String, Int>

    /**
     * Client-IP resolution strategy used to key rate-limit buckets.
     */
    fun clientIp(): ClientIpConfig

    /**
     * Bounds on the in-memory bucket store so unbounded key churn cannot exhaust memory.
     */
    fun bucket(): BucketConfig

    /**
     * Which backing store enforces the limits. `in-memory` (default) is per-instance;
     * `redis` enforces limits cluster-wide across ECS tasks. Selecting `redis` requires
     * `bucket4j-redis` + `lettuce-core` on the runtime classpath (they are optional/compileOnly
     * in this library) and a reachable Redis (see [redis]).
     * Default: in-memory.
     */
    @WithDefault("in-memory")
    fun store(): String

    /**
     * Redis connection settings, used only when [store] is `redis`.
     */
    fun redis(): RedisConfig

    /**
     * Payment session specific rate limiting configuration.
     */
    fun paymentSession(): PaymentSessionRateLimitConfig

    /**
     * Client-IP resolution configuration.
     */
    interface ClientIpConfig {

        /**
         * Strategy for deriving the client IP from the request.
         * Default: TRUSTED_PROXY_HOPS (spoof-resistant; replaces the old leftmost-XFF default).
         */
        @WithDefault("TRUSTED_PROXY_HOPS")
        fun strategy(): ClientIpStrategy

        /**
         * Number of trusted proxy hops in front of the application that append to
         * `X-Forwarded-For`. The client IP is taken as the Nth-from-right XFF value.
         * Default: 2 (ALB + Kong).
         */
        @WithDefault("2")
        fun trustedProxyHops(): Int
    }

    /**
     * Bucket store bounds (in-memory store only).
     */
    interface BucketConfig {

        /**
         * Maximum number of buckets retained in memory. When exceeded, least-recently-used
         * buckets are evicted. Default: 100000.
         */
        @WithDefault("100000")
        fun maxSize(): Long

        /**
         * Buckets untouched for this duration are evicted (ISO-8601 duration).
         * Default: PT10M (10 minutes — comfortably longer than the 1-minute refill window).
         */
        @WithDefault("PT10M")
        fun idleTtl(): Duration
    }

    /**
     * Redis store configuration (used only when `rate-limit.store=redis`).
     */
    interface RedisConfig {

        /**
         * Redis connection URI (Lettuce format), e.g. `redis://host:6379` or
         * `rediss://host:6380` for TLS. Default: redis://localhost:6379.
         */
        @WithDefault("redis://localhost:6379")
        fun uri(): String

        /**
         * Prefix applied to every bucket key in Redis, so rate-limit keys are namespaced
         * and clearable independently of anything else in the database. Default: `rate-limit:`.
         */
        @WithDefault("rate-limit:")
        fun keyPrefix(): String
    }

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
