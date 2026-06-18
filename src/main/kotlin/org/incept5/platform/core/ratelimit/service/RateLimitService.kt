package org.incept5.platform.core.ratelimit.service

import io.micrometer.core.instrument.Gauge
import io.micrometer.core.instrument.MeterRegistry
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Instance
import jakarta.inject.Inject
import org.incept5.platform.core.ratelimit.store.InMemoryRateLimitStore
import org.incept5.platform.core.ratelimit.store.RateLimitStore
import org.slf4j.LoggerFactory

/**
 * Service responsible for managing rate limits.
 *
 * Delegates storage to a pluggable [RateLimitStore] — the default [InMemoryRateLimitStore] is
 * bounded (size cap + idle TTL) so key churn cannot exhaust memory. A distributed (Redis-backed)
 * store can be substituted to enforce limits across instances (EPIC-46 STORY-03 AC4, deferred).
 *
 * The number of tracked buckets is published as the `rate_limit.buckets` gauge when a Micrometer
 * [MeterRegistry] is available (AC3).
 */
@ApplicationScoped
class RateLimitService {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val store: RateLimitStore

    /** No-arg constructor for non-CDI use (unit tests) and CDI client-proxy creation. */
    constructor() {
        this.store = InMemoryRateLimitStore()
    }

    @Inject
    constructor(store: RateLimitStore, meterRegistry: Instance<MeterRegistry>) {
        this.store = store
        registerMetrics(meterRegistry)
    }

    /**
     * Attempts to consume a token from the rate limit bucket.
     *
     * @param key Unique key identifying the rate limit rule and client
     * @param requestsPerMinute Maximum requests allowed per minute
     * @param tokensToConsume Number of tokens to consume (default: 1)
     * @return true if request is allowed, false if rate limit exceeded
     */
    fun tryConsume(
        key: String,
        requestsPerMinute: Int,
        tokensToConsume: Long = 1,
    ): Boolean = store.tryConsume(key, requestsPerMinute, tokensToConsume)

    /**
     * Gets the number of available tokens for a given key.
     * Useful for including rate limit information in response headers.
     *
     * @param key Unique key identifying the rate limit rule and client
     * @param requestsPerMinute Maximum requests allowed per minute
     * @return Number of available tokens
     */
    fun getAvailableTokens(key: String, requestsPerMinute: Int): Long =
        store.availableTokens(key, requestsPerMinute)

    /**
     * Clears all rate limit buckets.
     * Useful for testing or administrative purposes.
     */
    fun clearAll() = store.clear()

    /**
     * Gets the current number of tracked buckets.
     * Useful for monitoring memory usage.
     *
     * @return Number of active buckets
     */
    fun getBucketCount(): Int = store.size().toInt()

    private fun registerMetrics(meterRegistry: Instance<MeterRegistry>) {
        if (!meterRegistry.isResolvable) {
            logger.debug("No MeterRegistry available; rate_limit.buckets gauge not registered")
            return
        }
        Gauge.builder("rate_limit.buckets", store) { it.size().toDouble() }
            .description("Number of active rate-limit buckets currently held in memory")
            .register(meterRegistry.get())
    }
}
