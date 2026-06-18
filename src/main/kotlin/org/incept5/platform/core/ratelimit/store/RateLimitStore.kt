package org.incept5.platform.core.ratelimit.store

/**
 * Backing store for rate-limit token buckets. The implementation is chosen at runtime by
 * [RateLimitStoreProducer] from the `rate-limit.store` flag: the default [InMemoryRateLimitStore]
 * is bounded and per-instance; [RedisRateLimitStore] enforces limits cluster-wide (EPIC-46
 * STORY-03 AC4) and is enabled by setting `rate-limit.store=redis`.
 */
interface RateLimitStore {

    /**
     * Attempt to consume [tokens] from the bucket identified by [key], creating the bucket
     * (sized for [requestsPerMinute]) on first use.
     *
     * @return true if the request is within the limit, false if it should be rejected
     */
    fun tryConsume(key: String, requestsPerMinute: Int, tokens: Long = 1): Boolean

    /**
     * Number of tokens currently available for [key] (creating the bucket if absent).
     */
    fun availableTokens(key: String, requestsPerMinute: Int): Long

    /**
     * Current number of tracked buckets (for monitoring/metrics).
     */
    fun size(): Long

    /**
     * Remove all buckets (testing/administrative use).
     */
    fun clear()
}
