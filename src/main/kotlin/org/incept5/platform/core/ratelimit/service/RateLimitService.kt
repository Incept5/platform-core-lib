package org.incept5.platform.core.ratelimit.service

import io.github.bucket4j.Bandwidth
import io.github.bucket4j.Bucket
import io.github.bucket4j.Refill
import jakarta.enterprise.context.ApplicationScoped
import org.slf4j.LoggerFactory
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap

/**
 * Service responsible for managing rate limits using Bucket4j.
 * Provides in-memory rate limiting with configurable limits per key.
 *
 * In production, this should be backed by a distributed cache like Redis
 * to ensure rate limits are enforced across multiple instances.
 */
@ApplicationScoped
class RateLimitService {

    private val logger = LoggerFactory.getLogger(javaClass)

    // In-memory storage for rate limit buckets
    // Key format: "{rateLimitKey}:{clientIdentifier}"
    private val buckets = ConcurrentHashMap<String, Bucket>()

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
        tokensToConsume: Long = 1
    ): Boolean {
        val bucket = buckets.computeIfAbsent(key) {
            createBucket(requestsPerMinute)
        }

        val allowed = bucket.tryConsume(tokensToConsume)

        if (!allowed) {
            logger.debug("Rate limit exceeded for key: {}, limit: {}/min", key, requestsPerMinute)
        }

        return allowed
    }

    /**
     * Gets the number of available tokens for a given key.
     * Useful for including rate limit information in response headers.
     *
     * @param key Unique key identifying the rate limit rule and client
     * @param requestsPerMinute Maximum requests allowed per minute
     * @return Number of available tokens
     */
    fun getAvailableTokens(key: String, requestsPerMinute: Int): Long {
        val bucket = buckets.computeIfAbsent(key) {
            createBucket(requestsPerMinute)
        }
        return bucket.availableTokens
    }

    /**
     * Creates a new rate limit bucket with the specified configuration.
     *
     * @param requestsPerMinute Maximum requests allowed per minute
     * @return Configured Bucket instance
     */
    private fun createBucket(requestsPerMinute: Int): Bucket {
        val bandwidth = Bandwidth.classic(
            requestsPerMinute.toLong(),
            Refill.intervally(requestsPerMinute.toLong(), Duration.ofMinutes(1))
        )

        return Bucket.builder()
            .addLimit(bandwidth)
            .build()
    }

    /**
     * Clears all rate limit buckets.
     * Useful for testing or administrative purposes.
     */
    fun clearAll() {
        buckets.clear()
        logger.info("All rate limit buckets cleared")
    }

    /**
     * Gets the current number of tracked buckets.
     * Useful for monitoring memory usage.
     *
     * @return Number of active buckets
     */
    fun getBucketCount(): Int = buckets.size
}
