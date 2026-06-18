package org.incept5.platform.core.ratelimit.store

import com.github.benmanes.caffeine.cache.Cache
import com.github.benmanes.caffeine.cache.Caffeine
import io.github.bucket4j.Bandwidth
import io.github.bucket4j.Bucket
import io.quarkus.arc.DefaultBean
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.incept5.platform.core.ratelimit.config.RateLimitConfig
import org.slf4j.LoggerFactory
import java.time.Duration

/**
 * In-memory [RateLimitStore] backed by Bucket4j buckets held in a Caffeine cache.
 *
 * The cache is **bounded** — capped by `rate-limit.bucket.max-size` (LRU eviction) and expired
 * after `rate-limit.bucket.idle-ttl` of inactivity — so a flood of distinct keys (e.g. spoofed
 * `X-Forwarded-For` values, before [org.incept5.platform.core.ratelimit.ip.ClientIpResolver]
 * hardening, or any high-cardinality key dimension) cannot grow the map without bound and turn
 * the limiter itself into a memory-DoS vector (EPIC-46 STORY-03 AC3).
 *
 * Registered as a [DefaultBean] so a distributed implementation can replace it without changing
 * call sites.
 */
@ApplicationScoped
@DefaultBean
class InMemoryRateLimitStore : RateLimitStore {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val cache: Cache<String, Bucket>

    /** No-arg constructor for non-CDI use (unit tests) and CDI client-proxy creation. */
    constructor() : this(DEFAULT_MAX_SIZE, DEFAULT_IDLE_TTL)

    @Inject
    constructor(config: RateLimitConfig) : this(config.bucket().maxSize(), config.bucket().idleTtl())

    constructor(maxSize: Long, idleTtl: Duration) {
        this.cache = Caffeine.newBuilder()
            .maximumSize(maxSize)
            .expireAfterAccess(idleTtl)
            .build()
        logger.info("Initialised in-memory rate-limit store: maxSize={}, idleTtl={}", maxSize, idleTtl)
    }

    override fun tryConsume(key: String, requestsPerMinute: Int, tokens: Long): Boolean {
        val bucket = cache.get(key) { createBucket(requestsPerMinute) }
        val allowed = bucket.tryConsume(tokens)
        if (!allowed) {
            logger.debug("Rate limit exceeded for key: {}, limit: {}/min", key, requestsPerMinute)
        }
        return allowed
    }

    override fun availableTokens(key: String, requestsPerMinute: Int): Long {
        val bucket = cache.get(key) { createBucket(requestsPerMinute) }
        return bucket.availableTokens
    }

    override fun size(): Long {
        cache.cleanUp()
        return cache.estimatedSize()
    }

    override fun clear() {
        cache.invalidateAll()
        cache.cleanUp()
        logger.info("All rate limit buckets cleared")
    }

    private fun createBucket(requestsPerMinute: Int): Bucket {
        val bandwidth = Bandwidth.builder()
            .capacity(requestsPerMinute.toLong())
            .refillIntervally(requestsPerMinute.toLong(), Duration.ofMinutes(1))
            .build()

        return Bucket.builder()
            .addLimit(bandwidth)
            .build()
    }

    companion object {
        /** Default cap when constructed without config (tests / no-CDI). */
        const val DEFAULT_MAX_SIZE = 100_000L

        /** Default idle eviction window when constructed without config (tests / no-CDI). */
        val DEFAULT_IDLE_TTL: Duration = Duration.ofMinutes(10)
    }
}
