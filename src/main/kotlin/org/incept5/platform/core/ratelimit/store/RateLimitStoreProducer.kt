package org.incept5.platform.core.ratelimit.store

import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Produces
import org.incept5.platform.core.ratelimit.config.RateLimitConfig
import org.slf4j.LoggerFactory

/**
 * Produces the single [RateLimitStore] bean, selected at runtime by `rate-limit.store`:
 *  - `in-memory` (default) → bounded [InMemoryRateLimitStore], per-instance.
 *  - `redis` → [RedisRateLimitStore], enforcing limits cluster-wide.
 *
 * Keeping selection in a producer (rather than CDI `@DefaultBean`/alternatives) means the Redis
 * implementation — and therefore its `bucket4j-redis`/`lettuce-core` classes — is only loaded when
 * the flag is set to `redis`, so consumers using the default pay no dependency cost.
 */
@ApplicationScoped
class RateLimitStoreProducer(
    private val config: RateLimitConfig,
) {

    private val logger = LoggerFactory.getLogger(javaClass)

    /** Held only so the Lettuce connection can be closed on shutdown; null for in-memory. */
    private var closeable: AutoCloseable? = null

    @Produces
    @ApplicationScoped
    fun rateLimitStore(): RateLimitStore {
        val bucket = config.bucket()
        return if (config.store().equals(REDIS, ignoreCase = true)) {
            logger.info("Rate-limit store: redis (distributed, cluster-wide enforcement)")
            RedisRateLimitStore(config.redis().uri(), config.redis().keyPrefix(), bucket.idleTtl())
                .also { closeable = it }
        } else {
            logger.info("Rate-limit store: in-memory (per-instance)")
            InMemoryRateLimitStore(bucket.maxSize(), bucket.idleTtl())
        }
    }

    @PreDestroy
    fun shutdown() {
        closeable?.let {
            try {
                it.close()
            } catch (e: Exception) {
                logger.warn("Error closing rate-limit store: {}", e.message)
            }
        }
    }

    private companion object {
        const val REDIS = "redis"
    }
}
