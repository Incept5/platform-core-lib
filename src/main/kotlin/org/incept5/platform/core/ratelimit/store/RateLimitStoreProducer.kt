package org.incept5.platform.core.ratelimit.store

import io.micrometer.core.instrument.MeterRegistry
import jakarta.annotation.PreDestroy
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.inject.Instance
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
    /** The application's Micrometer registry, if one is on the classpath — used for the Redis
     *  store's fail-open error counter so it lands on the same registry the module already uses. */
    private val meterRegistry: Instance<MeterRegistry>,
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
            val redis = config.redis()
            RedisRateLimitStore(
                redis.uri(),
                redis.keyPrefix(),
                bucket.idleTtl(),
                redis.connectTimeoutMs(),
                redis.commandTimeoutMs(),
                redis.connectCooldownMs(),
                if (meterRegistry.isResolvable) meterRegistry.get() else null,
            ).also { closeable = it }
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
