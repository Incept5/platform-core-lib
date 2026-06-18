package org.incept5.platform.core.ratelimit.store

import io.github.bucket4j.Bandwidth
import io.github.bucket4j.BucketConfiguration
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy
import io.github.bucket4j.distributed.proxy.ProxyManager
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager
import io.lettuce.core.RedisClient
import io.lettuce.core.api.StatefulRedisConnection
import io.lettuce.core.codec.ByteArrayCodec
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.function.Supplier

/**
 * Distributed [RateLimitStore] backed by Redis via Bucket4j's Lettuce proxy manager, so a single
 * client's limit is enforced across every application instance sharing the Redis (EPIC-46
 * STORY-03 AC4) rather than being multiplied by the number of ECS tasks.
 *
 * Opt-in: only instantiated by [RateLimitStoreProducer] when `rate-limit.store=redis`.
 * `bucket4j-redis` and `lettuce-core` are compileOnly in this library, so consumers that do not
 * enable Redis pay no dependency cost. Bucket keys are namespaced by `rate-limit.redis.key-prefix`
 * and expire from Redis after the configured idle TTL.
 */
class RedisRateLimitStore(
    redisUri: String,
    private val keyPrefix: String,
    idleTtl: Duration,
) : RateLimitStore, AutoCloseable {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val redisClient: RedisClient = RedisClient.create(redisUri)
    private val connection: StatefulRedisConnection<ByteArray, ByteArray> =
        redisClient.connect(ByteArrayCodec.INSTANCE)

    private val proxyManager: ProxyManager<ByteArray> =
        LettuceBasedProxyManager.builderFor(connection)
            .withExpirationStrategy(
                ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(idleTtl),
            )
            .build()

    init {
        logger.info("Initialised Redis rate-limit store: uri={}, keyPrefix={}, idleTtl={}", redisUri, keyPrefix, idleTtl)
    }

    override fun tryConsume(key: String, requestsPerMinute: Int, tokens: Long): Boolean {
        val allowed = bucket(key, requestsPerMinute).tryConsume(tokens)
        if (!allowed) {
            logger.debug("Rate limit exceeded for key: {}, limit: {}/min", key, requestsPerMinute)
        }
        return allowed
    }

    override fun availableTokens(key: String, requestsPerMinute: Int): Long =
        bucket(key, requestsPerMinute).availableTokens

    /**
     * Not tracked for the distributed store — buckets live in Redis (which evicts them by TTL),
     * not in this JVM's heap, so there is no in-process count to report. Returns 0 so the
     * `rate_limit.buckets` gauge reflects in-memory pressure only.
     */
    override fun size(): Long = 0

    override fun clear() {
        val commands = connection.sync()
        val pattern = "$keyPrefix*".toByteArray(StandardCharsets.UTF_8)
        val keys = commands.keys(pattern)
        if (keys.isNotEmpty()) {
            commands.del(*keys.toTypedArray())
        }
    }

    override fun close() {
        try {
            connection.close()
        } finally {
            redisClient.shutdown()
        }
    }

    private fun bucket(key: String, requestsPerMinute: Int) =
        proxyManager.builder().build(
            (keyPrefix + key).toByteArray(StandardCharsets.UTF_8),
            Supplier { configuration(requestsPerMinute) },
        )

    private fun configuration(requestsPerMinute: Int): BucketConfiguration =
        BucketConfiguration.builder()
            .addLimit(
                Bandwidth.builder()
                    .capacity(requestsPerMinute.toLong())
                    .refillIntervally(requestsPerMinute.toLong(), Duration.ofMinutes(1))
                    .build(),
            )
            .build()
}
