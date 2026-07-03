package org.incept5.platform.core.ratelimit.store

import io.github.bucket4j.Bandwidth
import io.github.bucket4j.BucketConfiguration
import io.github.bucket4j.distributed.ExpirationAfterWriteStrategy
import io.github.bucket4j.distributed.proxy.ProxyManager
import io.github.bucket4j.redis.lettuce.cas.LettuceBasedProxyManager
import io.lettuce.core.ClientOptions
import io.lettuce.core.RedisClient
import io.lettuce.core.RedisConnectionException
import io.lettuce.core.RedisException
import io.lettuce.core.SocketOptions
import io.lettuce.core.TimeoutOptions
import io.lettuce.core.api.StatefulRedisConnection
import io.lettuce.core.codec.ByteArrayCodec
import io.micrometer.core.instrument.MeterRegistry
import io.micrometer.core.instrument.Metrics
import org.slf4j.LoggerFactory
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicLong
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
 *
 * ### Bounded latency on the hot path (FF-2948)
 *
 * The Lettuce client is configured with an explicit TCP connect timeout ([connectTimeoutMs]) and
 * per-command timeout ([commandTimeoutMs]) — without these, Lettuce's 10s/60s defaults would let
 * a single rate-limit check stall far longer than a clean block on a slow/degraded Redis.
 *
 * The Lettuce `SocketOptions.connectTimeout` covers the TCP dial only; **the JVM's DNS resolver
 * has no exposed timeout**, so a Redis hostname stuck in DNS-limbo (e.g. an ElastiCache endpoint
 * that has been deleted but whose zone still refuses to answer authoritatively) can hang
 * `RedisClient.connect(...)` for the full OS resolver default (~60s). This class therefore also
 * wraps the initial connect in a [CompletableFuture] on a dedicated single-thread executor and
 * enforces [connectTimeoutMs] via `orTimeout(...)` on a `copy()` of that future — so the caller
 * unblocks promptly while the original future stays live long enough to `close()` any connection
 * that arrives *after* the timeout (a post-timeout success must not leak a socket).
 *
 * A failed connect is then **negatively cached** for [connectCooldownMs]: during that window every
 * request fails open immediately without re-attempting. Without this, a sustained outage would
 * re-run the bounded connect on every request — serializing callers on the connect monitor and
 * accumulating one hung in-executor thread per attempt. The negative cache bounds that to one
 * attempt (and at most one hung thread) per window.
 *
 * ### Fail-open posture (FF-2948)
 *
 * The connection is established **lazily** on first use rather than in the constructor, so a Redis
 * that is down when the bean is first injected does not break bean construction. On a Redis outage
 * — either a failed lazy connect or a failed command on an established connection — the store
 * fails **open**: `tryConsume` returns `true`, `availableTokens` returns `Long.MAX_VALUE`,
 * `size`/`clear` degrade to zero/no-op. Rate-limit enforcement is preserved-when-healthy and
 * skipped-when-not, matching the challenge marker store's fail-open posture and Iain's principle
 * that our own infra outage must not block a legitimate buyer.
 *
 * NOTE: because a *permanent* misconfiguration (bad host/port/credentials) fails open exactly like
 * a transient outage, it will not fail the deploy — alert on `rate_limit_store_error_total` to
 * catch it. The `exception` tag distinguishes a persistent command error (bug/misconfig) from a
 * connection outage.
 *
 * Every outage emits `rate_limit_store_error_total{op,exception}` on the injected [MeterRegistry]
 * (or the global registry when none is injected) for ops visibility.
 */
class RedisRateLimitStore @JvmOverloads constructor(
    redisUri: String,
    private val keyPrefix: String,
    private val idleTtl: Duration,
    private val connectTimeoutMs: Long = DEFAULT_CONNECT_TIMEOUT_MS,
    commandTimeoutMs: Long = DEFAULT_COMMAND_TIMEOUT_MS,
    private val connectCooldownMs: Long = DEFAULT_CONNECT_COOLDOWN_MS,
    private val meterRegistry: MeterRegistry? = null,
) : RateLimitStore, AutoCloseable {

    private val logger = LoggerFactory.getLogger(javaClass)

    private val redisClient: RedisClient = RedisClient.create(redisUri).apply {
        options = ClientOptions.builder()
            .socketOptions(
                SocketOptions.builder()
                    .connectTimeout(Duration.ofMillis(connectTimeoutMs))
                    .build(),
            )
            .timeoutOptions(TimeoutOptions.enabled(Duration.ofMillis(commandTimeoutMs)))
            .build()
    }

    /**
     * Dedicated single-thread executor for the lazy `redisClient.connect()` call. Isolated from
     * the common ForkJoinPool so a DNS-limbo hang (which lives for the OS resolver's full window)
     * cannot starve unrelated request-path tasks. See class KDoc — FF-2948.
     */
    private val connectExecutor: ExecutorService = Executors.newSingleThreadExecutor { r ->
        Thread(r, "redis-rate-limit-connect").apply { isDaemon = true }
    }

    @Volatile
    private var connection: StatefulRedisConnection<ByteArray, ByteArray>? = null

    @Volatile
    private var proxyManager: ProxyManager<ByteArray>? = null

    /** `System.nanoTime()` deadline until which connect attempts are suppressed; null = no cooldown. */
    @Volatile
    private var connectCooldownUntilNanos: Long? = null

    /**
     * Count of real (non-short-circuited) connect attempts. Exposed [internal]ly so tests can assert
     * the negative cache actually suppresses reconnect storms during an outage.
     */
    internal val connectAttempts = AtomicLong()

    init {
        logger.info(
            "Initialised Redis rate-limit store (lazy connect): uri={}, keyPrefix={}, idleTtl={}",
            redisUri, keyPrefix, idleTtl,
        )
    }

    /**
     * Establish (or return the cached) Lettuce connection. Bounded by [connectTimeoutMs] so a
     * DNS-limbo hostname throws a fast [RedisConnectionException] instead of hanging past the
     * surrounding request-path budget (Kong 60s, Narayana JTA 60s). A failed connect is negatively
     * cached for [connectCooldownMs] so a sustained outage does not re-run this ceremony on every
     * request. See class KDoc.
     */
    private fun connection(): StatefulRedisConnection<ByteArray, ByteArray> {
        connection?.let { return it }
        if (inConnectCooldown()) throw connectCooldownException()
        synchronized(this) {
            connection?.let { return it }
            if (inConnectCooldown()) throw connectCooldownException()
            try {
                connection = boundedConnect()
                connectCooldownUntilNanos = null
            } catch (e: RedisException) {
                // Negative-cache the failure: until the window elapses, callers fail open
                // immediately (see connection()'s pre-monitor guard) instead of serializing on this
                // monitor and spawning another hung connect task per request.
                if (connectCooldownMs > 0) {
                    connectCooldownUntilNanos =
                        System.nanoTime() + Duration.ofMillis(connectCooldownMs).toNanos()
                }
                throw e
            }
            return connection!!
        }
    }

    private fun inConnectCooldown(): Boolean {
        val until = connectCooldownUntilNanos ?: return false
        // nanoTime-difference comparison is wraparound-safe.
        return until - System.nanoTime() > 0
    }

    private fun connectCooldownException() = RedisConnectionException(
        "connect suppressed within ${connectCooldownMs}ms negative-cache window after a recent failure",
    )

    /**
     * Connect on the dedicated executor, time-boxed to [connectTimeoutMs]. Always throws a
     * [RedisException] on failure so the caller's fail-open catch always applies (a bare
     * `TimeoutException` or a non-Lettuce cause must never escape). A connection that completes
     * *after* the timeout is closed rather than leaked.
     */
    private fun boundedConnect(): StatefulRedisConnection<ByteArray, ByteArray> {
        connectAttempts.incrementAndGet()
        val connectFuture = CompletableFuture
            .supplyAsync({ redisClient.connect(ByteArrayCodec.INSTANCE) }, connectExecutor)
        try {
            // Time-box a copy() so connectFuture itself stays live: even after the copy is failed by
            // orTimeout, connectFuture can still complete normally when the OS resolver finally
            // answers — the whenComplete below then closes that late connection.
            return connectFuture.copy().orTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS).get()
        } catch (e: ExecutionException) {
            // get() always wraps an exceptional completion in ExecutionException — including the
            // TimeoutException orTimeout completes with. Unwrap and branch on the cause.
            val cause = e.cause
            if (cause is TimeoutException) {
                // orTimeout fired — likely DNS-limbo. Don't cancel connectFuture (the in-executor
                // thread runs until the resolver gives up regardless); instead close whatever it
                // eventually produces so a post-timeout success does not leak a socket.
                connectFuture.whenComplete { conn, _ -> conn?.close() }
                throw RedisConnectionException(
                    "connect timed out after ${connectTimeoutMs}ms (likely DNS resolution)", cause,
                )
            }
            // Normalise any other failure to a RedisException so fail-open always applies.
            throw cause as? RedisException
                ?: RedisConnectionException("connect failed", cause ?: e)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw RedisConnectionException("connect interrupted", e)
        }
    }

    private fun proxyManager(): ProxyManager<ByteArray> {
        proxyManager?.let { return it }
        synchronized(this) {
            proxyManager?.let { return it }
            proxyManager = LettuceBasedProxyManager.builderFor(connection())
                .withExpirationStrategy(
                    ExpirationAfterWriteStrategy.basedOnTimeForRefillingBucketUpToMax(idleTtl),
                )
                .build()
            return proxyManager!!
        }
    }

    override fun tryConsume(key: String, requestsPerMinute: Int, tokens: Long): Boolean {
        return try {
            val allowed = bucket(key, requestsPerMinute).tryConsume(tokens)
            if (!allowed) {
                logger.debug("Rate limit exceeded for key: {}, limit: {}/min", key, requestsPerMinute)
            }
            allowed
        } catch (e: RedisException) {
            // Any Redis failure fails open: a lazy-connect failure (incl. the bounded-connect
            // timeout, thrown as RedisConnectionException — a RedisException) or a command failure
            // (incl. command-timeout) that bucket4j-redis surfaces as RedisException.
            failOpen("tryConsume", key, e)
            true
        }
    }

    override fun availableTokens(key: String, requestsPerMinute: Int): Long {
        return try {
            bucket(key, requestsPerMinute).availableTokens
        } catch (e: RedisException) {
            failOpen("availableTokens", key, e)
            Long.MAX_VALUE
        }
    }

    /**
     * Not tracked for the distributed store — buckets live in Redis (which evicts them by TTL),
     * not in this JVM's heap, so there is no in-process count to report. Returns 0 so the
     * `rate_limit.buckets` gauge reflects in-memory pressure only.
     */
    override fun size(): Long = 0

    override fun clear() {
        try {
            val commands = connection().sync()
            val pattern = "$keyPrefix*".toByteArray(StandardCharsets.UTF_8)
            val keys = commands.keys(pattern)
            if (keys.isNotEmpty()) {
                commands.del(*keys.toTypedArray())
            }
        } catch (e: RedisException) {
            // Admin-facing clear on an outage → silent no-op is acceptable. Ops sees the metric.
            failOpen("clear", key = null, e)
        }
    }

    override fun close() {
        try {
            connection?.close()
        } finally {
            try {
                connectExecutor.shutdownNow()
            } catch (_: Throwable) {
                // Best-effort — bean shutdown must not throw.
            }
            redisClient.shutdown()
        }
    }

    private fun bucket(key: String, requestsPerMinute: Int) =
        proxyManager().builder().build(
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

    private fun failOpen(op: String, key: String?, e: Exception) {
        val exception = e.javaClass.simpleName
        // Prefer the injected registry (the one the rest of the module publishes to); fall back to
        // the global registry for no-CDI/test construction. The `exception` tag lets ops tell a
        // persistent command error (bug/misconfig) apart from a transient connection outage.
        (meterRegistry ?: Metrics.globalRegistry)
            .counter("rate_limit_store_error_total", "op", op, "exception", exception)
            .increment()
        logger.warn(
            "rate_limit_store_error op={} key={} exception={}: {} — failing open",
            op, key ?: "(all)", exception, e.message,
        )
    }

    companion object {
        /** Default TCP + DNS connect budget when constructed without config (tests / no-CDI). */
        const val DEFAULT_CONNECT_TIMEOUT_MS = 1000L

        /** Default per-command timeout when constructed without config (tests / no-CDI). */
        const val DEFAULT_COMMAND_TIMEOUT_MS = 500L

        /** Default post-failure connect-suppression window when constructed without config. */
        const val DEFAULT_CONNECT_COOLDOWN_MS = 5000L
    }
}
