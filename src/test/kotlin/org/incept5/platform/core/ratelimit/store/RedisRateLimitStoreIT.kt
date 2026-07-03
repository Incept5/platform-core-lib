package org.incept5.platform.core.ratelimit.store

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.Assertions.assertTimeoutPreemptively
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import java.time.Duration

/**
 * Contract test for [RedisRateLimitStore] proving cluster-wide enforcement (EPIC-46 STORY-03 AC4).
 *
 * Spins up a real Redis in Docker (Testcontainers) and creates two independent store instances
 * pointed at it — standing in for two ECS tasks — to prove a single client's limit is shared
 * across both, not multiplied by the instance count.
 *
 * Requires a running Docker daemon; skips gracefully nowhere — if Docker is absent the test fails
 * fast, which is the intended signal in CI where Docker is available.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RedisRateLimitStoreIT {

    private val redis: GenericContainer<*> =
        GenericContainer(DockerImageName.parse("redis:7-alpine")).withExposedPorts(REDIS_PORT)

    private lateinit var uri: String

    @BeforeAll
    fun startRedis() {
        redis.start()
        uri = "redis://${redis.host}:${redis.getMappedPort(REDIS_PORT)}"
    }

    @AfterAll
    fun stopRedis() {
        redis.stop()
    }

    @BeforeEach
    fun flush() {
        // Clear any keys from a previous test so each starts from a clean slate.
        RedisRateLimitStore(uri, KEY_PREFIX, Duration.ofMinutes(10)).use { it.clear() }
    }

    @Test
    fun `AC4 - limit holds when requests are spread across two instances`() {
        val limit = 6
        val key = "client-x"

        storeA().use { a ->
            storeB().use { b ->
                // Spread `limit` requests alternately across the two instances — all must pass,
                // proving they draw from one shared bucket.
                var allowed = 0
                repeat(limit) { i ->
                    val store = if (i % 2 == 0) a else b
                    if (store.tryConsume(key, limit)) allowed++
                }
                assertThat(allowed).isEqualTo(limit)

                // The next request on EITHER instance is rejected — combined enforcement, not 2x.
                assertThat(a.tryConsume(key, limit)).isFalse()
                assertThat(b.tryConsume(key, limit)).isFalse()
            }
        }
    }

    @Test
    fun `available tokens reflect consumption made on the other instance`() {
        val limit = 5
        val key = "client-y"

        storeA().use { a ->
            storeB().use { b ->
                repeat(2) { assertThat(a.tryConsume(key, limit)).isTrue() }
                // b sees the tokens a consumed because state lives in Redis, not in-process.
                assertThat(b.availableTokens(key, limit)).isEqualTo((limit - 2).toLong())
            }
        }
    }

    @Test
    fun `different keys are independent`() {
        val limit = 1
        storeA().use { a ->
            assertThat(a.tryConsume("client-a", limit)).isTrue()
            assertThat(a.tryConsume("client-a", limit)).isFalse()
            assertThat(a.tryConsume("client-b", limit)).isTrue()
        }
    }

    /**
     * FF-2948 — bounded-connect + fail-open. When Redis is unreachable, the store must NOT hang
     * the caller (previously ~60s waiting on the OS resolver); it must throw its bounded
     * `RedisConnectionException` inside `connectTimeoutMs`, be caught by the store, and return
     * `true` from `tryConsume` (fail-open) so the request path is not blocked by our own infra
     * outage.
     *
     * Uses `unavailable-testing.invalid` (RFC 6761 reserved TLD → NXDOMAIN in <10ms on any
     * conformant resolver) as the stand-in for a DNS-limbo endpoint. The DNS-limbo variant
     * (a real hostname that neither answers nor returns NXDOMAIN) is what actually causes the
     * 60s hang in production; simulating that is not portable across CI runners, so this test
     * covers the fast-DNS-failure path which the bounded wrapper handles identically.
     */
    @Test
    fun `FF-2948 unreachable Redis fails open on tryConsume within the bounded budget`() {
        val budgetMs = 3000L
        assertTimeoutPreemptively(Duration.ofMillis(budgetMs)) {
            RedisRateLimitStore(
                redisUri = "redis://unavailable-testing.invalid:6379",
                keyPrefix = KEY_PREFIX,
                idleTtl = Duration.ofMinutes(10),
                connectTimeoutMs = 1000L,
                commandTimeoutMs = 500L,
            ).use { store ->
                assertThat(store.tryConsume("client-outage", requestsPerMinute = 1)).isTrue()
                assertThat(store.availableTokens("client-outage", requestsPerMinute = 1))
                    .isEqualTo(Long.MAX_VALUE)
            }
        }
    }

    private fun storeA() = RedisRateLimitStore(uri, KEY_PREFIX, Duration.ofMinutes(10))
    private fun storeB() = RedisRateLimitStore(uri, KEY_PREFIX, Duration.ofMinutes(10))

    private companion object {
        const val REDIS_PORT = 6379
        const val KEY_PREFIX = "test-rate-limit:"
    }
}
