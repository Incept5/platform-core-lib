package org.incept5.platform.core.ratelimit.store

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterAll
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

    private fun storeA() = RedisRateLimitStore(uri, KEY_PREFIX, Duration.ofMinutes(10))
    private fun storeB() = RedisRateLimitStore(uri, KEY_PREFIX, Duration.ofMinutes(10))

    private companion object {
        const val REDIS_PORT = 6379
        const val KEY_PREFIX = "test-rate-limit:"
    }
}
