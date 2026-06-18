package org.incept5.platform.core.ratelimit.store

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.time.Duration

class InMemoryRateLimitStoreTest {

    @Test
    fun `AC3 - bucket store stays bounded under key churn`() {
        val maxSize = 100L
        val store = InMemoryRateLimitStore(maxSize, Duration.ofMinutes(10))

        // Spray far more distinct keys than the cap (simulating spoofed XFF / high-cardinality keys)
        repeat(10_000) { i ->
            store.tryConsume("flood:$i", 5)
        }

        // The map must not grow without bound — it stays at or below the configured cap.
        assertThat(store.size()).isLessThanOrEqualTo(maxSize)
    }

    @Test
    fun `idle buckets expire after the configured TTL`() {
        // Very short TTL so expiry is observable without a fake clock.
        val store = InMemoryRateLimitStore(1_000L, Duration.ofMillis(50))
        store.tryConsume("idle:1", 5)
        assertThat(store.size()).isEqualTo(1L)

        Thread.sleep(120)

        // After the idle window the entry is evicted on the next maintenance cycle.
        assertThat(store.size()).isEqualTo(0L)
    }

    @Test
    fun `enforces the limit and tracks available tokens`() {
        val store = InMemoryRateLimitStore(1_000L, Duration.ofMinutes(10))
        val key = "limit:1"

        repeat(3) { assertThat(store.tryConsume(key, 3)).isTrue() }
        assertThat(store.tryConsume(key, 3)).isFalse()
        assertThat(store.availableTokens(key, 3)).isEqualTo(0L)
    }

    @Test
    fun `clear removes all buckets`() {
        val store = InMemoryRateLimitStore(1_000L, Duration.ofMinutes(10))
        store.tryConsume("a", 5)
        store.tryConsume("b", 5)
        assertThat(store.size()).isEqualTo(2L)

        store.clear()
        assertThat(store.size()).isEqualTo(0L)
    }
}
