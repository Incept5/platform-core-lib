package org.incept5.platform.core.ratelimit.service

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeEach
import org.assertj.core.api.Assertions.assertThat

class RateLimitServiceTest {

    private lateinit var rateLimitService: RateLimitService

    @BeforeEach
    fun setUp() {
        rateLimitService = RateLimitService()
        rateLimitService.clearAll()
    }

    @Test
    fun `should allow requests within limit`() {
        val key = "test:192.168.1.1"
        val limit = 5

        // Should allow all requests within the limit
        repeat(limit) {
            assertThat(rateLimitService.tryConsume(key, limit)).isTrue()
        }
    }

    @Test
    fun `should reject requests exceeding limit`() {
        val key = "test:192.168.1.1"
        val limit = 3

        // Consume all tokens
        repeat(limit) {
            assertThat(rateLimitService.tryConsume(key, limit)).isTrue()
        }

        // Next request should be rejected
        assertThat(rateLimitService.tryConsume(key, limit)).isFalse()
    }

    @Test
    fun `should track available tokens correctly`() {
        val key = "test:192.168.1.1"
        val limit = 5

        // Initially should have full limit available
        assertThat(rateLimitService.getAvailableTokens(key, limit)).isEqualTo(limit.toLong())

        // After consuming one token
        rateLimitService.tryConsume(key, limit)
        assertThat(rateLimitService.getAvailableTokens(key, limit)).isEqualTo((limit - 1).toLong())

        // After consuming all tokens
        repeat(limit - 1) {
            rateLimitService.tryConsume(key, limit)
        }
        assertThat(rateLimitService.getAvailableTokens(key, limit)).isEqualTo(0L)
    }

    @Test
    fun `should handle different keys independently`() {
        val key1 = "test:192.168.1.1"
        val key2 = "test:192.168.1.2"
        val limit = 2

        // Consume all tokens for key1
        repeat(limit) {
            assertThat(rateLimitService.tryConsume(key1, limit)).isTrue()
        }

        // key1 should be rate limited
        assertThat(rateLimitService.tryConsume(key1, limit)).isFalse()

        // key2 should still work
        assertThat(rateLimitService.tryConsume(key2, limit)).isTrue()
    }

    @Test
    fun `should clear all buckets`() {
        val key = "test:192.168.1.1"
        val limit = 5

        // Create bucket by consuming tokens
        rateLimitService.tryConsume(key, limit)
        assertThat(rateLimitService.getBucketCount()).isEqualTo(1)

        // Clear all buckets
        rateLimitService.clearAll()
        assertThat(rateLimitService.getBucketCount()).isEqualTo(0)
    }

    @Test
    fun `should handle multiple token consumption`() {
        val key = "test:192.168.1.1"
        val limit = 10
        val tokensToConsume = 3L

        // Should allow consuming multiple tokens if available
        assertThat(rateLimitService.tryConsume(key, limit, tokensToConsume)).isTrue()
        assertThat(rateLimitService.getAvailableTokens(key, limit)).isEqualTo((limit - tokensToConsume))

        // Should reject if not enough tokens available
        repeat(3) {
            rateLimitService.tryConsume(key, limit, tokensToConsume)
        }
        // Now we should have 1 token left, so consuming 3 should fail
        assertThat(rateLimitService.tryConsume(key, limit, tokensToConsume)).isFalse()
    }
}
