package org.incept5.platform.core.ratelimit.interceptor

import jakarta.interceptor.InvocationContext
import jakarta.ws.rs.PathParam
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.catchThrowable
import org.incept5.platform.core.ratelimit.annotation.RateLimit
import org.incept5.platform.core.ratelimit.config.ClientIpStrategy
import org.incept5.platform.core.ratelimit.config.RateLimitConfig
import org.incept5.platform.core.ratelimit.exception.RateLimitExceededException
import org.incept5.platform.core.ratelimit.ip.ClientIpResolver
import org.incept5.platform.core.ratelimit.service.RateLimitService
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import java.lang.reflect.Method
import java.time.Duration

class RateLimitInterceptorTest {

    /** Source of real annotated [Method] objects for the interceptor under test. */
    @Suppress("UNUSED_PARAMETER")
    class Sample {
        @RateLimit(requestsPerMinute = 5, key = "annotated")
        fun annotatedOnly() = "ok"

        @RateLimit(requestsPerMinute = 5, key = "configurable")
        fun configurable() = "ok"

        @RateLimit(requestsPerMinute = 5, key = "session", keyPathParam = "sessionId")
        fun withSession(@PathParam("sessionId") sessionId: String) = "ok"
    }

    private fun interceptor(
        config: RateLimitConfig,
        clientIp: String = "203.0.113.7",
    ): RateLimitInterceptor = RateLimitInterceptor().apply {
        rateLimitService = RateLimitService() // real bounded in-memory store
        clientIpResolver = mock<ClientIpResolver> { on { resolve(any()) } doReturn clientIp }
        this.config = config
    }

    private fun context(method: Method, args: Array<Any?> = emptyArray()): InvocationContext =
        mock {
            on { this.method } doReturn method
            on { parameters } doReturn args
            on { proceed() } doReturn "PROCEEDED"
        }

    @Test
    fun `AC5 - config limit overrides the annotation value`() {
        val cfg = FakeRateLimitConfig(enabled = true, limits = mapOf("configurable" to 2))
        val interceptor = interceptor(cfg)
        val method = Sample::class.java.getMethod("configurable")

        // limit is 2 (config), not 5 (annotation): first 2 pass, 3rd is rejected
        assertThat(interceptor.intercept(context(method))).isEqualTo("PROCEEDED")
        assertThat(interceptor.intercept(context(method))).isEqualTo("PROCEEDED")
        val thrown = catchThrowable { interceptor.intercept(context(method)) }
        assertThat(thrown).isInstanceOf(RateLimitExceededException::class.java)
        assertThat((thrown as RateLimitExceededException).requestsPerMinute).isEqualTo(2)
    }

    @Test
    fun `AC5 - annotation value is the fallback when no config override`() {
        val cfg = FakeRateLimitConfig(enabled = true, limits = emptyMap())
        val interceptor = interceptor(cfg)
        val method = Sample::class.java.getMethod("annotatedOnly")

        // limit is the annotation's 5
        repeat(5) { assertThat(interceptor.intercept(context(method))).isEqualTo("PROCEEDED") }
        assertThat(catchThrowable { interceptor.intercept(context(method)) })
            .isInstanceOf(RateLimitExceededException::class.java)
    }

    @Test
    fun `AC6 - different path-param values get independent buckets`() {
        val cfg = FakeRateLimitConfig(enabled = true, limits = mapOf("session" to 1))
        val interceptor = interceptor(cfg)
        val method = Sample::class.java.getMethod("withSession", String::class.java)

        // sessionA: limit 1 -> first ok, second rejected
        assertThat(interceptor.intercept(context(method, arrayOf("sessionA")))).isEqualTo("PROCEEDED")
        assertThat(catchThrowable { interceptor.intercept(context(method, arrayOf("sessionA"))) })
            .isInstanceOf(RateLimitExceededException::class.java)

        // sessionB: independent bucket -> still allowed despite sessionA being exhausted
        assertThat(interceptor.intercept(context(method, arrayOf("sessionB")))).isEqualTo("PROCEEDED")
    }

    @Test
    fun `same client and same session share a bucket`() {
        val cfg = FakeRateLimitConfig(enabled = true, limits = mapOf("session" to 1))
        val interceptor = interceptor(cfg)
        val method = Sample::class.java.getMethod("withSession", String::class.java)

        assertThat(interceptor.intercept(context(method, arrayOf("sessionA")))).isEqualTo("PROCEEDED")
        assertThat(catchThrowable { interceptor.intercept(context(method, arrayOf("sessionA"))) })
            .isInstanceOf(RateLimitExceededException::class.java)
    }

    @Test
    fun `disabled config bypasses rate limiting entirely`() {
        // limit 0 would reject everything if enforced; disabled => always proceeds
        val cfg = FakeRateLimitConfig(enabled = false, limits = mapOf("annotated" to 0))
        val interceptor = interceptor(cfg)
        val method = Sample::class.java.getMethod("annotatedOnly")

        repeat(10) { assertThat(interceptor.intercept(context(method))).isEqualTo("PROCEEDED") }
    }

    /** Minimal hand-rolled [RateLimitConfig] — only the methods the interceptor uses are real. */
    private class FakeRateLimitConfig(
        private val enabled: Boolean,
        private val limits: Map<String, Int>,
    ) : RateLimitConfig {
        override fun enabled() = enabled
        override fun defaultRequestsPerMinute() = 100
        override fun limits() = limits
        override fun clientIp() = object : RateLimitConfig.ClientIpConfig {
            override fun strategy() = ClientIpStrategy.TRUSTED_PROXY_HOPS
            override fun trustedProxyHops() = 2
        }
        override fun bucket() = object : RateLimitConfig.BucketConfig {
            override fun maxSize() = 100_000L
            override fun idleTtl(): Duration = Duration.ofMinutes(10)
        }
        override fun paymentSession() = object : RateLimitConfig.PaymentSessionRateLimitConfig {
            override fun cancellationRequestsPerMinute() = 10
            override fun includeHeaders() = true
        }
    }
}
