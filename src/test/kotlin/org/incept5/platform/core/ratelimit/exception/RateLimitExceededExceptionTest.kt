package org.incept5.platform.core.ratelimit.exception

import org.assertj.core.api.Assertions.assertThat
import org.incept5.error.ErrorCategory
import org.junit.jupiter.api.Test

class RateLimitExceededExceptionTest {

    @Test
    fun `should carry RATE_LIMIT_EXCEEDED category so error-lib maps it to 429`() {
        val exception = RateLimitExceededException(
            message = "Rate limit exceeded. Maximum 10 requests per minute allowed.",
            requestsPerMinute = 10,
            retryAfterSeconds = 60
        )

        assertThat(exception.category).isEqualTo(ErrorCategory.RATE_LIMIT_EXCEEDED)
        assertThat(exception.errors).hasSize(1)
        assertThat(exception.errors[0].code).isEqualTo("RATE_LIMIT_EXCEEDED")
        assertThat(exception.retryable).isTrue()
        assertThat(exception.retryAfterSeconds).isEqualTo(60)
        assertThat(exception.requestsPerMinute).isEqualTo(10)
    }

    @Test
    fun `should default message and leave retryAfterSeconds null when not supplied`() {
        val exception = RateLimitExceededException()

        assertThat(exception.message).isEqualTo("Rate limit exceeded")
        assertThat(exception.retryAfterSeconds).isNull()
        assertThat(exception.requestsPerMinute).isNull()
    }
}
