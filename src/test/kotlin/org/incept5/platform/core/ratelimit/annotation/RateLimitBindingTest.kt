package org.incept5.platform.core.ratelimit.annotation

import jakarta.enterprise.util.Nonbinding
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class RateLimitBindingTest {

    // RateLimitInterceptor is bound with a bare @RateLimit. CDI matches binding members by value
    // unless they are @Nonbinding, so a binding member would leave every endpoint that sets its own
    // limit or key without the interceptor (FF-3913).
    @Test
    fun `every RateLimit member is non-binding so the interceptor applies to any usage`() {
        val members = RateLimit::class.java.declaredMethods

        assertThat(members.map { it.name })
            .containsExactlyInAnyOrder("requestsPerMinute", "key", "keyPathParam")
        members.forEach { member ->
            assertThat(member.isAnnotationPresent(Nonbinding::class.java))
                .describedAs("@RateLimit.%s must be @Nonbinding", member.name)
                .isTrue()
        }
    }
}
