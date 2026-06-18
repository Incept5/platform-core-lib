package org.incept5.platform.core.ratelimit.annotation

import jakarta.interceptor.InterceptorBinding

/**
 * Annotation to apply rate limiting to REST endpoints.
 * Can be applied at class or method level.
 *
 * @param requestsPerMinute Maximum number of requests allowed per minute per client.
 *        Used as the fallback limit; a `rate-limit.limits."<key>"` config entry, when present,
 *        overrides this value so limits are tunable without changing the annotation.
 * @param key Unique key to identify this rate limit rule (also the config-override lookup key).
 * @param keyPathParam Optional name of a `@PathParam` on the annotated method whose value is
 *        appended to the bucket key, giving each value its own bucket (e.g. `"sessionId"` so two
 *        sessions from the same client are throttled independently). Empty = no extra dimension.
 */
@InterceptorBinding
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class RateLimit(
    val requestsPerMinute: Int = 100,
    val key: String = "default",
    val keyPathParam: String = "",
)
