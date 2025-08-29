package org.incept5.platform.core.ratelimit.annotation

import jakarta.interceptor.InterceptorBinding

/**
 * Annotation to apply rate limiting to REST endpoints.
 * Can be applied at class or method level.
 *
 * @param requestsPerMinute Maximum number of requests allowed per minute per IP address
 * @param key Unique key to identify this rate limit rule (useful for grouping endpoints)
 */
@InterceptorBinding
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class RateLimit(
    val requestsPerMinute: Int = 100,
    val key: String = "default"
)
