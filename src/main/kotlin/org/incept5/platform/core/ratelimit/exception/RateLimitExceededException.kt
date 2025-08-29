package org.incept5.platform.core.ratelimit.exception

import org.incept5.platform.core.error.ApiException
import org.incept5.error.ErrorCategory

/**
 * Exception thrown when rate limit is exceeded.
 * Maps to HTTP 429 Too Many Requests status code.
 */
class RateLimitExceededException(
    message: String = "Rate limit exceeded",
    val requestsPerMinute: Int? = null,
    val retryAfterSeconds: Long? = null
) : ApiException(message, ErrorCategory.CONFLICT)
