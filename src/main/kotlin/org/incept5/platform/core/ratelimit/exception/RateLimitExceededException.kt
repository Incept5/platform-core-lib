package org.incept5.platform.core.ratelimit.exception

import org.incept5.error.RateLimitExceededException as CoreRateLimitExceededException

/**
 * Exception thrown when rate limit is exceeded.
 * Maps to HTTP 429 Too Many Requests with a Retry-After header set from
 * retryAfterSeconds (defaulting to 60) via error-lib's RestErrorHandler.
 */
class RateLimitExceededException(
    message: String = "Rate limit exceeded",
    val requestsPerMinute: Int? = null,
    retryAfterSeconds: Long? = null
) : CoreRateLimitExceededException(message, retryAfterSeconds)
