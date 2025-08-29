package org.incept5.platform.core.ratelimit.interceptor

import jakarta.annotation.Priority
import jakarta.inject.Inject
import jakarta.interceptor.AroundInvoke
import jakarta.interceptor.Interceptor
import jakarta.interceptor.InvocationContext
import jakarta.ws.rs.core.Context
import io.vertx.core.http.HttpServerRequest
import org.incept5.platform.core.ratelimit.annotation.RateLimit
import org.incept5.platform.core.ratelimit.exception.RateLimitExceededException
import org.incept5.platform.core.ratelimit.service.RateLimitService
import org.slf4j.LoggerFactory

/**
 * Interceptor that enforces rate limiting on annotated methods.
 * Extracts client IP from HTTP request and uses it as the rate limit key.
 */
@RateLimit
@Interceptor
@Priority(Interceptor.Priority.APPLICATION)
class RateLimitInterceptor {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Inject
    lateinit var rateLimitService: RateLimitService

    // HTTP request will be injected at runtime in Quarkus environment
    @Context
    var httpServerRequest: HttpServerRequest? = null

    @AroundInvoke
    fun intercept(context: InvocationContext): Any {
        val annotation = getRateLimitAnnotation(context)
        val clientIp = extractClientIp()
        val rateLimitKey = "${annotation.key}:${clientIp}"

        logger.debug("Checking rate limit for key: {}, limit: {}/min", rateLimitKey, annotation.requestsPerMinute)

        if (!rateLimitService.tryConsume(rateLimitKey, annotation.requestsPerMinute)) {
            val availableTokens = rateLimitService.getAvailableTokens(rateLimitKey, annotation.requestsPerMinute)

            logger.warn(
                "Rate limit exceeded for IP: {}, endpoint: {}, limit: {}/min, available: {}",
                clientIp, annotation.key, annotation.requestsPerMinute, availableTokens
            )

            throw RateLimitExceededException(
                message = "Rate limit exceeded. Maximum ${annotation.requestsPerMinute} requests per minute allowed.",
                requestsPerMinute = annotation.requestsPerMinute,
                retryAfterSeconds = 60 // Simple approach: retry after 1 minute
            )
        }

        return context.proceed()
    }

    /**
     * Extracts the RateLimit annotation from the method or class.
     * Method-level annotation takes precedence over class-level.
     */
    private fun getRateLimitAnnotation(context: InvocationContext): RateLimit {
        // First check method-level annotation
        val methodAnnotation = context.method.getAnnotation(RateLimit::class.java)
        if (methodAnnotation != null) {
            return methodAnnotation
        }

        // Fall back to class-level annotation
        val classAnnotation = context.target.javaClass.getAnnotation(RateLimit::class.java)
        if (classAnnotation != null) {
            return classAnnotation
        }

        // This should not happen if interceptor binding is configured correctly
        throw IllegalStateException("RateLimit annotation not found on method or class")
    }

    /**
     * Extracts client IP address from HTTP request.
     * This implementation works with Vert.x HttpServerRequest.
     */
    private fun extractClientIp(): String {
        return try {
            httpServerRequest?.let { request ->
                // Check for X-Forwarded-For header first
                val xForwardedFor = request.getHeader("X-Forwarded-For")
                if (!xForwardedFor.isNullOrBlank()) {
                    return xForwardedFor.split(",")[0].trim()
                }

                // Check X-Real-IP header
                val xRealIp = request.getHeader("X-Real-IP")
                if (!xRealIp.isNullOrBlank()) {
                    return xRealIp.trim()
                }

                // Fall back to remote address
                request.remoteAddress()?.host() ?: "unknown"
            } ?: "unknown"
        } catch (e: Exception) {
            logger.warn("Failed to extract client IP: ${e.message}")
            "unknown"
        }
    }
}
