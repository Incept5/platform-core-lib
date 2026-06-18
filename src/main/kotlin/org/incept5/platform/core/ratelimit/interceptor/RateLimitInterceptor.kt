package org.incept5.platform.core.ratelimit.interceptor

import jakarta.annotation.Priority
import jakarta.inject.Inject
import jakarta.interceptor.AroundInvoke
import jakarta.interceptor.Interceptor
import jakarta.interceptor.InvocationContext
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.core.Context
import io.vertx.core.http.HttpServerRequest
import org.incept5.platform.core.ratelimit.annotation.RateLimit
import org.incept5.platform.core.ratelimit.config.RateLimitConfig
import org.incept5.platform.core.ratelimit.exception.RateLimitExceededException
import org.incept5.platform.core.ratelimit.ip.ClientIpResolver
import org.incept5.platform.core.ratelimit.service.RateLimitService
import org.slf4j.LoggerFactory

/**
 * Interceptor that enforces rate limiting on annotated methods.
 *
 * The bucket key is `{annotation.key}:{clientIp}[:{pathParamValue}]`, where:
 *  - `clientIp` is resolved by [ClientIpResolver] (spoof-resistant trusted-proxy-hop XFF by
 *    default — no longer the leftmost, attacker-controlled value);
 *  - the optional `pathParamValue` is appended when the annotation sets `keyPathParam`, giving
 *    each path-param value its own bucket.
 *
 * The effective limit is the per-key `rate-limit.limits` config value when present, otherwise the
 * annotation's `requestsPerMinute`. Rate limiting can be disabled globally via `rate-limit.enabled`.
 */
@RateLimit
@Interceptor
@Priority(Interceptor.Priority.APPLICATION)
class RateLimitInterceptor {

    private val logger = LoggerFactory.getLogger(javaClass)

    @Inject
    lateinit var rateLimitService: RateLimitService

    @Inject
    lateinit var clientIpResolver: ClientIpResolver

    @Inject
    lateinit var config: RateLimitConfig

    // HTTP request will be injected at runtime in Quarkus environment
    @Context
    var httpServerRequest: HttpServerRequest? = null

    @AroundInvoke
    fun intercept(context: InvocationContext): Any {
        if (!config.enabled()) {
            return context.proceed()
        }

        val annotation = getRateLimitAnnotation(context)
        val limit = resolveLimit(annotation)
        val clientIp = clientIpResolver.resolve(httpServerRequest)
        val rateLimitKey = buildKey(annotation, clientIp, context)

        logger.debug("Checking rate limit for key: {}, limit: {}/min", rateLimitKey, limit)

        if (!rateLimitService.tryConsume(rateLimitKey, limit)) {
            val availableTokens = rateLimitService.getAvailableTokens(rateLimitKey, limit)

            logger.warn(
                "Rate limit exceeded for IP: {}, endpoint: {}, limit: {}/min, available: {}",
                clientIp, annotation.key, limit, availableTokens
            )

            throw RateLimitExceededException(
                message = "Rate limit exceeded. Maximum $limit requests per minute allowed.",
                requestsPerMinute = limit,
                retryAfterSeconds = 60 // Simple approach: retry after 1 minute
            )
        }

        return context.proceed()
    }

    /**
     * Resolves the effective limit: a `rate-limit.limits."<key>"` config override if present,
     * otherwise the annotation's compile-time value.
     */
    private fun resolveLimit(annotation: RateLimit): Int =
        config.limits()[annotation.key] ?: annotation.requestsPerMinute

    /**
     * Builds the bucket key, optionally appending the configured path-param value so each value
     * gets an independent bucket.
     */
    private fun buildKey(annotation: RateLimit, clientIp: String, context: InvocationContext): String {
        val base = "${annotation.key}:$clientIp"
        val dimension = resolvePathParamValue(annotation.keyPathParam, context)
        return if (dimension != null) "$base:$dimension" else base
    }

    /**
     * Finds the value of the method `@PathParam` whose name matches [name] (empty = none).
     */
    private fun resolvePathParamValue(name: String, context: InvocationContext): String? {
        if (name.isBlank()) return null
        val parameters = context.method.parameters
        val args = context.parameters
        for (i in parameters.indices) {
            val pathParam = parameters[i].getAnnotation(PathParam::class.java)
            if (pathParam != null && pathParam.value == name) {
                return args.getOrNull(i)?.toString()
            }
        }
        logger.debug("keyPathParam '{}' not found among method params for key {}", name, "${context.method.name}")
        return null
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
}
