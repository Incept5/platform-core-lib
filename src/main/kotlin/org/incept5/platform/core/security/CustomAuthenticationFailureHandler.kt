package org.incept5.platform.core.security

import io.quarkus.runtime.StartupEvent
import io.vertx.core.Handler
import io.vertx.core.json.Json
import io.vertx.ext.web.Router
import io.vertx.ext.web.RoutingContext
import org.slf4j.LoggerFactory
import java.time.Instant
import jakarta.enterprise.context.ApplicationScoped
import jakarta.enterprise.event.Observes
import jakarta.inject.Inject
import jakarta.ws.rs.core.Response
import org.incept5.correlation.CorrelationId
import org.incept5.error.ErrorCategory
import org.incept5.error.response.CommonError
import org.incept5.error.response.CommonErrorResponse

@ApplicationScoped
class CustomAuthenticationFailureHandler {

    private val log = LoggerFactory.getLogger(CustomAuthenticationFailureHandler::class.java)

    @Inject
    lateinit var router: Router

    fun init(@Observes event: StartupEvent) {
        // Register failure handler for 401 status code (authentication failures)
        router.errorHandler(401, Handler { context ->
            handleAuthenticationFailure(context)
        })

        // Register failure handler for 500 status code (server errors including auth exceptions)
        router.errorHandler(500) { context ->
            val failure = context.failure()
            log.debug("Handling 500 error with failure: ${failure?.javaClass?.simpleName}: ${failure?.message}")
            when (failure) {
                is UnknownTokenException -> {
                    log.debug("Converting UnknownTokenException to 401: ${failure.message}")
                    sendCustomErrorResponse(context, failure, 401)
                }
                // Handle other JWT/authentication related exceptions that might cause 500s
                is com.auth0.jwt.exceptions.JWTDecodeException -> {
                    log.debug("Converting JWTDecodeException to 401: ${failure.message}")
                    val wrappedException = UnknownTokenException("Invalid token format: ${failure.message}", failure)
                    sendCustomErrorResponse(context, wrappedException, 401)
                }
                is com.auth0.jwt.exceptions.JWTVerificationException -> {
                    log.debug("Converting JWTVerificationException to 401: ${failure.message}")
                    val wrappedException = UnknownTokenException("Token verification failed: ${failure.message}", failure)
                    sendCustomErrorResponse(context, wrappedException, 401)
                }
                else -> {
                    log.debug("Letting default handler process: ${failure?.javaClass?.simpleName}")
                    // Let default handler take over
                    context.next()
                }
            }
        }
        
        log.info("CustomAuthenticationFailureHandler initialized with error handlers for 401 and 500 status codes")
    }

    private fun handleAuthenticationFailure(context: RoutingContext) {
        val failure = context.failure()

        log.debug("Authentication failure: ${failure?.message}")

        when (failure) {
            is UnknownTokenException -> {
                sendCustomErrorResponse(context, failure, 401)
            }
            else -> {
                // Default authentication failure response
                val errorResponse = mapOf(
                    "error" to "authentication_failed",
                    "message" to "Authentication required",
                    "timestamp" to Instant.now().toString()
                )

                context.response()
                    .setStatusCode(401)
                    .putHeader("Content-Type", "application/json")
                    .end(Json.encode(errorResponse))
            }
        }
    }

    private fun sendCustomErrorResponse(context: RoutingContext, exception: Throwable, statusCode: Int) {
        val errorResponse = CommonErrorResponse(
            listOf(CommonError(exception.message ?: "authentication_failed", ErrorCategory.AUTHENTICATION.name, exception.javaClass.simpleName)),
            CorrelationId.getId(),
            Response.Status.UNAUTHORIZED.statusCode,)

        context.response()
            .setStatusCode(statusCode)
            .putHeader("Content-Type", "application/json")
            .end(Json.encode(errorResponse))
    }
}
