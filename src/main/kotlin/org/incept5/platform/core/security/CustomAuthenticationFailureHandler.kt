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
        // Register failure handler for 401 status code
        router.errorHandler(401, Handler { context ->
            handleAuthenticationFailure(context)
        })

        // You can also register for specific exception types
        router.errorHandler(500) { context ->
            val failure = context.failure()
            when (failure) {
                is UnknownTokenException -> {
                    log.debug("Handling UnknownTokenException: ${failure.message}")
                    sendCustomErrorResponse(context, failure, 401)
                }
                // Add other custom exceptions here
                else -> {
                    // Let default handler take over
                    context.next()
                }
            }
        }
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
