
package org.incept5.platform.core.error.mapper

import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider
import org.incept5.correlation.CorrelationId
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.error.ConflictException
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.InvalidRequestException
import org.incept5.platform.core.error.NotFoundException
import org.incept5.platform.core.error.OptimisticLockException
import org.incept5.platform.core.error.ResourceNotFoundException
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.error.handler.ErrorHandler
import org.incept5.platform.core.error.response.PlatformErrorResponse
import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Global exception mapper that handles all ApiException types and converts them to proper HTTP responses.
 * This mapper provides consistent error handling across all platform APIs.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
class GlobalExceptionMapper : ExceptionMapper<Exception> {

    private val logger = LoggerFactory.getLogger(GlobalExceptionMapper::class.java)

    @Context
    lateinit var uriInfo: UriInfo

    override fun toResponse(exception: Exception): Response {
        logger.debug("Processing exception: ${exception.javaClass.simpleName} - ${exception.message}")

        return when (exception) {
            is ApiException -> handleApiException(exception)
            is WebApplicationException -> handleWebApplicationException(exception)
            else -> handleGeneralException(exception)
        }
    }

    private fun handleApiException(exception: ApiException): Response {
        val status = mapApiExceptionToHttpStatus(exception)

        val errorResponse = PlatformErrorResponse(
            error = PlatformErrorResponse.ErrorDetails(
                code = mapExceptionToErrorCode(exception),
                message = exception.message ?: "An error occurred",
                severity = mapExceptionToSeverity(exception),
                details = extractErrorDetails(exception)
            ),
            timestamp = Instant.now(),
            correlationId = CorrelationId.getId() ?: "unknown",
            path = uriInfo.path
        )

        ErrorHandler.logError(exception, errorResponse, status)

        return Response.status(status)
            .entity(errorResponse)
            .type(MediaType.APPLICATION_JSON)
            .build()
    }

    private fun handleWebApplicationException(exception: WebApplicationException): Response {
        val status = Response.Status.fromStatusCode(exception.response?.status ?: 500)
            ?: Response.Status.INTERNAL_SERVER_ERROR

        val errorResponse = PlatformErrorResponse(
            error = PlatformErrorResponse.ErrorDetails(
                code = status.name.replace(" ", "_").uppercase(),
                message = exception.message ?: status.reasonPhrase,
                severity = if (status.statusCode >= 500) "ERROR" else "WARNING"
            ),
            timestamp = Instant.now(),
            correlationId = CorrelationId.getId() ?: "unknown",
            path = uriInfo.path
        )

        ErrorHandler.logError(exception, errorResponse, status)

        return Response.status(status)
            .entity(errorResponse)
            .type(MediaType.APPLICATION_JSON)
            .build()
    }

    private fun handleGeneralException(exception: Exception): Response {
        val status = Response.Status.INTERNAL_SERVER_ERROR

        val errorResponse = PlatformErrorResponse(
            error = PlatformErrorResponse.ErrorDetails(
                code = "INTERNAL_SERVER_ERROR",
                message = "An unexpected error occurred",
                severity = "ERROR"
            ),
            timestamp = Instant.now(),
            correlationId = CorrelationId.getId() ?: "unknown",
            path = uriInfo.path
        )

        ErrorHandler.logError(exception, errorResponse, status)

        return Response.status(status)
            .entity(errorResponse)
            .type(MediaType.APPLICATION_JSON)
            .build()
    }

    private fun mapApiExceptionToHttpStatus(exception: ApiException): Response.Status {
        return when (exception) {
            is UnauthorizedException -> Response.Status.UNAUTHORIZED
            is ForbiddenException -> Response.Status.FORBIDDEN
            is NotFoundException, is ResourceNotFoundException -> Response.Status.NOT_FOUND
            is InvalidRequestException -> Response.Status.BAD_REQUEST
            is ConflictException, is OptimisticLockException -> Response.Status.CONFLICT
            else -> Response.Status.INTERNAL_SERVER_ERROR
        }
    }

    private fun mapExceptionToErrorCode(exception: ApiException): String {
        return when (exception) {
            is UnauthorizedException -> "UNAUTHORIZED"
            is ForbiddenException -> "FORBIDDEN"
            is NotFoundException -> "NOT_FOUND"
            is ResourceNotFoundException -> "RESOURCE_NOT_FOUND"
            is InvalidRequestException -> "INVALID_REQUEST"
            is ConflictException -> "CONFLICT"
            is OptimisticLockException -> "OPTIMISTIC_LOCK_FAILURE"
            else -> "API_ERROR"
        }
    }

    private fun mapExceptionToSeverity(exception: ApiException): String {
        return when (exception) {
            is UnauthorizedException, is ForbiddenException -> "WARNING"
            is NotFoundException, is ResourceNotFoundException -> "INFO"
            is InvalidRequestException -> "WARNING"
            is ConflictException, is OptimisticLockException -> "WARNING"
            else -> "ERROR"
        }
    }

    private fun extractErrorDetails(exception: ApiException): Map<String, Any> {
        val details = mutableMapOf<String, Any>()

        when (exception) {
            is OptimisticLockException -> {
                details["type"] = "optimistic_lock_failure"
                details["suggestion"] = "Retrieve the latest version and retry"
            }
            is ResourceNotFoundException -> {
                details["type"] = "resource_not_found"
            }
            is ConflictException -> {
                details["type"] = "resource_conflict"
            }
        }

        return details
    }
}
