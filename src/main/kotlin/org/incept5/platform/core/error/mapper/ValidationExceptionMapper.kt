
package org.incept5.platform.core.error.mapper

import jakarta.annotation.Priority
import jakarta.validation.ConstraintViolationException
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import jakarta.ws.rs.ext.ExceptionMapper
import jakarta.ws.rs.ext.Provider
import org.incept5.correlation.CorrelationId
import org.incept5.platform.core.error.handler.ErrorHandler
import org.slf4j.LoggerFactory

/**
 * Exception mapper for handling Bean Validation exceptions and converting them to proper HTTP responses.
 * Returns the legacy error format expected by existing tests and API consumers.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 2)
class ValidationExceptionMapper : ExceptionMapper<ConstraintViolationException> {

    private val logger = LoggerFactory.getLogger(ValidationExceptionMapper::class.java)

    @Context
    lateinit var uriInfo: UriInfo

    override fun toResponse(exception: ConstraintViolationException): Response {
        logger.debug("Processing constraint violation exception with {} violations", exception.constraintViolations.size)

        val errors = exception.constraintViolations.map { violation ->
            LegacyServiceError(
                code = "VALIDATION",
                message = violation.message,
                location = extractFieldPath(violation.propertyPath.toString())
            )
        }

        val errorResponse = LegacyErrorResponse(
            errors = errors,
            correlationId = CorrelationId.getId() ?: "unknown",
            httpStatusCode = Response.Status.BAD_REQUEST.statusCode
        )

        val status = Response.Status.BAD_REQUEST

        // Log using the legacy format for compatibility
        logger.warn("Validation failed with {} violations: {}", errors.size,
            errors.joinToString { "${it.location}: ${it.message}" })

        return Response.status(status)
            .entity(errorResponse)
            .type(MediaType.APPLICATION_JSON)
            .build()
    }

    private fun extractFieldPath(propertyPath: String): String {
        // Remove method parameter prefixes like "methodName.arg0." to get clean field names
        val parts = propertyPath.split(".")
        return if (parts.size > 2 && parts[1].startsWith("arg")) {
            parts.drop(2).joinToString(".")
        } else {
            propertyPath
        }
    }
}

/**
 * Legacy error response structure to maintain API compatibility.
 * This matches the format expected by existing tests and API consumers.
 */
private data class LegacyErrorResponse(
    val errors: List<LegacyServiceError>,
    val correlationId: String,
    val httpStatusCode: Int
)

/**
 * Legacy service error structure for individual validation errors.
 */
private data class LegacyServiceError(
    val code: String,
    val message: String,
    val location: String? = null
)
