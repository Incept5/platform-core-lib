
package org.incept5.platform.core.error.handler

import jakarta.ws.rs.core.Response
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.error.response.PlatformErrorResponse
import org.incept5.platform.core.logging.audit.AuditLogger
import org.incept5.platform.core.logging.structured.StructuredLogger
import org.slf4j.LoggerFactory

/**
 * Central error handler that provides consistent error logging and processing
 * across all platform components.
 */
object ErrorHandler {

    private val logger = LoggerFactory.getLogger(ErrorHandler::class.java)
    private val structuredLogger = StructuredLogger()
    private val auditLogger = AuditLogger()

    /**
     * Logs an error with appropriate level and context based on the exception type and HTTP status.
     *
     * @param exception The exception that occurred
     * @param errorResponse The error response that will be returned
     * @param httpStatus The HTTP status that will be returned
     */
    fun logError(exception: Throwable, errorResponse: PlatformErrorResponse, httpStatus: Response.Status) {
        when {
            exception is UnauthorizedException || exception is ForbiddenException -> {
                logSecurityError(exception, errorResponse)
            }
            exception is ApiException -> {
                logPlatformError(exception, errorResponse, httpStatus)
            }
            httpStatus.statusCode >= 500 -> {
                logSystemError(exception, errorResponse)
            }
            else -> {
                logClientError(exception, errorResponse, httpStatus)
            }
        }
    }

    private fun logSecurityError(exception: Throwable, errorResponse: PlatformErrorResponse) {
        auditLogger.logSecurityEvent(
            event = exception.javaClass.simpleName,
            details = mapOf(
                "message" to (exception.message ?: "Security violation"),
                "path" to errorResponse.path,
                "correlationId" to errorResponse.correlationId,
                "errorCode" to errorResponse.error.code
            )
        )
    }

    private fun logPlatformError(exception: ApiException, errorResponse: PlatformErrorResponse, httpStatus: Response.Status) {
        val logLevel = when (httpStatus.statusCode) {
            in 400..499 -> "INFO"
            else -> "ERROR"
        }

        val context = mapOf(
            "errorCode" to errorResponse.error.code,
            "errorSeverity" to errorResponse.error.severity,
            "httpStatus" to httpStatus.statusCode,
            "path" to errorResponse.path,
            "correlationId" to errorResponse.correlationId,
            "errorDetails" to errorResponse.error.details
        )

        if (logLevel == "ERROR") {
            structuredLogger.error("PLATFORM_ERROR", context, exception)
        } else {
            structuredLogger.info("PLATFORM_ERROR", context)
        }
    }

    private fun logSystemError(exception: Throwable, errorResponse: PlatformErrorResponse) {
        structuredLogger.error(
            event = "SYSTEM_ERROR",
            context = mapOf(
                "exceptionType" to exception.javaClass.simpleName,
                "correlationId" to errorResponse.correlationId,
                "path" to errorResponse.path,
                "message" to (exception.message ?: "System error occurred")
            ),
            throwable = exception
        )
    }

    private fun logClientError(exception: Throwable, errorResponse: PlatformErrorResponse, httpStatus: Response.Status) {
        structuredLogger.info(
            event = "CLIENT_ERROR",
            context = mapOf(
                "exceptionType" to exception.javaClass.simpleName,
                "httpStatus" to httpStatus.statusCode,
                "correlationId" to errorResponse.correlationId,
                "path" to errorResponse.path,
                "message" to (exception.message ?: "Client error occurred")
            )
        )
    }
}
