
package org.incept5.platform.core.error.response

import com.fasterxml.jackson.annotation.JsonFormat
import com.fasterxml.jackson.annotation.JsonInclude
import java.time.Instant

/**
 * Standardized error response structure for all platform APIs.
 * Provides consistent error format with correlation tracking and contextual information.
 */
@JsonInclude(JsonInclude.Include.NON_EMPTY)
data class PlatformErrorResponse(
    val error: ErrorDetails,
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX", timezone = "UTC")
    val timestamp: Instant = Instant.now(),
    val correlationId: String,
    val path: String
) {
    /**
     * Detailed error information including code, message, severity and optional field errors.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    data class ErrorDetails(
        val code: String,
        val message: String,
        val severity: String = "ERROR",
        val details: Map<String, Any> = emptyMap(),
        val fieldErrors: List<FieldError> = emptyList()
    )

    /**
     * Field-level validation error information.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    data class FieldError(
        val field: String,
        val rejectedValue: Any?,
        val message: String,
        val code: String? = null
    )
}

/**
 * Enumeration of error severity levels for categorizing error responses.
 */
enum class ErrorSeverity {
    INFO,
    WARNING,
    ERROR,
    CRITICAL
}
