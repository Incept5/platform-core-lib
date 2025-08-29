
package org.incept5.platform.core.logging.structured

import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.incept5.correlation.CorrelationId
import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Structured logger that outputs JSON-formatted log entries for better parsing and analysis.
 * Integrates with correlation ID tracking for distributed tracing.
 */
@ApplicationScoped
class StructuredLogger {

    private val logger = LoggerFactory.getLogger(StructuredLogger::class.java)
    private val objectMapper = ObjectMapper()

    /**
     * Logs an informational event with structured context.
     *
     * @param event The event name/type
     * @param context Additional context data
     */
    fun info(event: String, context: Map<String, Any> = emptyMap()) {
        log(LogLevel.INFO, event, context, null)
    }

    /**
     * Logs a warning event with structured context.
     *
     * @param event The event name/type
     * @param context Additional context data
     * @param throwable Optional exception
     */
    fun warn(event: String, context: Map<String, Any> = emptyMap(), throwable: Throwable? = null) {
        log(LogLevel.WARN, event, context, throwable)
    }

    /**
     * Logs an error event with structured context.
     *
     * @param event The event name/type
     * @param context Additional context data
     * @param throwable Optional exception
     */
    fun error(event: String, context: Map<String, Any> = emptyMap(), throwable: Throwable? = null) {
        log(LogLevel.ERROR, event, context, throwable)
    }

    /**
     * Logs a debug event with structured context.
     *
     * @param event The event name/type
     * @param context Additional context data
     */
    fun debug(event: String, context: Map<String, Any> = emptyMap()) {
        log(LogLevel.DEBUG, event, context, null)
    }

    private fun log(level: LogLevel, event: String, context: Map<String, Any>, throwable: Throwable?) {
        val logEvent = LogEvent(
            timestamp = Instant.now(),
            level = level,
            event = event,
            correlationId = CorrelationId.getId() ?: "unknown",
            context = context.plus("thread" to Thread.currentThread().name)
        )

        try {
            val logMessage = objectMapper.writeValueAsString(logEvent)

            when (level) {
                LogLevel.DEBUG -> logger.debug(logMessage)
                LogLevel.INFO -> logger.info(logMessage)
                LogLevel.WARN -> if (throwable != null) logger.warn(logMessage, throwable) else logger.warn(logMessage)
                LogLevel.ERROR -> if (throwable != null) logger.error(logMessage, throwable) else logger.error(logMessage)
            }
        } catch (e: Exception) {
            // Fallback to simple logging if JSON serialization fails
            logger.error("Failed to serialize structured log event. Event: $event, Error: ${e.message}", e)
            when (level) {
                LogLevel.DEBUG -> logger.debug("$event - Context: $context")
                LogLevel.INFO -> logger.info("$event - Context: $context")
                LogLevel.WARN -> if (throwable != null) logger.warn("$event - Context: $context", throwable) else logger.warn("$event - Context: $context")
                LogLevel.ERROR -> if (throwable != null) logger.error("$event - Context: $context", throwable) else logger.error("$event - Context: $context")
            }
        }
    }
}

/**
 * Structured log event data model.
 */
data class LogEvent(
    val timestamp: Instant,
    val level: LogLevel,
    val event: String,
    val correlationId: String,
    val context: Map<String, Any>
)

/**
 * Log levels for structured logging.
 */
enum class LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
}
