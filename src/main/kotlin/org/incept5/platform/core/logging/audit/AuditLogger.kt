
package org.incept5.platform.core.logging.audit

import jakarta.enterprise.context.ApplicationScoped
import org.incept5.correlation.CorrelationId
import org.incept5.platform.core.logging.structured.StructuredLogger
import org.slf4j.LoggerFactory
import java.time.Instant

/**
 * Audit logger for security events, user actions, and compliance tracking.
 * Provides specialized logging for audit trails and security monitoring.
 */
@ApplicationScoped
class AuditLogger {

    private val logger = LoggerFactory.getLogger("AUDIT")
    private val structuredLogger = StructuredLogger()

    /**
     * Logs a user action for audit tracking.
     *
     * @param userId The ID of the user performing the action
     * @param action The action being performed
     * @param resourceType The type of resource being acted upon
     * @param resourceId The ID of the specific resource
     * @param details Additional context details
     */
    fun logUserAction(
        userId: String,
        action: String,
        resourceType: String,
        resourceId: String,
        details: Map<String, Any> = emptyMap()
    ) {
        val auditEvent = AuditEvent(
            userId = userId,
            action = action,
            resourceType = resourceType,
            resourceId = resourceId,
            timestamp = Instant.now(),
            correlationId = CorrelationId.getId() ?: "unknown",
            details = details
        )

        structuredLogger.info("USER_ACTION", mapOf("audit" to auditEvent))
    }

    /**
     * Logs a system event for operational tracking.
     *
     * @param event The system event description
     * @param details Additional event details
     */
    fun logSystemEvent(
        event: String,
        details: Map<String, Any> = emptyMap()
    ) {
        structuredLogger.info("SYSTEM_EVENT", mapOf(
            "event" to event,
            "details" to details,
            "timestamp" to Instant.now()
        ))
    }

    /**
     * Logs a security event for compliance and monitoring.
     *
     * @param event The security event description
     * @param userId Optional user ID if applicable
     * @param ipAddress Optional IP address if available
     * @param details Additional security context
     */
    fun logSecurityEvent(
        event: String,
        userId: String? = null,
        ipAddress: String? = null,
        details: Map<String, Any> = emptyMap()
    ) {
        val securityContext = mutableMapOf<String, Any>().apply {
            put("event", event)
            put("timestamp", Instant.now())
            userId?.let { put("userId", it) }
            ipAddress?.let { put("ipAddress", it) }
            put("details", details)
        }

        structuredLogger.warn("SECURITY_EVENT", securityContext)
    }

    /**
     * Logs a data access event for compliance tracking.
     *
     * @param userId The user accessing the data
     * @param dataType The type of data being accessed
     * @param dataId The specific data identifier
     * @param operation The operation being performed (READ, CREATE, UPDATE, DELETE)
     * @param details Additional context
     */
    fun logDataAccess(
        userId: String,
        dataType: String,
        dataId: String,
        operation: String,
        details: Map<String, Any> = emptyMap()
    ) {
        val dataAccessEvent = DataAccessEvent(
            userId = userId,
            dataType = dataType,
            dataId = dataId,
            operation = operation,
            timestamp = Instant.now(),
            correlationId = CorrelationId.getId() ?: "unknown",
            details = details
        )

        structuredLogger.info("DATA_ACCESS", mapOf("dataAccess" to dataAccessEvent))
    }
}

/**
 * Audit event data model for user actions.
 */
data class AuditEvent(
    val userId: String,
    val action: String,
    val resourceType: String,
    val resourceId: String,
    val timestamp: Instant,
    val correlationId: String,
    val details: Map<String, Any>
)

/**
 * Data access audit event model.
 */
data class DataAccessEvent(
    val userId: String,
    val dataType: String,
    val dataId: String,
    val operation: String,
    val timestamp: Instant,
    val correlationId: String,
    val details: Map<String, Any>
)

/**
 * Audit operation types for data access logging.
 */
object AuditOperations {
    const val CREATE = "CREATE"
    const val READ = "READ"
    const val UPDATE = "UPDATE"
    const val DELETE = "DELETE"
    const val EXPORT = "EXPORT"
    const val IMPORT = "IMPORT"
}
