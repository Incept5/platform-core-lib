package org.incept5.platform.core.logging.correlation

import org.incept5.correlation.CorrelationId
import jakarta.annotation.Priority
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.ext.Provider
import jakarta.ws.rs.Priorities
import java.util.UUID

@Provider
@Priority(Priorities.HEADER_DECORATOR)
class CorrelationIdFilter : ContainerRequestFilter, ContainerResponseFilter {

    companion object {
        const val CORRELATION_ID_HEADER = "X-Correlation-ID"
        private const val CORRELATION_ID_PROPERTY = "correlationId"
    }

    override fun filter(requestContext: ContainerRequestContext) {
        // Get or create a new correlation ID
        val correlationId = requestContext.headers.getFirst(CORRELATION_ID_HEADER)
            ?: CorrelationId.getId()
            ?: UUID.randomUUID().toString()

        // Set the correlation ID in the thread local context
        CorrelationId.setId(correlationId)

        // Store the correlation ID in the request property for later use in the response filter
        requestContext.setProperty(CORRELATION_ID_PROPERTY, correlationId)

        // Add or update the correlation ID header in the request
        requestContext.headers.putSingle(CORRELATION_ID_HEADER, correlationId)
    }

    override fun filter(requestContext: ContainerRequestContext, responseContext: ContainerResponseContext) {
        // Get the correlation ID from the request property
        val correlationId = requestContext.getProperty(CORRELATION_ID_PROPERTY) as? String
            ?: CorrelationId.getId()
            ?: UUID.randomUUID().toString()

        // Add the correlation ID to the response headers
        responseContext.headers.putSingle(CORRELATION_ID_HEADER, correlationId)
    }
}
