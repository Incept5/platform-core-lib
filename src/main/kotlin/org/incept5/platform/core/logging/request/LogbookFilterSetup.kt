package org.incept5.platform.core.logging.request

import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.ext.Provider
import jakarta.ws.rs.ext.WriterInterceptor
import jakarta.ws.rs.ext.WriterInterceptorContext
import org.zalando.logbook.Logbook
import org.zalando.logbook.jaxrs.LogbookServerFilter
import java.io.IOException

@Provider
@Suppress("unused")
class LogbookFilterSetup : ContainerRequestFilter, ContainerResponseFilter, WriterInterceptor {

    private val logbookServerFilter = LogbookServerFilter(Logbook.create())

    @Throws(IOException::class, WebApplicationException::class)
    override fun filter(context: ContainerRequestContext) {
        logbookServerFilter.filter(context)
    }

    override fun filter(requestContext: ContainerRequestContext, responseContext: ContainerResponseContext) {
        logbookServerFilter.filter(requestContext, responseContext)
    }

    @Throws(IOException::class, WebApplicationException::class)
    override fun aroundWriteTo(context: WriterInterceptorContext) {
        logbookServerFilter.aroundWriteTo(context)
    }
}
