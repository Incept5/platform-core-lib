
package org.incept5.platform.core.error.mapper

import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriInfo
import org.assertj.core.api.Assertions.assertThat
import org.incept5.correlation.CorrelationId
import org.incept5.platform.core.error.ConflictException
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.InvalidRequestException
import org.incept5.platform.core.error.NotFoundException
import org.incept5.platform.core.error.OptimisticLockException
import org.incept5.platform.core.error.ResourceNotFoundException
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.error.response.PlatformErrorResponse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class GlobalExceptionMapperTest {

    private lateinit var exceptionMapper: GlobalExceptionMapper
    private lateinit var mockUriInfo: UriInfo

    @BeforeEach
    fun setup() {
        exceptionMapper = GlobalExceptionMapper()
        mockUriInfo = mock()
        whenever(mockUriInfo.path).thenReturn("/api/v1/test")
        exceptionMapper.uriInfo = mockUriInfo

        // Set a test correlation ID
        CorrelationId.setId("test-correlation-id")
    }

    @Test
    fun `should map UnauthorizedException to 401 response`() {
        val exception = UnauthorizedException("Authentication required")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(401)
        assertThat(response.entity).isInstanceOf(PlatformErrorResponse::class.java)

        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("UNAUTHORIZED")
        assertThat(errorResponse.error.message).isEqualTo("Authentication required")
        assertThat(errorResponse.error.severity).isEqualTo("WARNING")
        assertThat(errorResponse.correlationId).isEqualTo("test-correlation-id")
        assertThat(errorResponse.path).isEqualTo("/api/v1/test")
    }

    @Test
    fun `should map ForbiddenException to 403 response`() {
        val exception = ForbiddenException("Access denied")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(403)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("FORBIDDEN")
        assertThat(errorResponse.error.message).isEqualTo("Access denied")
        assertThat(errorResponse.error.severity).isEqualTo("WARNING")
    }

    @Test
    fun `should map NotFoundException to 404 response`() {
        val exception = NotFoundException("User not found")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(404)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("NOT_FOUND")
        assertThat(errorResponse.error.message).isEqualTo("User not found")
        assertThat(errorResponse.error.severity).isEqualTo("INFO")
    }

    @Test
    fun `should map ResourceNotFoundException to 404 response`() {
        val exception = ResourceNotFoundException("Partner resource not found")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(404)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("RESOURCE_NOT_FOUND")
        assertThat(errorResponse.error.message).isEqualTo("Partner resource not found")
        assertThat(errorResponse.error.severity).isEqualTo("INFO")
    }

    @Test
    fun `should map InvalidRequestException to 400 response`() {
        val exception = InvalidRequestException("Invalid request data")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(400)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("INVALID_REQUEST")
        assertThat(errorResponse.error.message).isEqualTo("Invalid request data")
        assertThat(errorResponse.error.severity).isEqualTo("WARNING")
    }

    @Test
    fun `should map ConflictException to 409 response`() {
        val exception = ConflictException("Resource already exists")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(409)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("CONFLICT")
        assertThat(errorResponse.error.message).isEqualTo("Resource already exists")
        assertThat(errorResponse.error.severity).isEqualTo("WARNING")
    }

    @Test
    fun `should map OptimisticLockException to 409 response with details`() {
        val exception = OptimisticLockException("Resource has been modified")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(409)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("OPTIMISTIC_LOCK_FAILURE")
        assertThat(errorResponse.error.message).isEqualTo("Resource has been modified")
        assertThat(errorResponse.error.details["type"]).isEqualTo("optimistic_lock_failure")
        assertThat(errorResponse.error.details["suggestion"]).isEqualTo("Retrieve the latest version and retry")
    }

    @Test
    fun `should map WebApplicationException to appropriate response`() {
        val exception = WebApplicationException("Bad request", Response.Status.BAD_REQUEST)

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(400)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("BAD_REQUEST")
        assertThat(errorResponse.error.message).isEqualTo("Bad request")
    }

    @Test
    fun `should map general exception to 500 response`() {
        val exception = RuntimeException("Unexpected error")

        val response = exceptionMapper.toResponse(exception)

        assertThat(response.status).isEqualTo(500)
        val errorResponse = response.entity as PlatformErrorResponse
        assertThat(errorResponse.error.code).isEqualTo("INTERNAL_SERVER_ERROR")
        assertThat(errorResponse.error.message).isEqualTo("An unexpected error occurred")
        assertThat(errorResponse.error.severity).isEqualTo("ERROR")
    }

    @Test
    fun `should handle missing correlation ID gracefully`() {
        CorrelationId.clear()
        val exception = NotFoundException("Test not found")

        val response = exceptionMapper.toResponse(exception)

        val errorResponse = response.entity as PlatformErrorResponse
        // The correlation ID library may generate a new ID when cleared, so we just verify it's not null
        assertThat(errorResponse.correlationId).isNotNull()
        assertThat(errorResponse.correlationId).isNotBlank()
    }
}
