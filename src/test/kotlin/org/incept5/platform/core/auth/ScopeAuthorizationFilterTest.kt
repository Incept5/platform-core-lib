
package org.incept5.platform.core.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.kotest.matchers.string.shouldContain
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.HttpHeaders
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import java.lang.reflect.Method
import java.time.Instant
import java.util.*

class ScopeAuthorizationFilterTest {

    private lateinit var scopeFilter: ScopeAuthorizationFilter
    private val mockRequestContext = mock<ContainerRequestContext>()
    private val mockResourceInfo = mock<ResourceInfo>()
    private val mockMethod = mock<Method>()
    private val algorithm = Algorithm.HMAC256("test-secret-key-that-is-long-enough-for-hmac256-algorithm")

    @BeforeEach
    fun setup() {
        scopeFilter = ScopeAuthorizationFilter()
        val resourceInfoField = ScopeAuthorizationFilter::class.java.getDeclaredField("resourceInfo")
        resourceInfoField.isAccessible = true
        resourceInfoField.set(scopeFilter, mockResourceInfo)

        whenever(mockResourceInfo.resourceMethod).thenReturn(mockMethod)
    }

    @Test
    fun `should pass when no RequireScope annotation is present`() {
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(null)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithoutAnnotation::class.java)

        scopeFilter.filter(mockRequestContext)
        // No exception = pass
    }

    @Test
    fun `should bypass scope check for user token without clientId`() {
        setupRequireScope("payment:read")
        setupAuthHeader(createUserToken())

        scopeFilter.filter(mockRequestContext)
        // No exception = bypass
    }

    @Test
    fun `should pass when API key token has required scope`() {
        setupRequireScope("payment:read")
        setupAuthHeader(createApiKeyToken("client-123", listOf("payment:read", "payment:write")))

        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should throw ForbiddenException when API key token lacks required scope`() {
        setupRequireScope("payment:write")
        setupAuthHeader(createApiKeyToken("client-123", listOf("payment:read")))

        val ex = assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
        ex.message shouldContain "Missing required scope"
    }

    @Test
    fun `should throw ForbiddenException when scopeOnlyAuthorization and no clientId`() {
        setupRequireScope("service.payment.reporting:read", scopeOnlyAuthorization = true)
        setupAuthHeader(createUserToken())

        val ex = assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
        ex.message shouldContain "only accessible with API Key"
    }

    @Test
    fun `should pass when scopeOnlyAuthorization and API key has scope`() {
        setupRequireScope("service.payment.reporting:read", scopeOnlyAuthorization = true)
        setupAuthHeader(createApiKeyToken("client-456", listOf("service.payment.reporting:read")))

        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should throw UnauthorizedException when no auth header`() {
        setupRequireScope("payment:read")
        whenever(mockRequestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null)

        assertThrows<UnauthorizedException> { scopeFilter.filter(mockRequestContext) }
    }

    @Test
    fun `should throw UnauthorizedException when invalid auth header format`() {
        setupRequireScope("payment:read")
        whenever(mockRequestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Basic abc123")

        assertThrows<UnauthorizedException> { scopeFilter.filter(mockRequestContext) }
    }

    @Test
    fun `should pass when token has empty scopes and no clientId`() {
        setupRequireScope("payment:read")
        setupAuthHeader(createUserToken())

        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should throw when API key token has empty scopes`() {
        setupRequireScope("payment:read")
        setupAuthHeader(createApiKeyToken("client-789", emptyList()))

        assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
    }

    // --- Helper methods ---

    private fun setupRequireScope(scope: String, scopeOnlyAuthorization: Boolean = false) {
        val annotation = mock<RequireScope>()
        whenever(annotation.value).thenReturn(scope)
        whenever(annotation.scopeOnlyAuthorization).thenReturn(scopeOnlyAuthorization)
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(annotation)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithoutAnnotation::class.java)
    }

    private fun setupAuthHeader(token: String) {
        whenever(mockRequestContext.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer $token")
    }

    private fun createUserToken(): String {
        return JWT.create()
            .withSubject(UUID.randomUUID().toString())
            .withClaim("role", "backoffice.admin")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)
    }

    private fun createApiKeyToken(clientId: String, scopes: List<String>): String {
        return JWT.create()
            .withSubject(clientId)
            .withClaim("role", "partner.admin")
            .withClaim("clientId", clientId)
            .withClaim("scopes", scopes)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)
    }

    // Test resource classes for annotation testing
    class TestResourceWithoutAnnotation
}
