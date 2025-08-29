
package org.incept5.platform.core.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.SecurityContext
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.security.ApiPrincipal
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.lang.reflect.Method
import java.time.Instant
import java.util.*

class ScopeAuthorizationFilterTest {

    private lateinit var scopeFilter: ScopeAuthorizationFilter
    private val mockRequestContext = mock<ContainerRequestContext>()
    private val mockResourceInfo = mock<ResourceInfo>()
    private val mockSecurityContext = mock<SecurityContext>()
    private val mockMethod = mock<Method>()
    private val algorithm = Algorithm.HMAC256("test-secret-key-that-is-long-enough-for-hmac256-algorithm")

    @BeforeEach
    fun setup() {
        scopeFilter = ScopeAuthorizationFilter()
        // Set the ResourceInfo using reflection since it's injected via @Context
        val resourceInfoField = ScopeAuthorizationFilter::class.java.getDeclaredField("resourceInfo")
        resourceInfoField.isAccessible = true
        resourceInfoField.set(scopeFilter, mockResourceInfo)

        whenever(mockRequestContext.securityContext).thenReturn(mockSecurityContext)
        whenever(mockResourceInfo.resourceMethod).thenReturn(mockMethod)
        // Resource class will be set per test as needed
    }

    @Test
    fun `should pass when no RequireScope annotation is present`() {
        // Given
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(null)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithoutAnnotation::class.java)

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
        
        // Verify no interaction with security context
        verify(mockSecurityContext, never()).userPrincipal
    }

    @Test
    fun `should throw NotAuthorizedException when no principal present`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(null)

        // When/Then
        assertThrows<NotAuthorizedException> {
            scopeFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should bypass scope check for user tokens without client ID`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = null)
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
        
        // Should not check Authorization header when bypassing
        verify(mockRequestContext, never()).getHeaderString(any())
    }

    @Test
    fun `should pass when token has required scope`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-123")
        val token = createJwtToken(scopes = listOf("payment:read", "payment:create"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should throw ApiException when token lacks required scope`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:manage")
        val principal = createApiPrincipal(clientId = "client-123")
        val token = createJwtToken(scopes = listOf("payment:read", "payment:create"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then
        val exception = assertThrows<ApiException> {
            scopeFilter.filter(mockRequestContext)
        }
        exception.message shouldContain "higher privileges"
    }

    @Test
    fun `should pass when token has multiple scopes including required one`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("partner:manage")
        val principal = createApiPrincipal(clientId = "client-456")
        val token = createJwtToken(scopes = listOf("payment:read", "partner:manage", "merchant:read"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should handle token with no scopes claim`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-789")
        val token = createJwtToken(scopes = null) // No scopes claim
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then
        val exception = assertThrows<ApiException> {
            scopeFilter.filter(mockRequestContext)
        }
        exception.message shouldContain "higher privileges"
    }

    @Test
    fun `should handle token with empty scopes array`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-empty")
        val token = createJwtToken(scopes = emptyList())
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then
        val exception = assertThrows<ApiException> {
            scopeFilter.filter(mockRequestContext)
        }
        exception.message shouldContain "higher privileges"
    }

    @Test
    fun `should throw ForbiddenException when no Authorization header present`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-123")
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn(null)

        // When/Then
        assertThrows<ForbiddenException> {
            scopeFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should throw ForbiddenException when Authorization header has wrong format`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-123")
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Basic dXNlcjpwYXNz")

        // When/Then
        assertThrows<ForbiddenException> {
            scopeFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should throw ForbiddenException when token is malformed`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-123")
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer malformed.token")

        // When/Then
        assertThrows<ForbiddenException> {
            scopeFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should handle case insensitive Bearer token`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read")
        val principal = createApiPrincipal(clientId = "client-123")
        val token = createJwtToken(scopes = listOf("payment:read"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("bearer $token")

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should use class-level annotation when method-level annotation not present`() {
        // Given
        val principal = createApiPrincipal(clientId = "client-class")
        val token = createJwtToken(scopes = listOf("merchant:read"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(null)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithAnnotation::class.java)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
    }

    @Test
    fun `should throw ApiException when scopeOnlyAuthorization is true and clientId is null`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read", scopeOnlyAuthorization = true)
        val principal = createApiPrincipal(clientId = null)
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ApiException> {
            scopeFilter.filter(mockRequestContext)
        }
        exception.message shouldContain "not allowed access"
        exception.message shouldContain "Use tokens issues by a valid API Key"
    }

    @Test
    fun `should throw ApiException when scopeOnlyAuthorization is true and clientId is empty`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read", scopeOnlyAuthorization = true)
        val principal = createApiPrincipal(clientId = "")
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ApiException> {
            scopeFilter.filter(mockRequestContext)
        }
        exception.message shouldContain "not allowed access"
    }

    @Test
    fun `should pass when scopeOnlyAuthorization is true and clientId is present with valid scope`() {
        // Given
        val requireScopeAnnotation = createRequireScopeAnnotation("payment:read", scopeOnlyAuthorization = true)
        val principal = createApiPrincipal(clientId = "api-key-client")
        val token = createJwtToken(scopes = listOf("payment:read", "payment:create"))
        
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(requireScopeAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.getHeaderString("Authorization")).thenReturn("Bearer $token")

        // When/Then - Should not throw any exception
        scopeFilter.filter(mockRequestContext)
    }

    // Helper methods

    private fun createRequireScopeAnnotation(
        value: String,
        scopeOnlyAuthorization: Boolean = false
    ): RequireScope {
        val mockAnnotation = mock<RequireScope>()
        whenever(mockAnnotation.value).thenReturn(value)
        whenever(mockAnnotation.scopeOnlyAuthorization).thenReturn(scopeOnlyAuthorization)
        return mockAnnotation
    }

    private fun createApiPrincipal(
        clientId: String? = null
    ): ApiPrincipal {
        return ApiPrincipal(
            subject = "test-user-123",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-123",
            clientId = clientId
        )
    }

    private fun createJwtToken(scopes: List<String>?): String {
        val tokenBuilder = JWT.create()
            .withSubject("test-subject")
            .withIssuer("test-issuer")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))

        // Add scopes claim only if provided (null means no scopes claim at all)
        scopes?.let { tokenBuilder.withClaim("scopes", it) }

        return tokenBuilder.sign(algorithm)
    }
}

// Test resource classes for annotation testing
class TestResourceWithoutAnnotation

@RequireScope("merchant:read")
class TestResourceWithAnnotation
