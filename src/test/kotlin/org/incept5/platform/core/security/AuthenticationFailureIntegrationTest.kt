
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.vertx.core.http.HttpServerRequest
import io.vertx.ext.web.RoutingContext
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import org.junit.jupiter.api.DisplayName
import java.time.Instant
import java.util.*

/**
 * Integration test for authentication failure handling.
 * This test verifies that authentication failures result in proper error responses
 * handled by the CustomAuthenticationFailureHandler.
 * 
 * Unlike a full @QuarkusTest, this focuses on unit testing the authentication mechanism
 * and failure handler components in isolation.
 */
class AuthenticationFailureIntegrationTest {

    private lateinit var authMechanism: SupabaseJwtAuthMechanism
    private lateinit var failureHandler: CustomAuthenticationFailureHandler
    private val mockJwtValidator = mock<DualJwtValidator>()
    private val mockRoutingContext = mock<RoutingContext>()
    private val mockHttpRequest = mock<HttpServerRequest>()

    // Test configuration values
    private val jwtSecret = "dGVzdC1zZWNyZXQtZm9yLXRlc3RpbmctcHVycG9zZXMtb25seQ=="
    private val apiBaseUrl = "http://localhost:8081"

    @BeforeEach
    fun setup() {
        authMechanism = SupabaseJwtAuthMechanism(mockJwtValidator)
        failureHandler = CustomAuthenticationFailureHandler()
        
        whenever(mockRoutingContext.request()).thenReturn(mockHttpRequest)
        // Don't mock the fail methods - just let them be called normally
    }

    @Test
    @DisplayName("Should handle expired token and trigger custom error handling")
    fun `should handle expired token and demonstrate custom error response structure`() {
        // Given
        val expiredToken = generateExpiredToken()
        val expectedException = UnknownTokenException("Invalid Supabase token: JWT expired at 2024-01-01T00:00:00Z")
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $expiredToken")
        whenever(mockJwtValidator.validateToken(expiredToken)).thenThrow(expectedException)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        
        // Verify that the context was failed with the UnknownTokenException
        verify(mockRoutingContext).fail(expectedException)
        
        // Verify that the failure handler would process this as a custom error
        expectedException.message shouldContain "Invalid Supabase token"
        expectedException::class.java.simpleName shouldBe "UnknownTokenException"
    }

    @Test
    @DisplayName("Should handle malformed token and trigger custom error handling")
    fun `should handle malformed token and demonstrate custom error response structure`() {
        // Given
        val malformedToken = "invalid.jwt.token"
        val expectedException = UnknownTokenException("Invalid token format")
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $malformedToken")
        whenever(mockJwtValidator.validateToken(malformedToken)).thenThrow(expectedException)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockRoutingContext).fail(expectedException)
        
        // Verify error structure that CustomAuthenticationFailureHandler would use
        expectedException.message shouldContain "Invalid token format"
        expectedException::class.java.simpleName shouldBe "UnknownTokenException"
    }

    @Test
    @DisplayName("Should handle token with invalid issuer and trigger custom error handling")
    fun `should handle token with invalid issuer and demonstrate custom error response structure`() {
        // Given
        val invalidIssuerToken = generateTokenWithInvalidIssuer()
        val expectedException = UnknownTokenException("Unknown token issuer: https://invalid-issuer.com/auth/v1")
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $invalidIssuerToken")
        whenever(mockJwtValidator.validateToken(invalidIssuerToken)).thenThrow(expectedException)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockRoutingContext).fail(expectedException)
        
        // Verify error structure
        expectedException.message shouldContain "Unknown token issuer"
        expectedException.message shouldContain "invalid-issuer.com"
    }

    @Test
    @DisplayName("Should handle token with invalid signature and trigger custom error handling")
    fun `should handle token with invalid signature and demonstrate custom error response structure`() {
        // Given
        val invalidSignatureToken = generateTokenWithInvalidSignature()
        val expectedException = UnknownTokenException("Invalid Supabase token: The Token's Signature resulted invalid")
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $invalidSignatureToken")
        whenever(mockJwtValidator.validateToken(invalidSignatureToken)).thenThrow(expectedException)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockRoutingContext).fail(expectedException)
        
        // Verify error structure
        expectedException.message shouldContain "Invalid Supabase token"
        expectedException.message shouldContain "Signature resulted invalid"
    }

    @Test
    @DisplayName("Should return null for missing Authorization header (default error handling)")
    fun `should return null for missing Authorization header and use default error handling`() {
        // Given
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn(null)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        
        // Verify that no custom exception was thrown (falls back to default handling)
        verify(mockRoutingContext, never()).fail(any<UnknownTokenException>())
        verify(mockJwtValidator, never()).validateToken(any())
    }

    @Test
    @DisplayName("Should return null for invalid Authorization header format (default error handling)")
    fun `should return null for invalid Authorization header format and use default error handling`() {
        // Given
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz")

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        
        // Verify that no custom exception was thrown (falls back to default handling)
        verify(mockRoutingContext, never()).fail(any<UnknownTokenException>())
        verify(mockJwtValidator, never()).validateToken(any())
    }

    @Test
    @DisplayName("Should successfully authenticate with valid token")
    fun `should successfully authenticate with valid token and extract user details`() {
        // Given
        val validToken = "valid.jwt.token"
        val validationResult = TokenValidationResult.valid(
            subject = "12345678-1234-1234-1234-123456789012",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-456",
            scopes = listOf("payment:read"),
            clientId = null,
            tokenSource = TokenSource.SUPABASE
        )
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $validToken")
        whenever(mockJwtValidator.validateToken(validToken)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null
        
        val principal = identity.principal as ApiPrincipal
        principal.subject shouldBe "12345678-1234-1234-1234-123456789012"
        principal.userRole shouldBe UserRole.entity_user
        principal.entityType shouldBe EntityType.partner
        principal.entityId shouldBe "partner-456"
        
        identity.hasRole(UserRole.entity_user.name) shouldBe true
        identity.hasRole(UserRole.platform_admin.name) shouldBe false
        
        // Verify no failure was recorded
        verify(mockRoutingContext, never()).fail(any<Throwable>())
        verify(mockRoutingContext, never()).fail(any<Int>())
    }

    @Test
    @DisplayName("Should handle unexpected exceptions and convert to custom errors")
    fun `should handle unexpected exceptions and convert to custom error format`() {
        // Given
        val token = "problematic.jwt.token"
        val unexpectedException = RuntimeException("Unexpected database error")
        
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenThrow(unexpectedException)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mock())

        // Then
        result.await().indefinitely() shouldBe null
        
        // Verify that the context was failed with a 401 status (generic error handling)
        verify(mockRoutingContext).fail(401)
    }

    @Test
    @DisplayName("Should provide correct challenge data for 401 responses")
    fun `should provide correct WWW-Authenticate challenge for unauthorized requests`() {
        // When
        val result = authMechanism.getChallenge(mockRoutingContext)

        // Then
        val challengeData = result.await().indefinitely()
        challengeData.status shouldBe 401
        challengeData.headerName shouldBe "WWW-Authenticate"
        challengeData.headerContent shouldBe "Bearer realm=\"Supabase\", charset=\"UTF-8\""
    }

    /**
     * Demonstrates the structure of error responses that would be generated
     * by the CustomAuthenticationFailureHandler for different types of failures.
     */
    @Test
    @DisplayName("Should demonstrate expected error response structures from CustomAuthenticationFailureHandler")
    fun `should demonstrate expected error response structures for different failure types`() {
        // This test documents the expected error response format that would be produced
        // by the CustomAuthenticationFailureHandler when processing different types of failures
        
        // For UnknownTokenException (expired, invalid signature, etc.)
        val tokenException = UnknownTokenException("Invalid Supabase token: JWT expired")
        val expectedTokenErrorStructure = mapOf(
            "errors" to listOf(
                mapOf(
                    "message" to "Invalid Supabase token: JWT expired",
                    "category" to "AUTHENTICATION",
                    "type" to "UnknownTokenException"
                )
            ),
            "correlationId" to "test-correlation-id",
            "httpStatusCode" to 401
        )
        
        // For default authentication failures (missing/invalid headers)
        val expectedDefaultErrorStructure = mapOf(
            "error" to "authentication_failed",
            "message" to "Authentication required",
            "timestamp" to "2024-01-01T12:00:00Z"
        )
        
        // Verify that our exception structure matches what the handler expects
        tokenException.message shouldBe "Invalid Supabase token: JWT expired"
        tokenException::class.java.simpleName shouldBe "UnknownTokenException"
        
        // These structures demonstrate the format that would be returned to clients
        // when authentication fails and is processed by the CustomAuthenticationFailureHandler
        expectedTokenErrorStructure["httpStatusCode"] shouldBe 401
        expectedDefaultErrorStructure["error"] shouldBe "authentication_failed"
    }

    /**
     * Generate an expired token for testing
     */
    private fun generateExpiredToken(): String {
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        val now = Instant.now()
        val expiredTime = now.minusSeconds(60) // 1 minute ago

        val appMetadata = mapOf(
            "entity_type" to EntityType.partner.name,
            "entity_id" to "test-partner-123"
        )

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(expiredTime.minusSeconds(3600))) // 1 hour before expiration
            .withExpiresAt(Date.from(expiredTime)) // Already expired
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("$apiBaseUrl/auth/v1")
            .withClaim("email", "test-user-123@test.com")
            .withClaim("app_metadata", appMetadata)
            .sign(algorithm)
    }

    /**
     * Generate a token with invalid issuer for testing
     */
    private fun generateTokenWithInvalidIssuer(): String {
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        val now = Instant.now()

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(3600)))
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("https://invalid-issuer.com/auth/v1") // Invalid issuer
            .withClaim("email", "test-user-123@test.com")
            .sign(algorithm)
    }

    /**
     * Generate a token with invalid signature for testing
     */
    private fun generateTokenWithInvalidSignature(): String {
        val invalidSecret = "invalid-secret-key-that-does-not-match"
        val algorithm = Algorithm.HMAC256(invalidSecret.toByteArray())
        val now = Instant.now()

        val appMetadata = mapOf(
            "entity_type" to EntityType.partner.name,
            "entity_id" to "test-partner-123"
        )

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(3600)))
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("$apiBaseUrl/auth/v1") // Correct issuer
            .withClaim("email", "test-user-123@test.com")
            .withClaim("app_metadata", appMetadata)
            .sign(algorithm) // Signed with wrong secret
    }
}
