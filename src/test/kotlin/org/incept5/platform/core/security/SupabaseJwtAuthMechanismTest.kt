
package org.incept5.platform.core.security

import io.quarkus.security.identity.IdentityProviderManager
import io.quarkus.security.runtime.QuarkusSecurityIdentity
import io.smallrye.mutiny.Uni
import io.vertx.core.http.HttpServerRequest
import io.vertx.ext.web.RoutingContext
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.kotlin.*
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import org.junit.jupiter.api.assertThrows

class SupabaseJwtAuthMechanismTest {

    private lateinit var authMechanism: SupabaseJwtAuthMechanism
    private val mockJwtValidator = mock<DualJwtValidator>()
    private val mockRoutingContext = mock<RoutingContext>()
    private val mockHttpRequest = mock<HttpServerRequest>()
    private val mockIdentityProviderManager = mock<IdentityProviderManager>()

    @BeforeEach
    fun setup() {
        authMechanism = SupabaseJwtAuthMechanism(mockJwtValidator)
        
        whenever(mockRoutingContext.request()).thenReturn(mockHttpRequest)
    }

    @Test
    fun `should skip authentication for health checks`() {
        // Given
        whenever(mockHttpRequest.path()).thenReturn("/health/ready")

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockJwtValidator, never()).validateToken(any())
    }

    @Test
    fun `should return null when no Authorization header present`() {
        // Given
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn(null)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockJwtValidator, never()).validateToken(any())
    }

    @Test
    fun `should return null when Authorization header does not start with Bearer`() {
        // Given
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz")

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockJwtValidator, never()).validateToken(any())
    }

    @Test
    fun `should authenticate valid user token`() {
        // Given
        val token = "valid.jwt.token"
        val validationResult = TokenValidationResult.valid(
            subject = "user123",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-123",
            scopes = listOf("payment:read"),
            clientId = "client-456",
            tokenSource = TokenSource.SUPABASE
        )

        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null
        identity.shouldBeInstanceOf<QuarkusSecurityIdentity>()

        val principal = identity.principal
        principal.shouldBeInstanceOf<ApiPrincipal>()
        principal.subject shouldBe "user123"
        principal.userRole shouldBe UserRole.entity_user
        principal.entityType shouldBe EntityType.partner
        principal.entityId shouldBe "partner-123"
        principal.clientId shouldBe "client-456"

        identity.hasRole(UserRole.entity_user.name) shouldBe true
        verify(mockJwtValidator).validateToken(token)
    }

    @Test
    fun `should authenticate service role token and map to platform admin`() {
        // Given
        val token = "service.role.token"
        val validationResult = TokenValidationResult.valid(
            subject = "service-role-user",
            userRole = UserRole.service_role,
            entityType = null,
            entityId = null,
            scopes = emptyList(),
            clientId = null,
            tokenSource = TokenSource.SUPABASE
        )

        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null

        val principal = identity.principal
        principal.shouldBeInstanceOf<ApiPrincipal>()
        principal.subject shouldBe "service-role-user"
        principal.userRole shouldBe UserRole.service_role
        principal.entityType shouldBe null
        principal.entityId shouldBe null

        identity.hasRole(UserRole.service_role.name) shouldBe true
        verify(mockJwtValidator).validateToken(token)
    }

    @Test
    fun `should authenticate platform admin token`() {
        // Given
        val token = "platform.admin.token"
        val validationResult = TokenValidationResult.valid(
            subject = "admin123",
            userRole = UserRole.platform_admin,
            entityType = null,
            entityId = null,
            scopes = listOf("payment:manage", "partner:manage"),
            clientId = null,
            tokenSource = TokenSource.PLATFORM
        )

        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null

        val principal = identity.principal
        principal.shouldBeInstanceOf<ApiPrincipal>()
        principal.subject shouldBe "admin123"
        principal.userRole shouldBe UserRole.platform_admin
        principal.entityType shouldBe null
        principal.entityId shouldBe null

        identity.hasRole(UserRole.platform_admin.name) shouldBe true
    }

    @Test
    fun `should authenticate entity admin token`() {
        // Given
        val token = "entity.admin.token"
        val validationResult = TokenValidationResult.valid(
            subject = "entity-admin-456",
            userRole = UserRole.entity_admin,
            entityType = EntityType.merchant,
            entityId = "merchant-789",
            scopes = listOf("payment:create", "merchant:manage"),
            clientId = null,
            tokenSource = TokenSource.SUPABASE
        )

        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null

        val principal = identity.principal
        principal.shouldBeInstanceOf<ApiPrincipal>()
        principal.subject shouldBe "entity-admin-456"
        principal.userRole shouldBe UserRole.entity_admin
        principal.entityType shouldBe EntityType.merchant
        principal.entityId shouldBe "merchant-789"

        identity.hasRole(UserRole.entity_admin.name) shouldBe true
    }

    @Test
    fun `should handle case insensitive Bearer token`() {
        // Given
        val token = "valid.jwt.token"
        val validationResult = TokenValidationResult.valid(
            subject = "user123",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-123",
            scopes = listOf("payment:read"),
            clientId = null,
            tokenSource = TokenSource.SUPABASE
        )

        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenReturn(validationResult)

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        val identity = result.await().indefinitely()
        identity shouldNotBe null
        verify(mockJwtValidator).validateToken(token)
    }

    @Test
    fun `should return null when token validation fails`() {
        // Given
        val token = "invalid.jwt.token"
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenThrow(UnknownTokenException("Invalid token"))

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockJwtValidator).validateToken(token)
    }

    @Test
    fun `should return null when unexpected exception occurs`() {
        // Given
        val token = "problematic.jwt.token"
        whenever(mockHttpRequest.path()).thenReturn("/api/v1/test")
        whenever(mockHttpRequest.getHeader("Authorization")).thenReturn("Bearer $token")
        whenever(mockJwtValidator.validateToken(token)).thenThrow(RuntimeException("Unexpected error"))

        // When
        val result = authMechanism.authenticate(mockRoutingContext, mockIdentityProviderManager)

        // Then
        result.await().indefinitely() shouldBe null
        verify(mockJwtValidator).validateToken(token)
    }

    @Test
    fun `should provide correct challenge data`() {
        // When
        val result = authMechanism.getChallenge(mockRoutingContext)

        // Then
        val challengeData = result.await().indefinitely()
        challengeData.status shouldBe 401
        challengeData.headerName shouldBe "WWW-Authenticate"
        challengeData.headerContent shouldBe "Bearer realm=\"Supabase\", charset=\"UTF-8\""
    }

    @Test
    fun `should return empty credential types`() {
        // When
        val credentialTypes = authMechanism.credentialTypes

        // Then
        credentialTypes.isEmpty() shouldBe true
    }

    @Test
    fun `SupabaseSecurityContext should work correctly`() {
        // Given
        val principal = ApiPrincipal(
            subject = "test-user",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )
        val securityContext = SupabaseSecurityContext(principal)

        // When/Then
        securityContext.userPrincipal shouldBe principal
        securityContext.isUserInRole(UserRole.entity_admin.name) shouldBe true
        securityContext.isUserInRole(UserRole.platform_admin.name) shouldBe false
        securityContext.isSecure shouldBe true
        securityContext.authenticationScheme shouldBe "Bearer"
    }
}
