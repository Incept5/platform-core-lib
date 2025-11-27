
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.*
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey

class DualJwtValidatorTest {

    private lateinit var dualJwtValidator: DualJwtValidator
    private val jwtSecretBytes = "test-secret-key-that-is-long-enough-for-hmac256-algorithm".toByteArray()
    private val jwtSecret = Base64.getEncoder().encodeToString(jwtSecretBytes)
    private val baseApiUrl = "https://api.test.com"
    private val supabaseAuthPath = "/auth/v1"
    private val platformOauthPath = "/api/v1/oauth/token"
    private val algorithm = Algorithm.HMAC256(jwtSecretBytes)

    @BeforeEach
    fun setup() {
        dualJwtValidator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath
        )
    }

    // Supabase Token Tests

    @Test
    fun `should validate valid Supabase user token`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "user123"
        result.userRole shouldBe UserRole.entity_user
        result.entityType shouldBe EntityType.partner
        result.entityId shouldBe "partner-123"
        result.scopes shouldBe listOf("payment:create", "payment:read")
        result.clientId shouldBe null
    }

    @Test
    fun `should validate Supabase service role token and map to platform admin`() {
        // Given
        val token = createSupabaseServiceRoleToken()

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.platform_admin
        result.entityType shouldBe null
        result.entityId shouldBe null
        result.scopes shouldBe listOf(
            "payment:create", "payment:read", "payment:manage",
            "partner:create", "partner:read", "partner:manage",
            "merchant:create", "merchant:read", "merchant:manage"
        )
    }

    @Test
    fun `should validate Supabase entity admin token with correct scopes`() {
        // Given
        val token = createSupabaseToken(
            subject = "admin123",
            role = UserRole.entity_admin,
            entityType = EntityType.merchant,
            entityId = "merchant-456"
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.entity_admin
        result.entityType shouldBe EntityType.merchant
        result.scopes shouldBe listOf(
            "payment:create", "payment:read", "merchant:manage"
        )
    }

    @Test
    fun `should validate Supabase platform admin token`() {
        // Given
        val token = createSupabaseToken(
            subject = "platform-admin-123",
            role = UserRole.platform_admin,
            entityType = null,
            entityId = null
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.platform_admin
        result.scopes shouldBe listOf(
            "payment:create", "payment:read", "payment:manage",
            "partner:create", "partner:read", "partner:manage",
            "merchant:create", "merchant:read", "merchant:manage"
        )
    }

    // Platform Token Tests

    @Test
    fun `should validate valid Platform token`() {
        // Given
        val token = createPlatformToken(
            subject = "client-123",
            role = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "partner-789",
            scopes = listOf("payment:read", "partner:manage")
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-123"
        result.userRole shouldBe UserRole.entity_admin
        result.entityType shouldBe EntityType.partner
        result.entityId shouldBe "partner-789"
        result.scopes shouldBe listOf("payment:read", "partner:manage")
        result.clientId shouldBe "client-123"
    }

    @Test
    fun `should validate Platform token with minimal claims`() {
        // Given
        val token = createPlatformToken(
            subject = "client-minimal",
            role = UserRole.entity_readonly,
            entityType = null,
            entityId = null,
            scopes = emptyList()
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-minimal"
        result.userRole shouldBe UserRole.entity_readonly
        result.entityType shouldBe null
        result.entityId shouldBe null
        result.scopes shouldBe emptyList()
        result.clientId shouldBe "client-minimal"
    }

    // Error Cases

    @Test
    fun `should throw UnknownTokenException for invalid token format`() {
        // Given
        val invalidToken = "invalid.token.format"

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(invalidToken)
        }
        exception.message shouldBe "Invalid token format"
    }

    @Test
    fun `should throw UnknownTokenException for unknown issuer`() {
        // Given
        val token = JWT.create()
            .withSubject("test-user")
            .withIssuer("https://unknown-issuer.com")
            .withClaim("role", UserRole.entity_user.name)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(token)
        }
        exception.message?.contains("Unknown token issuer") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for Supabase token without subject`() {
        // Given
        val token = JWT.create()
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", UserRole.entity_user.name)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(token)
        }
        exception.message?.contains("Invalid Supabase token") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for Supabase token without role`() {
        // Given
        val token = JWT.create()
            .withSubject("test-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(token)
        }
        exception.message?.contains("Invalid Supabase token") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for Platform token without subject`() {
        // Given
        val token = JWT.create()
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", UserRole.entity_user.name)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(token)
        }
        exception.message?.contains("Invalid Platform token") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for expired token`() {
        // Given
        val expiredToken = JWT.create()
            .withSubject("test-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", UserRole.entity_user.name)
            .withExpiresAt(Date.from(Instant.now().minusSeconds(3600))) // Expired 1 hour ago
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(expiredToken)
        }
        exception.message?.contains("Invalid Supabase token") shouldBe true
    }

    // Utility Methods Tests

    @Test
    fun `getEntityType should return correct entity type`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = UserRole.entity_user,
            entityType = EntityType.merchant,
            entityId = "merchant-123"
        )

        // When
        val entityType = dualJwtValidator.getEntityType(token)

        // Then
        entityType shouldBe EntityType.merchant
    }

    @Test
    fun `getEntityId should return correct entity ID`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = "partner-456"
        )

        // When
        val entityId = dualJwtValidator.getEntityId(token)

        // Then
        entityId shouldBe "partner-456"
    }

    @Test
    fun `getEntityType should return null for token without entity type`() {
        // Given
        val token = createPlatformToken(
            subject = "client-123",
            role = UserRole.platform_admin,
            entityType = null,
            entityId = null,
            scopes = emptyList()
        )

        // When
        val entityType = dualJwtValidator.getEntityType(token)

        // Then
        entityType shouldBe null
    }

    // Test Helper Methods

    private fun createSupabaseToken(
        subject: String,
        role: UserRole,
        entityType: EntityType?,
        entityId: String?
    ): String {
        val tokenBuilder = JWT.create()
            .withSubject(subject)
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", role.name)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it.name }
            entityId?.let { appMetadata["entity_id"] = it }
            tokenBuilder.withClaim("app_metadata", appMetadata)
        }

        return tokenBuilder.sign(algorithm)
    }

    private fun createSupabaseServiceRoleToken(): String {
        return JWT.create()
            .withSubject("service-role-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", UserRole.service_role.name)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)
    }

    private fun createPlatformToken(
        subject: String,
        role: UserRole,
        entityType: EntityType?,
        entityId: String?,
        scopes: List<String>
    ): String {
        val tokenBuilder = JWT.create()
            .withSubject(subject)
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", role.name)
            .withClaim("scopes", scopes)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it.name }
            entityId?.let { appMetadata["entity_id"] = it }
            tokenBuilder.withClaim("app_metadata", appMetadata)
        }

        return tokenBuilder.sign(algorithm)
    }

    @Test
    fun `should validate RS256 Platform token when RSA enabled`() {
        // Given RSA key pair
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val privateKey = kp.private as RSAPrivateKey
        val privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.encoded)

        // Validator configured for RSA verification
        val rsaValidator = DualJwtValidator(
            jwtSecret = jwtSecret,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            baseApiUrl = baseApiUrl,
            rsaEnabled = true,
            rsaPrivateKey = privateKeyBase64,
            supabaseJwtEnabled = false
        )

        // RS256-signed platform token
        val token = JWT.create()
            .withSubject("client-rs256")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", UserRole.entity_admin.name)
            .withClaim("scopes", listOf("payment:read"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(Algorithm.RSA256(null, privateKey))

        // When
        val result = rsaValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-rs256"
        result.userRole shouldBe UserRole.entity_admin
        result.clientId shouldBe "client-rs256"
    }
}
