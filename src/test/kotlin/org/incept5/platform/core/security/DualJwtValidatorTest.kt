
package org.incept5.platform.core.security
import org.incept5.authz.core.context.AssuranceLevel
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
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
            platformOauthPath = platformOauthPath,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty()
        )
    }

    // Supabase Token Tests

    @Test
    fun `should validate valid Supabase user token`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = "entity_user",
            entityType = "partner",
            entityId = "partner-123"
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "user123"
        result.userRole shouldBe UserRole.of("entity_user")
        result.entityType shouldBe EntityType.PARTNER
        result.entityId shouldBe "partner-123"
        result.scopes shouldBe emptyList()
        result.clientId shouldBe null
    }

    @Test
    fun `should validate Supabase service role token and map to service admin`() {
        // Given
        val token = createSupabaseServiceRoleToken()

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.of("service_role")
        result.entityType shouldBe null
        result.entityId shouldBe null
        result.scopes shouldBe emptyList()
        // FF-3799 (AC8): the service_role key is a service-to-service credential -> machine
        // principal, so MFA enforcement never applies to it whatever roles it resolves to.
        result.machinePrincipal shouldBe true
    }

    @Test
    fun `a normal Supabase user token is not a machine principal`() {
        val token = createSupabaseToken(
            subject = "user-123",
            role = "platform_admin",
            entityType = null,
            entityId = null,
            aal = "aal2",
        )

        val result = dualJwtValidator.validateToken(token)

        result.machinePrincipal shouldBe false
    }

    @Test
    fun `should validate Supabase entity admin token`() {
        // Given
        val token = createSupabaseToken(
            subject = "admin123",
            role = "entity_admin",
            entityType = "merchant",
            entityId = "merchant-456"
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.of("entity_admin")
        result.entityType shouldBe EntityType.MERCHANT
        result.scopes shouldBe emptyList()
    }

    @Test
    fun `should validate Supabase platform admin token`() {
        // Given
        val token = createSupabaseToken(
            subject = "platform-admin-123",
            role = "platform_admin",
            entityType = null,
            entityId = null
        )

        // When
        val result = dualJwtValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.userRole shouldBe UserRole.of("platform_admin")
        result.scopes shouldBe emptyList()
    }

    // AAL claim -> provider-neutral assurance level mapping — FF-3798 (H5)

    @Test
    fun `maps aal2 to MULTI_FACTOR for a verified Supabase token`() {
        val token = createSupabaseToken(
            subject = "admin-aal2",
            role = "platform_admin",
            entityType = null,
            entityId = null,
            aal = "aal2"
        )

        val result = dualJwtValidator.validateToken(token)

        result.assuranceLevel shouldBe AssuranceLevel.MULTI_FACTOR
        result.machinePrincipal shouldBe false
    }

    @Test
    fun `maps aal1 to SINGLE_FACTOR for a single-factor Supabase token`() {
        val token = createSupabaseToken(
            subject = "admin-aal1",
            role = "platform_admin",
            entityType = null,
            entityId = null,
            aal = "aal1"
        )

        val result = dualJwtValidator.validateToken(token)

        result.assuranceLevel shouldBe AssuranceLevel.SINGLE_FACTOR
        result.machinePrincipal shouldBe false
    }

    @Test
    fun `treats a Supabase token with no aal claim as SINGLE_FACTOR`() {
        val token = createSupabaseToken(
            subject = "admin-no-aal",
            role = "platform_admin",
            entityType = null,
            entityId = null
        )

        val result = dualJwtValidator.validateToken(token)

        result.assuranceLevel shouldBe AssuranceLevel.SINGLE_FACTOR
        result.machinePrincipal shouldBe false
    }

    @Test
    fun `treats an unrecognised aal value as SINGLE_FACTOR (fail closed)`() {
        val token = createSupabaseToken(
            subject = "admin-weird-aal",
            role = "platform_admin",
            entityType = null,
            entityId = null,
            aal = "aal3"
        )

        val result = dualJwtValidator.validateToken(token)

        // Only the literal "aal2" is multi-factor; anything unrecognised (a future GoTrue level, a
        // typo, an attacker's guess) fails closed to single-factor rather than being trusted.
        result.assuranceLevel shouldBe AssuranceLevel.SINGLE_FACTOR
        result.machinePrincipal shouldBe false
    }

    @Test
    fun `platform token is a machine principal`() {
        val token = createPlatformToken(
            subject = "client-123",
            role = "entity_admin",
            entityType = "partner",
            entityId = "partner-789",
            scopes = listOf("payment:read")
        )
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )

        val result = validator.validateToken(token)

        result.machinePrincipal shouldBe true
        result.assuranceLevel shouldBe AssuranceLevel.SINGLE_FACTOR
    }

    // Platform Token Tests

    @Test
    fun `should validate valid Platform token`() {
        // Given
        val token = createPlatformToken(
            subject = "client-123",
            role = "entity_admin",
            entityType = "partner",
            entityId = "partner-789",
            scopes = listOf("payment:read", "partner:manage")
        )

        // When
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )
        val result = validator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-123"
        result.userRole shouldBe UserRole.of("entity_admin")
        result.entityType shouldBe EntityType.PARTNER
        result.entityId shouldBe "partner-789"
        result.scopes shouldBe listOf("payment:read", "partner:manage")
        result.clientId shouldBe "client-123"
    }

    @Test
    fun `should validate Platform token with minimal claims`() {
        // Given
        val token = createPlatformToken(
            subject = "client-minimal",
            role = "entity_readonly",
            entityType = null,
            entityId = null,
            scopes = emptyList()
        )

        // When
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )
        val result = validator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-minimal"
        result.userRole shouldBe UserRole.of("entity_readonly")
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
            .withClaim("role", "entity_user")
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
            .withClaim("role", "entity_user")
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
            .withClaim("role", "entity_user")
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
            .withClaim("role", "entity_user")
            .withExpiresAt(Date.from(Instant.now().minusSeconds(3600))) // Expired 1 hour ago
            .sign(algorithm)

        // When/Then
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(expiredToken)
        }
        exception.message?.contains("Invalid Supabase token") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for Supabase token with no exp claim`() {
        // Given a correctly signed Supabase token that carries no expiry
        val token = JWT.create()
            .withSubject("test-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", "entity_user")
            // no withExpiresAt
            .sign(algorithm)

        // When/Then — a missing exp must be rejected, not treated as valid forever (AC13)
        val exception = shouldThrow<UnknownTokenException> {
            dualJwtValidator.validateToken(token)
        }
        exception.message?.contains("Invalid Supabase token") shouldBe true
    }

    @Test
    fun `should throw UnknownTokenException for Platform token with no exp claim`() {
        // Given a correctly signed platform token that carries no expiry
        val token = JWT.create()
            .withSubject("client-123")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_admin")
            .withClaim("scopes", listOf("payment:read"))
            // no withExpiresAt
            .sign(algorithm)

        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )

        // When/Then (AC13)
        val exception = shouldThrow<UnknownTokenException> {
            validator.validateToken(token)
        }
        exception.message?.contains("Invalid Platform token") shouldBe true
    }

    // Utility Methods Tests

    @Test
    fun `getEntityType should return correct entity type`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = "entity_user",
            entityType = "merchant",
            entityId = "merchant-123"
        )

        // When
        val entityType = dualJwtValidator.getEntityType(token)

        // Then
        entityType shouldBe EntityType.MERCHANT
    }

    @Test
    fun `getEntityId should return correct entity ID`() {
        // Given
        val token = createSupabaseToken(
            subject = "user123",
            role = "entity_user",
            entityType = "partner",
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
            role = "platform_admin",
            entityType = null,
            entityId = null,
            scopes = emptyList()
        )

        // When
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )
        val entityType = validator.getEntityType(token)

        // Then
        entityType shouldBe null
    }

    // Test Helper Methods

    private fun createSupabaseToken(
        subject: String,
        role: String,
        entityType: String?,
        entityId: String?,
        aal: String? = null
    ): String {
        val tokenBuilder = JWT.create()
            .withSubject(subject)
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", role)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))

        aal?.let { tokenBuilder.withClaim("aal", it) }

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it }
            entityId?.let { appMetadata["entity_id"] = it }
            tokenBuilder.withClaim("app_metadata", appMetadata)
        }

        return tokenBuilder.sign(algorithm)
    }

    private fun createSupabaseServiceRoleToken(): String {
        return JWT.create()
            .withSubject("service-role-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", "service_role")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)
    }

    private fun createPlatformToken(
        subject: String,
        role: String,
        entityType: String?,
        entityId: String?,
        scopes: List<String>
    ): String {
        val tokenBuilder = JWT.create()
            .withSubject(subject)
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", role)
            .withClaim("scopes", scopes)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))

        if (entityType != null || entityId != null) {
            val appMetadata = mutableMapOf<String, Any>()
            entityType?.let { appMetadata["entity_type"] = it }
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
        val publicKey = kp.public as java.security.interfaces.RSAPublicKey
        val publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.encoded)
        
        val rsaValidator = DualJwtValidator(
            jwtSecret = jwtSecret,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            baseApiUrl = baseApiUrl,
            rsaEnabled = true,
            rsaPublicKey = Optional.of(publicKeyBase64),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = false
        )

        // RS256-signed platform token with partner context
        val token = JWT.create()
            .withSubject("client-rs256")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_admin")
            .withClaim("scopes", listOf("payment:read"))
            .withClaim("app_metadata", mapOf("entity_type" to "partner", "entity_id" to "partner-rs256"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(Algorithm.RSA256(null, privateKey))

        // When
        val result = rsaValidator.validateToken(token)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-rs256"
        result.userRole shouldBe UserRole.of("entity_admin")
        result.clientId shouldBe "client-rs256"
    }

    @Test
    fun `should validate HS256 Platform token when HMAC fallback enabled`() {
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = true
        )

        val token = JWT.create()
            .withSubject("client-hs256")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_admin")
            .withClaim("scopes", listOf("payment:read"))
            .withClaim("app_metadata", mapOf("entity_type" to "partner", "entity_id" to "partner-hs256"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val result = validator.validateToken(token)
        result.isValid shouldBe true
        result.subject shouldBe "client-hs256"
        result.userRole shouldBe UserRole.of("entity_admin")
        result.clientId shouldBe "client-hs256"
    }

    @Test
    fun `should fail HS256 Platform token when HMAC fallback disabled`() {
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = false,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = false
        )

        val token = JWT.create()
            .withSubject("client-hs256-no-fallback")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_admin")
            .withClaim("scopes", listOf("payment:read"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val ex = shouldThrow<UnknownTokenException> {
            validator.validateToken(token)
        }
        ex.message?.contains("No enabled algorithm for platform token validation") shouldBe true
    }
}
