package org.incept5.platform.core.security
import org.incept5.platform.core.model.UserRole

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.junit.jupiter.api.Test
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import java.time.Instant
import java.util.*

/**
 * Tests to verify that DualJwtValidator works correctly when optional
 * RSA configuration properties are not provided, ensuring Quarkus
 * applications can start without errors.
 */
class OptionalConfigTest {

    private val jwtSecretBytes = "test-secret-key-that-is-long-enough-for-hmac256-algorithm".toByteArray()
    private val jwtSecret = Base64.getEncoder().encodeToString(jwtSecretBytes)
    private val baseApiUrl = "https://api.test.com"
    private val supabaseAuthPath = "/auth/v1"
    private val platformOauthPath = "/api/v1/oauth/token"
    private val algorithm = Algorithm.HMAC256(jwtSecretBytes)

    @Test
    fun `should create validator without RSA properties provided`() {
        // Given - no RSA properties provided (using Optional.empty())
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

        // When - validate a Supabase token (should always work)
        val supabaseToken = JWT.create()
            .withSubject("user123")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", "entity_user")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val result = validator.validateToken(supabaseToken)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "user123"
    }

    @Test
    fun `should validate Platform token with HMAC fallback when RSA disabled and properties not provided`() {
        // Given - RSA disabled, HMAC fallback enabled, no RSA properties
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

        // When - validate a Platform token signed with HMAC
        val platformToken = JWT.create()
            .withSubject("client-123")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_admin")
            .withClaim("scopes", listOf("payment:read"))
            .withClaim("app_metadata", mapOf("entity_type" to "partner", "entity_id" to "partner-123"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val result = validator.validateToken(platformToken)

        // Then
        result.isValid shouldBe true
        result.subject shouldBe "client-123"
        result.userRole shouldBe UserRole.of("entity_admin")
    }

    @Test
    fun `should throw exception when RSA enabled but no properties provided`() {
        // Given - RSA enabled but no public key or JWKS URL
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = true,
            rsaPublicKey = Optional.empty(),
            jwksUrl = Optional.empty(),
            hmacFallbackEnabled = false
        )

        // When - try to validate a Platform token
        val platformToken = JWT.create()
            .withSubject("client-456")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_user")
            .withClaim("scopes", emptyList<String>())
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        // Then - should throw exception about missing configuration
        val exception = shouldThrow<UnknownTokenException> {
            validator.validateToken(platformToken)
        }
        exception.message?.contains("No enabled algorithm for platform token validation") shouldBe true
    }

    @Test
    fun `should work with blank RSA properties (empty strings in Optional)`() {
        // Given - RSA properties present but blank
        val validator = DualJwtValidator(
            jwtSecret = jwtSecret,
            baseApiUrl = baseApiUrl,
            supabaseAuthPath = supabaseAuthPath,
            platformOauthPath = platformOauthPath,
            rsaEnabled = true,
            rsaPublicKey = Optional.of(""),
            jwksUrl = Optional.of(""),
            hmacFallbackEnabled = true
        )

        // When - validate a Platform token with HMAC (fallback)
        val platformToken = JWT.create()
            .withSubject("client-789")
            .withIssuer("$baseApiUrl$platformOauthPath")
            .withClaim("role", "entity_readonly")
            .withClaim("scopes", listOf("payment:read"))
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val result = validator.validateToken(platformToken)

        // Then - should fall back to HMAC
        result.isValid shouldBe true
        result.subject shouldBe "client-789"
    }

    @Test
    fun `should validate Supabase tokens regardless of RSA configuration`() {
        // Given - validator with no RSA config and no HMAC fallback
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

        // When - validate Supabase token
        val supabaseToken = JWT.create()
            .withSubject("supabase-user")
            .withIssuer("$baseApiUrl$supabaseAuthPath")
            .withClaim("role", "platform_admin")
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

        val result = validator.validateToken(supabaseToken)

        // Then - Supabase validation should work (uses jwtSecret)
        result.isValid shouldBe true
        result.subject shouldBe "supabase-user"
        result.userRole shouldBe UserRole.of("platform_admin")
    }
}
