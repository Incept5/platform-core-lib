
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.DecodedJWT
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.jboss.logging.Logger
import java.time.Instant

/**
 * JWT validator for stacks that issue their own RS256 access tokens from a single
 * issuer (`iss` claim) and publish signing keys via JWKS with `kid`-based rotation.
 *
 * Intentionally narrower than [DualJwtValidator]: no HMAC fallback, no dual-issuer
 * dispatch, no Supabase-shaped claim reads. Use [DualJwtValidator] for stacks that
 * front a Supabase auth surface; use this validator for stacks that own the full
 * auth stack and mint their own tokens.
 *
 * Key rotation uses standard JWKS semantics: during the rotation overlap window
 * the JWKS endpoint serves both the previous and current keys, each with its own
 * `kid`; the validator picks by the token's `kid` header. No explicit "two key
 * slots" configuration.
 *
 * Step-up tokens (one-shot, context-bound) are verified via [verifyStepUp], which
 * additionally enforces a `purpose` claim and `purpose_context` key/value pairs.
 */
@ApplicationScoped
class SingleIssuerJwtValidator @Inject constructor(
    @ConfigProperty(name = "single-issuer-jwt.issuer")
    private val issuer: String,
    @ConfigProperty(name = "single-issuer-jwt.audience")
    private val audience: String,
    @ConfigProperty(name = "single-issuer-jwt.jwks-url")
    private val jwksUrl: String,
    @ConfigProperty(name = "single-issuer-jwt.leeway-seconds", defaultValue = "30")
    private val leewaySeconds: Long = 30L
) {
    private val log = Logger.getLogger(SingleIssuerJwtValidator::class.java)

    // Lazy — defer first JWKS fetch until first verify call so an unreachable
    // JWKS endpoint at boot doesn't prevent startup.
    private val jwksProvider: JwksKeyProvider by lazy {
        log.info("Initializing SingleIssuerJwtValidator JWKS provider: $jwksUrl")
        JwksKeyProvider(jwksUrl)
    }

    /**
     * Verify a session or step-up JWT and return the extracted claims.
     *
     * Throws [UnknownTokenException] on any verification failure (bad signature,
     * wrong issuer, wrong audience, expired, missing required claims, unknown
     * `kid`). The exception is intentionally generic — callers MUST NOT
     * distinguish failure modes to the client.
     */
    fun verify(token: String): SingleIssuerTokenClaims {
        try {
            val verified = decodeAndVerify(token)
            return extractClaims(verified)
        } catch (e: UnknownTokenException) {
            throw e
        } catch (e: JWTVerificationException) {
            log.warn("Token verification failed: ${e.message}")
            throw UnknownTokenException("Invalid token: ${e.message}", e)
        } catch (e: Exception) {
            log.warn("Token verification error", e)
            throw UnknownTokenException("Error verifying token: ${e.message}", e)
        }
    }

    /**
     * Verify a step-up token and check it carries the expected `purpose` and
     * matching `purpose_context` entries. Every entry in [expectedContext] must
     * be present in the token's `purpose_context` claim with the same value
     * (compared by string form).
     *
     * Use this from consumer modules to gate one-shot sensitive operations
     * (e.g. transfer confirm, withdraw confirm, passcode update). The context
     * binding prevents a PIN-validated step-up token from being replayed
     * against a different operation.
     */
    fun verifyStepUp(
        token: String,
        expectedPurpose: String,
        expectedContext: Map<String, Any> = emptyMap()
    ): SingleIssuerTokenClaims {
        val claims = verify(token)

        val actualPurpose = claims.purpose
            ?: throw UnknownTokenException("Step-up token missing 'purpose' claim")
        if (actualPurpose != expectedPurpose) {
            throw UnknownTokenException(
                "Step-up purpose mismatch: expected '$expectedPurpose', got '$actualPurpose'"
            )
        }

        if (expectedContext.isNotEmpty()) {
            val actualContext = claims.purposeContext
                ?: throw UnknownTokenException("Step-up token missing 'purpose_context' claim")
            for ((key, expected) in expectedContext) {
                val actual = actualContext[key]
                if (actual == null || actual.toString() != expected.toString()) {
                    throw UnknownTokenException(
                        "Step-up purpose_context mismatch on '$key': expected '$expected', got '$actual'"
                    )
                }
            }
        }

        return claims
    }

    private fun decodeAndVerify(token: String): DecodedJWT {
        val decoded = try {
            JWT.decode(token)
        } catch (e: Exception) {
            throw UnknownTokenException("Invalid token format", e)
        }

        if (decoded.issuer != issuer) {
            throw UnknownTokenException(
                "Invalid issuer: expected '$issuer', got '${decoded.issuer}'"
            )
        }

        val publicKey = try {
            jwksProvider.getPublicKeyById(decoded.keyId)
        } catch (e: UnknownTokenException) {
            throw e
        } catch (e: Exception) {
            throw UnknownTokenException("Failed to resolve signing key: ${e.message}", e)
        }

        val algorithm = Algorithm.RSA256(publicKey, null)

        return JWT.require(algorithm)
            .withIssuer(issuer)
            .withAudience(audience)
            .withClaimPresence("sub")
            .withClaimPresence("exp")
            .withClaimPresence("iat")
            .acceptLeeway(leewaySeconds)
            .build()
            .verify(token)
    }

    private fun extractClaims(jwt: DecodedJWT): SingleIssuerTokenClaims {
        val subject = jwt.subject
            ?: throw UnknownTokenException("Token missing subject")

        return SingleIssuerTokenClaims(
            subject = subject,
            subjectType = jwt.getClaim("sub_type")?.asString(),
            kycLevel = jwt.getClaim("kyc_level")?.asInt(),
            deviceId = jwt.getClaim("device_id")?.asString(),
            scopes = jwt.getClaim("scopes")?.asList(String::class.java) ?: emptyList(),
            purpose = jwt.getClaim("purpose")?.asString(),
            purposeContext = jwt.getClaim("purpose_context")?.asMap(),
            jti = jwt.id,
            issuedAt = jwt.issuedAt?.toInstant(),
            expiresAt = jwt.expiresAt?.toInstant(),
            audience = jwt.audience ?: emptyList(),
            issuer = jwt.issuer ?: ""
        )
    }
}

/**
 * Claims extracted from a verified single-issuer JWT.
 *
 * Standard claims ([subject], [audience], [issuer], [issuedAt], [expiresAt],
 * [jti]) are always populated when verification succeeds. The chivo-shaped
 * claims ([subjectType], [kycLevel], [deviceId], [scopes]) are optional and
 * reflect whatever the token issuer set. The step-up fields ([purpose],
 * [purposeContext]) are populated only for step-up tokens.
 */
data class SingleIssuerTokenClaims(
    val subject: String,
    val subjectType: String?,
    val kycLevel: Int?,
    val deviceId: String?,
    val scopes: List<String>,
    val purpose: String?,
    val purposeContext: Map<String, Any>?,
    val jti: String?,
    val issuedAt: Instant?,
    val expiresAt: Instant?,
    val audience: List<String>,
    val issuer: String
)
