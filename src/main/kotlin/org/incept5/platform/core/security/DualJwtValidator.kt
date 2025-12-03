
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.model.UserRole
import java.util.Base64
import org.incept5.platform.core.model.EntityType
import org.incept5.error.ErrorCategory
import org.jboss.logging.Logger

/**
 * Exception thrown when a token source cannot be determined or is not recognized.
 * This will result in a 401 Unauthorized response.
 */
class UnknownTokenException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.AUTHORIZATION, cause)

@ApplicationScoped
class DualJwtValidator @Inject constructor(
    @ConfigProperty(name = "supabase.jwt.secret")
    private val jwtSecret: String,
    @ConfigProperty(name = "rsa-jwt.hmac-fallback.enabled", defaultValue = "false")
    private val hmacFallbackEnabled: Boolean = false,
    @ConfigProperty(name = "api.base.url")
    private val baseApiUrl: String,
    @ConfigProperty(name = "auth.supabase.path", defaultValue = "/auth/v1")
    private val supabaseAuthPath: String,
    @ConfigProperty(name = "auth.platform.oauth.path", defaultValue = "/api/v1/oauth/token")
    private val platformOauthPath: String,
    @ConfigProperty(name = "rsa-jwt.enabled", defaultValue = "true")
    private val rsaEnabled: Boolean = true,
    @ConfigProperty(name = "rsa-jwt.private-key", defaultValue = "")
    private val rsaPrivateKey: String = ""
) {
    private val log = Logger.getLogger(DualJwtValidator::class.java)

    private fun requireSupabaseAlgorithm(): Algorithm {
        return Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
    }

    private fun requirePlatformAlgorithm(): Algorithm {
        if (rsaEnabled && rsaPrivateKey.isNotBlank()) {
            val publicKey = derivePublicKeyFromPrivate(rsaPrivateKey)
            return Algorithm.RSA256(publicKey, null)
        } else {
            if (hmacFallbackEnabled) {
                return Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
            }
        }
        throw UnknownTokenException("No enabled algorithm for platform token validation")
    }


    fun validateToken(token: String): TokenValidationResult {
        try {
            val tokenSource = detectTokenSource(token)

            return when (tokenSource) {
                TokenSource.SUPABASE -> validateSupabaseToken(token)
                TokenSource.PLATFORM -> validatePlatformToken(token)
                // We should never reach here since detectTokenSource now throws an exception for UNKNOWN
                else -> throw UnknownTokenException("Unknown token source")
            }
        } catch (e: UnknownTokenException) {
            throw e // Rethrow UnknownTokenException
        } catch (e: Exception) {
            // Convert other exceptions to UnknownTokenException
            throw UnknownTokenException("Error validating token: ${e.message}", e)
        }
    }

    private fun detectTokenSource(token: String): TokenSource {
        try {
            val decoded = JWT.decode(token)
            val issuer = decoded.issuer

            return when {
                issuer == "$baseApiUrl$supabaseAuthPath" -> TokenSource.SUPABASE
                issuer == "$baseApiUrl$platformOauthPath" -> TokenSource.PLATFORM
                else -> {
                    log.warn("Token issuer must have base Url: $baseApiUrl")
                    log.error("Unknown token issuer: $issuer")
                    throw UnknownTokenException("Unknown token issuer: $issuer")
                }
            }
        } catch (e: UnknownTokenException) {
            throw e // Rethrow if it's already our custom exception
        } catch (e: Exception) {
            log.error("Failed to decode token", e)
            throw UnknownTokenException("Invalid token format", e)
        }
    }

    private fun validateSupabaseToken(token: String): TokenValidationResult {
        try {
            val jwt = JWT.require(requireSupabaseAlgorithm())
                .withClaimPresence("role")
                .withIssuer("$baseApiUrl$supabaseAuthPath")
                .build()
                .verify(token)

            val subject = jwt.subject ?: throw JWTVerificationException("No subject claim")

            val userRole = jwt.getClaim("role")?.asString()?.let { UserRole.valueOf(it) }
                ?: throw JWTVerificationException("Invalid role")


            // Handle service_role tokens specially
            if (userRole == UserRole.service_role) {
                return TokenValidationResult.valid(
                    subject = subject,
                    userRole = UserRole.platform_admin, // Service role gets platform_admin privileges
                    entityType = null,
                    entityId = null,
                    scopes = deriveScopesFromRole(UserRole.platform_admin, null),
                    clientId = null,
                    tokenSource = TokenSource.SUPABASE
                )
            }


            val appMetadata = jwt.getClaim("app_metadata")?.asMap()
            val entityType = appMetadata?.get("entity_type")?.toString()?.let {
                try {
                    EntityType.valueOf(it)
                } catch (e: IllegalArgumentException) {
                    null // Allow null entity type for service roles
                }
            }
            val entityId = appMetadata?.get("entity_id")?.toString()

            // Derive scopes from role and entity type for Supabase tokens
            val scopes = deriveScopesFromRole(userRole, entityType)

            return TokenValidationResult.valid(
                subject = subject,
                userRole = userRole,
                entityType = entityType,
                entityId = entityId,
                scopes = scopes,
                clientId = null,
                tokenSource = TokenSource.SUPABASE
            )
        } catch (e: Exception) {
            log.warn("Supabase token validation failed", e)
            // We'll use dummy values for subject and userRole since we're throwing an exception instead
            throw UnknownTokenException("Invalid Supabase token: ${e.message}", e)
        }
    }

    private fun validatePlatformToken(token: String): TokenValidationResult {
        try {
            val jwt = JWT.require(requirePlatformAlgorithm())
                .withClaimPresence("role")
                .withIssuer("$baseApiUrl$platformOauthPath")
                .build()
                .verify(token)

            val subject = jwt.subject ?: throw JWTVerificationException("No subject claim")
            val userRole = jwt.getClaim("role")?.asString()?.let { UserRole.valueOf(it) }
                ?: throw JWTVerificationException("Invalid role")

            val appMetadata = jwt.getClaim("app_metadata")?.asMap()
            val entityType = appMetadata?.get("entity_type")?.toString()?.let { EntityType.valueOf(it) }
            val entityId = appMetadata?.get("entity_id")?.toString()

            // Extract explicit scopes from FanFair tokens
            val scopes = jwt.getClaim("scopes")?.asList(String::class.java) ?: emptyList()

            // Extract client ID from FanFair tokens (sub claim for client_credentials)
            val clientId = subject // For client_credentials, sub is the client ID

            return TokenValidationResult.valid(
                subject = subject,
                userRole = userRole,
                entityType = entityType,
                entityId = entityId,
                scopes = scopes,
                clientId = clientId,
                tokenSource = TokenSource.PLATFORM
            )
        } catch (e: Exception) {
            log.warn("Platform token validation failed", e)
            throw UnknownTokenException("Invalid Platform token: ${e.message}", e)
        }
    }

    private fun deriveScopesFromRole(role: UserRole, entityType: EntityType?): List<String> {
        return when (role) {
            UserRole.platform_admin -> listOf(
                "payment:create", "payment:read", "payment:manage",
                "partner:create", "partner:read", "partner:manage",
                "merchant:create", "merchant:read", "merchant:manage"
            )
            UserRole.entity_admin -> when (entityType) {
                EntityType.partner -> listOf(
                    "payment:create", "payment:read", "partner:manage",
                    "merchant:create", "merchant:read", "merchant:manage"
                )
                EntityType.merchant -> listOf(
                    "payment:create", "payment:read", "merchant:manage"
                )
                else -> emptyList()
            }
            UserRole.entity_user -> when (entityType) {
                EntityType.partner -> listOf("payment:create", "payment:read")
                EntityType.merchant -> listOf("payment:create", "payment:read")
                else -> emptyList()
            }
            UserRole.entity_readonly -> listOf("payment:read")
            UserRole.service_role -> listOf(
                "payment:create", "payment:read", "payment:manage",
                "partner:create", "partner:read", "partner:manage",
                "merchant:create", "merchant:read", "merchant:manage"
            )
        }
    }


    fun getEntityType(token: String): EntityType? = validateToken(token).entityType
    fun getEntityId(token: String): String? = validateToken(token).entityId

    private fun derivePublicKeyFromPrivate(base64: String): java.security.interfaces.RSAPublicKey {
        val raw = Base64.getDecoder().decode(base64)
        val content = String(raw)
        val keyBytes = if (content.contains("BEGIN")) {
            val cleaned = content
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("\n", "")
                .replace("\r", "")
            Base64.getDecoder().decode(cleaned)
        } else raw
        val spec = java.security.spec.PKCS8EncodedKeySpec(keyBytes)
        val kf = java.security.KeyFactory.getInstance("RSA")
        val privateKey = kf.generatePrivate(spec)
        val crt = privateKey as? java.security.interfaces.RSAPrivateCrtKey
        val pubSpec = java.security.spec.RSAPublicKeySpec(
            crt?.modulus ?: (privateKey as java.security.interfaces.RSAPrivateKey).modulus,
            crt?.publicExponent ?: java.math.BigInteger.valueOf(65537L)
        )
        return kf.generatePublic(pubSpec) as java.security.interfaces.RSAPublicKey
    }
}
