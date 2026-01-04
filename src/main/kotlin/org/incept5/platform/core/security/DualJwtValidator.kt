
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.RSAKeyProvider
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.model.UserRole
import java.util.Base64
import org.incept5.platform.core.model.EntityType
import org.incept5.error.ErrorCategory
import org.jboss.logging.Logger
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey

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
    @ConfigProperty(name = "rsa-jwt.public-key", defaultValue = "")
    private val rsaPublicKey: String = "",
    @ConfigProperty(name = "rsa-jwt.jwks-url", defaultValue = "")
    private val jwksUrl: String = ""
) {
    private val log = Logger.getLogger(DualJwtValidator::class.java)
    
    // Lazy initialization of JWKS provider to avoid fetching keys at startup
    private val jwksProvider: JwksKeyProvider? by lazy {
        if (jwksUrl.isNotBlank()) {
            try {
                log.info("Initializing JWKS provider with URL: $jwksUrl")
                JwksKeyProvider(jwksUrl)
            } catch (e: Exception) {
                log.error("Failed to initialize JWKS provider", e)
                null
            }
        } else {
            null
        }
    }

    private fun requireSupabaseAlgorithm(): Algorithm {
        return Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
    }

    private fun requirePlatformAlgorithm(): Algorithm {
        if (rsaEnabled) {
            // Priority 1: Use JWKS provider if configured
            jwksProvider?.let { provider ->
                log.debug("Using JWKS provider for RSA verification")
                return Algorithm.RSA256(provider)
            }
            
            // Priority 2: Use explicit public key if provided
            if (rsaPublicKey.isNotBlank()) {
                log.debug("Using explicit public key for RSA verification")
                val publicKey = parsePublicKey(rsaPublicKey)
                return Algorithm.RSA256(publicKey, null)
            }
            
            log.warn("RSA enabled but no public key or JWKS URL configured")
        }
        
        // Fallback: Use HMAC if enabled
        if (hmacFallbackEnabled) {
            log.debug("Using HMAC256 fallback for platform token validation")
            return Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        }
        
        throw UnknownTokenException("No enabled algorithm for platform token validation. Configure either rsa-jwt.public-key, rsa-jwt.jwks-url, or enable HMAC fallback.")
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

    /**
     * Parse a PEM-encoded or raw base64 RSA public key.
     * Supports both X.509 SubjectPublicKeyInfo format and raw base64.
     */
    private fun parsePublicKey(base64: String): RSAPublicKey {
        try {
            val raw = Base64.getDecoder().decode(base64)
            val content = String(raw, Charsets.UTF_8)
            
            val keyBytes = if (content.contains("BEGIN")) {
                // PEM format: strip headers and decode
                val cleaned = content
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                    .replace("-----END RSA PUBLIC KEY-----", "")
                    .replace("\n", "")
                    .replace("\r", "")
                    .trim()
                Base64.getDecoder().decode(cleaned)
            } else {
                raw
            }
            
            val spec = java.security.spec.X509EncodedKeySpec(keyBytes)
            val keyFactory = java.security.KeyFactory.getInstance("RSA")
            return keyFactory.generatePublic(spec) as RSAPublicKey
        } catch (e: Exception) {
            throw UnknownTokenException("Failed to parse RSA public key: ${e.message}", e)
        }
    }
}

/**
 * JWKS-based RSA Key Provider that fetches public keys from a JWKS endpoint.
 * Implements auth0's RSAKeyProvider interface.
 */
open class JwksKeyProvider(private val jwksUrl: String) : RSAKeyProvider {
    private val log = Logger.getLogger(JwksKeyProvider::class.java)
    protected val keyCache = mutableMapOf<String, RSAPublicKey>()
    
    init {
        log.info("Initializing JWKS provider with URL: $jwksUrl")
        // Eagerly fetch keys on initialization (non-blocking)
        try {
            fetchKeys()
            log.info("Successfully initialized JWKS provider with ${keyCache.size} keys")
        } catch (e: Exception) {
            log.warn("Failed to fetch JWKS keys on initialization. Keys will be fetched on first use.", e)
        }
    }
    
    override fun getPublicKeyById(keyId: String?): RSAPublicKey {
        // If no key ID specified, try to return the first available key
        if (keyId == null) {
            return keyCache.values.firstOrNull() 
                ?: throw UnknownTokenException("No RSA public keys available in JWKS")
        }
        
        // Try cache first
        keyCache[keyId]?.let { return it }
        
        // Refresh cache and try again
        try {
            fetchKeys()
            keyCache[keyId]?.let { return it }
        } catch (e: Exception) {
            log.error("Failed to fetch JWKS keys for key ID: $keyId", e)
        }
        
        throw UnknownTokenException("Public key not found for key ID: $keyId")
    }
    
    override fun getPrivateKey(): RSAPrivateKey? = null
    override fun getPrivateKeyId(): String? = null
    
    private fun fetchKeys() {
        try {
            val url = java.net.URL(jwksUrl)
            val connection = url.openConnection() as java.net.HttpURLConnection
            connection.requestMethod = "GET"
            connection.connectTimeout = 10000
            connection.readTimeout = 10000
            
            val responseCode = connection.responseCode
            if (responseCode != 200) {
                throw UnknownTokenException("Failed to fetch JWKS: HTTP $responseCode")
            }
            
            val response = connection.inputStream.bufferedReader().use { it.readText() }
            parseJwks(response)
            
            log.info("Successfully fetched ${keyCache.size} keys from JWKS endpoint")
        } catch (e: Exception) {
            log.error("Error fetching JWKS", e)
            throw UnknownTokenException("Failed to fetch JWKS: ${e.message}", e)
        }
    }
    
    protected open fun parseJwks(json: String) {
        // Simple JSON parsing for JWKS format
        // Expected format: {"keys": [{"kid": "...", "n": "...", "e": "...", "kty": "RSA", "use": "sig"}]}
        
        try {
            // Extract keys array from JSON
            val keysMatch = "\"keys\"\\s*:\\s*\\[([^\\]]+)\\]".toRegex().find(json)
                ?: throw UnknownTokenException("No 'keys' array found in JWKS")
            
            val keysJson = keysMatch.groupValues[1]
            
            // Parse each key object
            val keyObjects = "\\{([^}]+)\\}".toRegex().findAll(keysJson)
            
            for (keyMatch in keyObjects) {
                try {
                    val keyJson = keyMatch.value
                    
                    // Extract required fields
                    val kid = extractJsonField(keyJson, "kid")
                    val n = extractJsonField(keyJson, "n")
                    val e = extractJsonField(keyJson, "e")
                    val kty = extractJsonField(keyJson, "kty")
                    
                    // Only process RSA keys for signature verification
                    if (kty != "RSA") continue
                    
                    // Decode Base64URL encoded modulus and exponent
                    val modulus = java.math.BigInteger(1, Base64.getUrlDecoder().decode(n))
                    val exponent = java.math.BigInteger(1, Base64.getUrlDecoder().decode(e))
                    
                    // Create RSA public key
                    val spec = java.security.spec.RSAPublicKeySpec(modulus, exponent)
                    val keyFactory = java.security.KeyFactory.getInstance("RSA")
                    val publicKey = keyFactory.generatePublic(spec) as RSAPublicKey
                    
                    keyCache[kid] = publicKey
                    log.debug("Cached RSA public key with ID: $kid")
                } catch (e: Exception) {
                    log.warn("Failed to parse key from JWKS", e)
                }
            }
            
            if (keyCache.isEmpty()) {
                throw UnknownTokenException("No valid RSA keys found in JWKS")
            }
        } catch (e: Exception) {
            if (e is UnknownTokenException) throw e
            throw UnknownTokenException("Failed to parse JWKS: ${e.message}", e)
        }
    }
    
    private fun extractJsonField(json: String, field: String): String {
        val pattern = "\"$field\"\\s*:\\s*\"([^\"]+)\"".toRegex()
        val match = pattern.find(json)
            ?: throw UnknownTokenException("Required field '$field' not found in JWKS key")
        return match.groupValues[1]
    }
}
