
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.exceptions.JWTVerificationException
import com.auth0.jwt.interfaces.RSAKeyProvider
import com.fasterxml.jackson.databind.ObjectMapper
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.incept5.authz.core.context.AssuranceLevel
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import java.util.Base64
import org.incept5.error.ErrorCategory
import org.jboss.logging.Logger
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.Optional

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
    @ConfigProperty(name = "rsa-jwt.public-key")
    private val rsaPublicKey: Optional<String>,
    @ConfigProperty(name = "rsa-jwt.jwks-url")
    private val jwksUrl: Optional<String>
) {
    private val log = Logger.getLogger(DualJwtValidator::class.java)
    
    // Lazy initialization of JWKS provider to avoid fetching keys at startup
    private val jwksProvider: JwksKeyProvider? by lazy {
        jwksUrl.map { url ->
            if (url.isNotBlank()) {
                try {
                    log.info("Initializing JWKS provider with URL: $url")
                    JwksKeyProvider(url)
                } catch (e: Exception) {
                    log.error("Failed to initialize JWKS provider", e)
                    null
                }
            } else {
                null
            }
        }.orElse(null)
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
            val publicKeyValue = rsaPublicKey.orElse(null)
            if (publicKeyValue != null && publicKeyValue.isNotBlank()) {
                log.debug("Using explicit public key for RSA verification")
                val publicKey = parsePublicKey(publicKeyValue)
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
                // Require exp so a signed token with no expiry is not treated as valid forever
                // (story AC13). GoTrue always sets exp, so no legitimate token is affected.
                .withClaimPresence("exp")
                .withIssuer("$baseApiUrl$supabaseAuthPath")
                .build()
                .verify(token)

            val subject = jwt.subject ?: throw JWTVerificationException("No subject claim")

            val rawRole = jwt.getClaim("role")?.asString()
                ?: throw JWTVerificationException("Invalid role")

            val appMetadata = jwt.getClaim("app_metadata")?.asMap()
            val entityTypeStr = appMetadata?.get("entity_type")?.toString()
            val entityType = entityTypeStr?.let { EntityType.fromValue(it) }
            val entityId = appMetadata?.get("entity_id")?.toString()

            // Pass raw role string through — legacy mapping handled by SupabaseTokenExchangePlugin
            val userRole = UserRole.of(rawRole)

            // Scopes are no longer derived from role — authz-lib handles permissions
            val scopes = emptyList<String>()

            // GoTrue writes "aal2" after a verified TOTP challenge; a password grant is "aal1" and
            // a legacy token may carry no claim. This is the ONLY place the Supabase claim value is
            // interpreted — it is mapped to the provider-neutral AssuranceLevel here, and authz-lib's
            // enforcement never sees "aal2".
            val aal = jwt.getClaim("aal")?.asString()
            val assuranceLevel =
                if (aal == "aal2") AssuranceLevel.MULTI_FACTOR else AssuranceLevel.SINGLE_FACTOR

            return TokenValidationResult.valid(
                subject = subject,
                userRole = userRole,
                entityType = entityType,
                entityId = entityId,
                scopes = scopes,
                clientId = null,
                assuranceLevel = assuranceLevel,
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
                // Require exp so a signed token with no expiry is not treated as valid forever
                // (story AC13). JwtTokenGenerator always sets withExpiresAt, so no legitimate
                // FanFair-issued token is affected.
                .withClaimPresence("exp")
                .withIssuer("$baseApiUrl$platformOauthPath")
                .build()
                .verify(token)

            val subject = jwt.subject ?: throw JWTVerificationException("No subject claim")
            val rawRole = jwt.getClaim("role")?.asString()
                ?: throw JWTVerificationException("Invalid role")

            val appMetadata = jwt.getClaim("app_metadata")?.asMap()
            val entityTypeStr = appMetadata?.get("entity_type")?.toString()
            val entityType = entityTypeStr?.let { EntityType.fromValue(it) }
            val entityId = appMetadata?.get("entity_id")?.toString()

            // Pass raw role string through
            val userRole = UserRole.of(rawRole)

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
                machinePrincipal = true,
            )
        } catch (e: Exception) {
            log.warn("Platform token validation failed", e)
            throw UnknownTokenException("Invalid Platform token: ${e.message}", e)
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
    
    /**
     * Parse a JWKS document (RFC 7517) and cache every usable RSA signing key by `kid`.
     *
     * Parsed with a real JSON parser rather than a regex. The previous regex delimited the key set
     * with `"keys"\s*:\s*\[([^\]]+)\]`, whose negated character class stops at the *first* `]` in
     * the document — which, for any IdP that publishes the X.509 chain, is the one closing a key's
     * nested `x5c` array, not the one closing `keys`. Every such key set (Keycloak's included) was
     * therefore reported as "No valid RSA keys found in JWKS", an error naming the wrong cause. A
     * tighter regex would only move that boundary; JSON is not a regular language.
     *
     * Keys the platform cannot use for RS256 signature verification are skipped rather than
     * failing the document: non-RSA key types, keys explicitly published for encryption
     * (`"use": "enc"` — Keycloak serves an RSA-OAEP key alongside the RS256 signing key), and any
     * individual key that will not decode. A key set legitimately carries keys this platform has
     * no use for, including during a rotation overlap, and one unusable key must not discard the
     * rest of the set.
     *
     * Still `protected open`: consumers overriding it keep working.
     */
    protected open fun parseJwks(json: String) {
        try {
            val keys = MAPPER.readTree(json).get("keys")
                ?: throw UnknownTokenException("No 'keys' array found in JWKS")
            if (!keys.isArray) {
                throw UnknownTokenException("JWKS 'keys' is not an array")
            }

            var parsed = 0
            for (key in keys) {
                // A missing "use" means the key is usable for signing — RFC 7517 makes the field
                // optional, and IdPs that omit it must keep working.
                if (key.text("kty") != "RSA") continue
                val use = key.text("use")
                if (use != null && use != "sig") continue

                val kid = key.text("kid") ?: continue
                val n = key.text("n") ?: continue
                val e = key.text("e") ?: continue
                try {
                    // Base64URL-encoded modulus and exponent, unsigned big-endian.
                    val modulus = java.math.BigInteger(1, Base64.getUrlDecoder().decode(n))
                    val exponent = java.math.BigInteger(1, Base64.getUrlDecoder().decode(e))

                    val spec = java.security.spec.RSAPublicKeySpec(modulus, exponent)
                    val keyFactory = java.security.KeyFactory.getInstance("RSA")
                    keyCache[kid] = keyFactory.generatePublic(spec) as RSAPublicKey
                    parsed++
                    log.debug("Cached RSA public key with ID: $kid")
                } catch (e: Exception) {
                    log.warn("Skipping unparseable JWKS key '$kid'", e)
                }
            }

            if (parsed == 0) {
                throw UnknownTokenException("No valid RSA signing keys found in JWKS")
            }
        } catch (e: Exception) {
            if (e is UnknownTokenException) throw e
            throw UnknownTokenException("Failed to parse JWKS: ${e.message}", e)
        }
    }

    /**
     * The value of a JWK's string member, or null if absent or not a string.
     *
     * Deliberately not `get(field)?.asText()`: on a JSON `null` that yields the four-character
     * string `"null"`, which is valid base64url and would be decoded into a nonsense modulus and
     * cached under the key's `kid` rather than skipping the key.
     */
    private fun com.fasterxml.jackson.databind.JsonNode.text(field: String): String? =
        get(field)?.takeIf { it.isTextual }?.asText()

    companion object {
        /**
         * Shared rather than per-instance, and deliberately so: [JwksKeyProvider]'s constructor
         * calls [parseJwks] through [fetchKeys], and Kotlin initialises a *subclass*'s
         * constructor-property backing fields only after the superclass constructor returns. An
         * instance mapper field would therefore be null on that first call for any subclass that
         * overrides the parse. Companion state is initialised on first class access, so it is
         * already there. `ObjectMapper` is safe for concurrent reads once configured, and this one
         * is never configured after construction.
         */
        private val MAPPER = ObjectMapper()
    }
}
