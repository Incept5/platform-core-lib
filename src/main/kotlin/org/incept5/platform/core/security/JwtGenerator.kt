
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.incept5.platform.core.model.EntityType
import java.time.Instant
import java.util.*

/**
 * Core JWT token generator for creating various types of authentication tokens.
 * This is a non-CDI class that can be used in both production and test environments.
 */
open class JwtGenerator(
    private val jwtSecret: String
) {
    
    /**
     * Creates the HMAC256 algorithm instance using the configured JWT secret
     */
    protected fun createAlgorithm(): Algorithm {
        return Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
    }

    /**
     * Generate a user authentication token
     *
     * @param user The user information to include in the token
     * @param issuer The token issuer (typically auth service URL)
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token string
     */
    fun generateUserToken(
        user: TestUser,
        issuer: String,
        expirationMinutes: Long = 60
    ): String {
        val now = Instant.now()
        val algorithm = createAlgorithm()

        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(user.userId.toString())
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", user.userRole.name)
            .withClaim("aud", "authenticated")
            .withIssuer(issuer)
            .withClaim("email", "${user.userId}@test.com")

        // Create app_metadata map
        val appMetadata = createAppMetadata(user.entityId, user.entityType)

        // Add app_metadata to the token if it's not empty
        if (appMetadata.isNotEmpty()) {
            tokenBuilder.withClaim("app_metadata", appMetadata)
        }

        // TODO: map user role to allowed scopes
        val scopes = emptyArray<String>()
        tokenBuilder.withArrayClaim("scopes", scopes)

        return tokenBuilder.sign(algorithm)
    }

    /**
     * Generate an API key token for service-to-service authentication
     *
     * @param clientId The client identifier
     * @param partnerId The partner/entity identifier
     * @param issuer The token issuer (typically OAuth token endpoint)
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token string
     */
    fun generateApiKeyToken(
        clientId: String,
        partnerId: String,
        issuer: String,
        expirationMinutes: Long = 60
    ): String {
        val now = Instant.now()
        val algorithm = createAlgorithm()

        // Create app_metadata map
        val appMetadata = createAppMetadata(partnerId, EntityType.partner)

        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(clientId)
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", "entity_admin")
            .withClaim("aud", "authenticated")
            .withIssuer(issuer)
            .withClaim("app_metadata", appMetadata)

        // TODO: map user role to allowed scopes
        val scopes = arrayOf("payment:create", "payment:read", "payment:update", "payment:refund")
        tokenBuilder.withArrayClaim("scopes", scopes)

        return tokenBuilder.sign(algorithm)
    }

    /**
     * Generate API key token with custom scopes for testing scope-based authorization
     *
     * @param clientId The client identifier
     * @param partnerId The partner/entity identifier
     * @param scopes The custom scopes to include in the token
     * @param issuer The token issuer (typically OAuth token endpoint)
     * @param expirationMinutes Token expiration time in minutes
     * @return JWT token string
     */
    fun generateApiKeyTokenWithScopes(
        clientId: String,
        partnerId: String,
        scopes: Array<String>,
        issuer: String,
        expirationMinutes: Long = 60
    ): String {
        val now = Instant.now()
        val algorithm = createAlgorithm()

        // Create app_metadata map
        val appMetadata = createAppMetadata(partnerId, EntityType.partner)

        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(clientId)
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", "entity_admin")
            .withClaim("aud", "authenticated")
            .withIssuer(issuer)
            .withClaim("app_metadata", appMetadata)
            .withArrayClaim("scopes", scopes)
            .withClaim("clientId", clientId)

        return tokenBuilder.sign(algorithm)
    }

    /**
     * Generate a service role token for system-level operations
     *
     * @param role The service role (default: "service_role")
     * @param issuer The token issuer
     * @return JWT token string
     */
    fun generateServiceRoleToken(
        role: String = "service_role",
        issuer: String
    ): String {
        val algorithm = createAlgorithm()
        return JWT.create()
            .withClaim("role", role)
            .withIssuer(issuer)
            .withSubject("service-role-token")
            .sign(algorithm)
    }

    /**
     * Create app_metadata map for JWT claims
     *
     * @param entityId The entity ID (optional)
     * @param entityType The entity type (optional)
     * @return Map of app metadata claims
     */
    private fun createAppMetadata(entityId: String?, entityType: EntityType?): Map<String, Any> {
        val appMetadata = HashMap<String, Any>()

        if (entityId != null) {
            appMetadata["entity_id"] = entityId
        }

        if (entityType != null) {
            appMetadata["entity_type"] = entityType.name
        }

        return appMetadata
    }
}
