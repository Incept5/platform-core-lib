
package org.incept5.platform.core.security

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import jakarta.enterprise.context.ApplicationScoped
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.incept5.platform.core.model.EntityType
import java.time.Instant
import java.util.*

@ApplicationScoped
class TestJwtGenerator {
    @ConfigProperty(name = "supabase.jwt.secret")
    lateinit var jwtSecret: String

    @ConfigProperty(name = "api.base.url")
    lateinit var apiBaseUrl: String

    fun generateUserToken(user: TestUser = TestUser(), expirationMinutes: Long = 60): String {
        val now = Instant.now()
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))

        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(user.userId.toString())
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", user.userRole.name)
            .withClaim("aud", "authenticated")
           // Supabase tokens need the expected issuer for proper recognition
            .withIssuer("$apiBaseUrl/auth/v1")
            .withClaim("email", "${user.userId}@test.com")

        // Create app_metadata map
        val appMetadata = HashMap<String, Any>()

        // Add entity_id and entity_type to app_metadata if they exist
        if (user.entityId != null) {
            appMetadata["entity_id"] = user.entityId
        }

        if (user.entityType != null) {
            appMetadata["entity_type"] = user.entityType.name
        }

        // Add app_metadata to the token if it's not empty
        if (appMetadata.isNotEmpty()) {
            tokenBuilder.withClaim("app_metadata", appMetadata)
        }

        // TODO: map user role to allowed scopes
        val scopes = emptyArray<String>()
        tokenBuilder.withArrayClaim("scopes", scopes)

        // Log the token details for debugging
        println("Generating token for user: ${user.userId}, role: ${user.userRole}, entityId: ${user.entityId}, entityType: ${user.entityType}")
        println("App metadata: $appMetadata")
        println("Scopes: ${scopes.joinToString(", ")}")

        return tokenBuilder.sign(algorithm)
    }

    fun generateApiKeyToken(clientId: String, partnerId: String, expirationMinutes: Long = 60): String {
        val now = Instant.now()
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        // Create app_metadata map
        val appMetadata = HashMap<String, Any>()

        // Add entity_id and entity_type to app_metadata
        appMetadata["entity_id"] = partnerId
        appMetadata["entity_type"] = EntityType.partner.name
        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(clientId)
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", "entity_admin")
            .withClaim("aud", "authenticated")
            // FanFair tokens need the expected issuer for proper recognition
            .withIssuer("$apiBaseUrl/api/v1/oauth/token")
            .withClaim("app_metadata", appMetadata)


        // TODO: map user role to allowed scopes
        val scopes = arrayOf("payment:create", "payment:read", "payment:update", "payment:refund")
        tokenBuilder.withArrayClaim("scopes", scopes)

        // Log the token details for debugging
        println("Generating token for API Key: ${clientId}")
        println("App metadata: $appMetadata")
        println("Scopes: ${scopes.joinToString(", ")}")

        return tokenBuilder.sign(algorithm)
    }

    /**
     * Generate API key token with custom scopes for testing scope-based authorization
     */
    fun generateApiKeyTokenWithScopes(
        clientId: String,
        partnerId: String,
        scopes: Array<String>,
        expirationMinutes: Long = 60
    ): String {
        val now = Instant.now()
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))

        // Create app_metadata map
        val appMetadata = HashMap<String, Any>()
        appMetadata["entity_id"] = partnerId
        appMetadata["entity_type"] = EntityType.partner.name

        // Create the token builder
        val tokenBuilder = JWT.create()
            .withSubject(clientId)
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(expirationMinutes * 60)))
            .withClaim("role", "entity_admin")
            .withClaim("aud", "authenticated")
            .withIssuer("$apiBaseUrl/api/v1/oauth/token")
            .withClaim("app_metadata", appMetadata)
            .withArrayClaim("scopes", scopes)
            .withClaim("clientId", clientId)

        // Log the token details for debugging
        println("Generating API key token with custom scopes: clientId=${clientId}, partnerId=${partnerId}")
        println("App metadata: $appMetadata")
        println("Scopes: ${scopes.joinToString(", ")}")

        return tokenBuilder.sign(algorithm)
    }

    fun generateServiceRoleToken(role: String = "service_role"): String {
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        return JWT.create()
            .withClaim("role", role)
            .withIssuer("$apiBaseUrl/auth/v1")
            .withSubject("service-role-token")  // Add subject claim required for FanFair token validation
            .sign(algorithm)
    }

}
