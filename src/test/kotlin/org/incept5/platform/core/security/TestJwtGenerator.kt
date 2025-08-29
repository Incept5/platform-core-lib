
package org.incept5.platform.core.security

import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject
import org.eclipse.microprofile.config.inject.ConfigProperty
import org.incept5.platform.core.model.EntityType

/**
 * Test-specific JWT generator that extends the base JwtGenerator with CDI integration
 * and debug logging capabilities for testing purposes.
 */
@ApplicationScoped
class TestJwtGenerator @Inject constructor(
    @ConfigProperty(name = "supabase.jwt.secret") jwtSecret: String,
    @ConfigProperty(name = "api.base.url") private val apiBaseUrl: String
) : JwtGenerator(jwtSecret) {

    /**
     * Generate user token with default Supabase issuer and debug logging
     */
    fun generateUserToken(user: TestUser = TestUser(), expirationMinutes: Long = 60): String {
        val issuer = "$apiBaseUrl/auth/v1"
        
        // Log the token details for debugging
        println("Generating token for user: ${user.userId}, role: ${user.userRole}, entityId: ${user.entityId}, entityType: ${user.entityType}")
        println("Issuer: $issuer")
        
        return super.generateUserToken(user, issuer, expirationMinutes)
    }

    /**
     * Generate API key token with default OAuth issuer and debug logging
     */
    fun generateApiKeyToken(clientId: String, partnerId: String, expirationMinutes: Long = 60): String {
        val issuer = "$apiBaseUrl/api/v1/oauth/token"
        
        // Log the token details for debugging
        println("Generating token for API Key: $clientId")
        println("Partner ID: $partnerId")
        println("Issuer: $issuer")
        
        return super.generateApiKeyToken(clientId, partnerId, issuer, expirationMinutes)
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
        val issuer = "$apiBaseUrl/api/v1/oauth/token"
        
        // Log the token details for debugging
        println("Generating API key token with custom scopes: clientId=$clientId, partnerId=$partnerId")
        println("Issuer: $issuer")
        println("Scopes: ${scopes.joinToString(", ")}")
        
        return super.generateApiKeyTokenWithScopes(clientId, partnerId, scopes, issuer, expirationMinutes)
    }

    /**
     * Generate service role token with default Supabase issuer and debug logging
     */
    fun generateServiceRoleToken(role: String = "service_role"): String {
        val issuer = "$apiBaseUrl/auth/v1"
        
        // Log the token details for debugging
        println("Generating service role token: role=$role")
        println("Issuer: $issuer")
        
        return super.generateServiceRoleToken(role, issuer)
    }

}
