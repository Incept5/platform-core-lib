
package org.incept5.platform.core.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException
import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.ext.Provider
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.jboss.logging.Logger

/**
 * Filter that enforces OAuth scope-based authorization for endpoints annotated with @RequireScope.
 * This filter extracts scopes from JWT tokens and validates them against required scopes.
 *
 * Works with API key tokens that carry explicit scopes in the JWT claims.
 * User tokens (from Supabase) bypass scope checks since they don't have scopes.
 */
@Provider
@RequireScope("")
@Priority(Priorities.AUTHORIZATION + 1)
class ScopeAuthorizationFilter : ContainerRequestFilter {

    private val log = Logger.getLogger(ScopeAuthorizationFilter::class.java)

    @Context
    private lateinit var resourceInfo: ResourceInfo

    override fun filter(requestContext: ContainerRequestContext) {
        val method = resourceInfo.resourceMethod
        val requireScope = method.getAnnotation(RequireScope::class.java)
            ?: resourceInfo.resourceClass.getAnnotation(RequireScope::class.java)
            ?: return

        log.debug("Checking scope authorization for endpoint requiring scope: ${requireScope.value}")

        val authHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)
            ?: throw UnauthorizedException("No Authorization header present")

        if (!authHeader.startsWith("Bearer ", ignoreCase = true)) {
            throw UnauthorizedException("Invalid Authorization header format")
        }

        val token = authHeader.substring(7)
        val decodedJWT = try {
            JWT.decode(token)
        } catch (e: JWTDecodeException) {
            throw UnauthorizedException("Invalid token format")
        }

        val subject = decodedJWT.subject ?: "unknown"
        val clientId = decodedJWT.getClaim("clientId")?.asString()

        // If scopeOnlyAuthorization is set, only API key tokens (with clientId) are allowed
        if (requireScope.scopeOnlyAuthorization && clientId.isNullOrEmpty()) {
            log.warn("Subject $subject tried to access endpoint which is only accessible with API Key issued tokens")
            throw ForbiddenException("Access denied: Endpoint only accessible with API Key issued tokens")
        }

        // User tokens (no clientId) bypass scope checks — scopes only apply to API key tokens
        if (clientId.isNullOrEmpty()) {
            log.debug("Bypassing scope check for authenticated user (no clientId)")
            return
        }

        log.debug("Checking scope authorization for client: $subject")

        // Extract scopes from JWT token
        val tokenScopes = try {
            val scopesClaim = decodedJWT.getClaim("scopes")
            when {
                scopesClaim.isNull -> emptyList()
                scopesClaim.asArray(String::class.java) != null -> scopesClaim.asArray(String::class.java).toList()
                else -> emptyList()
            }
        } catch (e: Exception) {
            log.error("Error extracting scopes from token", e)
            throw UnauthorizedException("Error processing token")
        }

        log.debug("Token scopes: ${tokenScopes.joinToString(", ")}, Required: ${requireScope.value}")

        // Check if the required scope is present in the token
        if (requireScope.value !in tokenScopes) {
            log.warn("Access denied: Client $subject does not have required scope '${requireScope.value}'. Available: ${tokenScopes.joinToString(", ")}")
            throw ForbiddenException("Access denied: Missing required scope '${requireScope.value}'")
        }

        log.debug("Scope authorization successful for client $subject")
    }
}
