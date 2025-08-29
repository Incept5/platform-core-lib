
package org.incept5.platform.core.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.exceptions.JWTDecodeException
import jakarta.annotation.Priority
import jakarta.ws.rs.ForbiddenException
import jakarta.ws.rs.NotAuthorizedException
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.ext.Provider
import org.incept5.platform.core.error.ApiException
import org.incept5.platform.core.security.ApiPrincipal
import org.incept5.error.ErrorCategory
import org.jboss.logging.Logger

/**
 * Filter that enforces OAuth scope-based authorization for endpoints annotated with @RequireScope.
 * This filter extracts scopes from JWT tokens and validates them against required scopes.
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

        val securityContext = requestContext.securityContext
        val principal = securityContext.userPrincipal as? ApiPrincipal
            ?: throw NotAuthorizedException("No authentication present")

        if (requireScope.scopeOnlyAuthorization && principal.clientId.isNullOrEmpty()) {
            log.debug("Endpoint only accessible with API Key issued tokens")
            throw ApiException("Access denied: User ${principal.subject} not allowed access. Use tokens issues by a valid API Key instead",
                ErrorCategory.AUTHORIZATION)
        }
        if (principal.clientId.isNullOrEmpty()) { //only tokens issued with API Key have scopes
            log.debug("bypassing scope check for authenticated user")
            return
        }

        log.debug("Checking scope authorization for user: ${principal.subject}")

        // Extract scopes from JWT token
        val tokenScopes = extractScopesFromToken(requestContext)

        log.debug("Token scopes: ${tokenScopes.joinToString(", ")}")
        log.debug("Required scope: ${requireScope.value}")

        // Check if the required scope is present in the token
        if (requireScope.value !in tokenScopes) {
            log.warn("Access denied: User ${principal.subject} does not have required scope '${requireScope.value}'. Available scopes: ${tokenScopes.joinToString(", ")}")
            throw ApiException("The request requires higher privileges than provided by the access token",
                ErrorCategory.AUTHORIZATION)
        }

        log.debug("Scope authorization successful for user ${principal.subject}")
    }

    /**
     * Extracts scopes from the JWT token in the Authorization header
     *
     * @param requestContext The request context containing the Authorization header
     * @return List of scopes from the token
     * @throws ForbiddenException if the token cannot be decoded or scopes cannot be extracted
     */
    private fun extractScopesFromToken(requestContext: ContainerRequestContext): List<String> {
        val authHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION)
            ?: throw ForbiddenException("No Authorization header present")

        if (!authHeader.startsWith("Bearer ", ignoreCase = true)) {
            throw ForbiddenException("Invalid Authorization header format")
        }

        val token = authHeader.substring(7)

        return try {
            val decodedJWT = JWT.decode(token)
            val scopesClaim = decodedJWT.getClaim("scopes")

            when {
                scopesClaim.isNull -> {
                    log.debug("No scopes claim found in token")
                    emptyList()
                }
                scopesClaim.asArray(String::class.java) != null -> {
                    val scopes = scopesClaim.asArray(String::class.java).toList()
                    log.debug("Extracted scopes from token: ${scopes.joinToString(", ")}")
                    scopes
                }
                else -> {
                    log.warn("Scopes claim is not an array in token")
                    emptyList()
                }
            }
        } catch (e: JWTDecodeException) {
            log.error("Failed to decode JWT token for scope extraction", e)
            throw ForbiddenException("Invalid token format")
        } catch (e: Exception) {
            log.error("Error extracting scopes from token", e)
            throw ForbiddenException("Error processing token")
        }
    }
}
