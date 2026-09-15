
package org.incept5.platform.core.auth

import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.ext.Provider
import org.incept5.platform.core.authz.ApiPrincipal
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.jboss.logging.Logger

/**
 * Filter that enforces OAuth scope-based authorization for endpoints annotated with @RequireScope.
 *
 * Scopes and client id are read from the [ApiPrincipal] that authz-lib's `AuthzFilter` has already
 * built from a **signature-verified** token (it runs earlier, at [Priorities.AUTHENTICATION]). This
 * filter never decodes the Authorization header itself. If no verified principal is present — which
 * is the case on any path the authz ignore list exempts — it **fails closed** with 401 rather than
 * trusting whatever claims an unverified token might carry.
 *
 * Works with API key / service tokens that carry a client id and explicit scopes. Verified user
 * tokens (from Supabase, no client id) bypass scope checks since they don't have scopes.
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

        // Only a principal that AuthzFilter built from a signature-verified token is trusted. On an
        // ignored path no token exchange runs and no principal is set, so we fail closed — never
        // read the header, or a hand-built unsigned token would be honoured (C1 finding, FF-3774).
        val principal = requestContext.securityContext?.userPrincipal as? ApiPrincipal
            ?: run {
                log.warn("Scope-guarded endpoint reached with no verified principal: ${requestContext.uriInfo.path}")
                throw UnauthorizedException("Authentication required")
            }

        val subject = principal.subject
        val clientId = principal.clientId

        // If scopeOnlyAuthorization is set, only client tokens (API key / service, with a clientId)
        // are allowed
        if (requireScope.scopeOnlyAuthorization && clientId.isNullOrEmpty()) {
            log.warn("Subject $subject tried to access endpoint which is only accessible with API Key issued tokens")
            throw ForbiddenException("Access denied: Endpoint only accessible with API Key issued tokens")
        }

        // Verified user tokens (no clientId) bypass scope checks — scopes only apply to client tokens
        if (clientId.isNullOrEmpty()) {
            log.debug("Bypassing scope check for authenticated user (no clientId)")
            return
        }

        log.debug("Checking scope authorization for client: $subject")

        val tokenScopes = principal.scopes
        log.debug("Token scopes: ${tokenScopes.joinToString(", ")}, Required: ${requireScope.value}")

        // Check if the required scope is present on the verified principal
        if (requireScope.value !in tokenScopes) {
            log.warn("Access denied: Client $subject does not have required scope '${requireScope.value}'. Available: ${tokenScopes.joinToString(", ")}")
            throw ForbiddenException("Access denied: Missing required scope '${requireScope.value}'")
        }

        log.debug("Scope authorization successful for client $subject")
    }
}
