package org.incept5.platform.core.authz

import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.ext.Provider
import org.incept5.platform.core.security.TokenSource
import org.jboss.logging.Logger

/**
 * Enforces server-side MFA: refuses a Supabase user token that holds a configured role but is not
 * `aal2` (verified TOTP), with **403 `MFA_REQUIRED`** (see [MfaRequiredException]).
 *
 * Runs at [Priorities.AUTHENTICATION] + 1, i.e. **after** authz-lib's `AuthzFilter`
 * ([Priorities.AUTHENTICATION]) has exchanged the signature-verified token and installed the
 * [ApiPrincipal] on the JAX-RS `SecurityContext`, and **before** `ScopeAuthorizationFilter`
 * ([Priorities.AUTHORIZATION] + 1). It only *reads* the already-verified principal; it never
 * decodes the Authorization header itself.
 *
 * Unlike `ScopeAuthorizationFilter` (name-bound via `@RequireScope`), this is an unbound global
 * provider that sees every request, so each guard clause below fails open for requests it does not
 * govern: no configured roles, no verified principal, a platform (API-key/service) token, or a
 * principal whose roles are not in the required set. A missing `aal` claim counts as single-factor.
 */
@Provider
@Priority(Priorities.AUTHENTICATION + 1)
class AssuranceLevelFilter(
    private val config: MfaEnforcementConfig,
) : ContainerRequestFilter {

    private val log = Logger.getLogger(AssuranceLevelFilter::class.java)

    /** Roles requiring aal2. Parsed once; blanks (from an unset `@WithDefault("")`) dropped. */
    private val requiredRoles: Set<String> =
        config.aal2RequiredRoles().filter { it.isNotBlank() }.toSet()

    /** Endpoints a single-factor holder of a required role may still reach. Parsed once at build. */
    private val allowedEndpoints: Set<Endpoint> =
        config.aal1AllowedEndpoints().filter { it.isNotBlank() }.map(::parseEndpoint).toSet()

    override fun filter(requestContext: ContainerRequestContext) {
        // AC2: nothing configured -> the library changes no behaviour.
        if (requiredRoles.isEmpty()) return

        // AC9: an ignored/public path never gets a principal (AuthzFilter returns early) -> pass.
        val principal = requestContext.securityContext?.userPrincipal as? ApiPrincipal ?: return

        // AC8: API-key and service tokens are PLATFORM-issued and carry no aal -> never refused here.
        if (principal.tokenSource != TokenSource.SUPABASE) return

        // Only principals actually holding a configured role are governed.
        val roles = principal.getGlobalRoles() + principal.getEntityRoles().flatMap { it.roles }
        if (roles.none { it in requiredRoles }) return

        // AC1: a verified second factor passes untouched.
        if (principal.authenticatorAssuranceLevel == "aal2") return

        // AC3: a single-factor user may still reach explicitly allow-listed endpoints (exact match).
        val endpoint = Endpoint(
            requestContext.method.uppercase(),
            "/" + requestContext.uriInfo.path.trimStart('/'),
        )
        if (endpoint in allowedEndpoints) return

        // AC5/AC6/AC7: refuse — aal1, missing aal, or a legacy role mapped onto a required role.
        log.warn(
            "MFA_REQUIRED: refusing single-factor session subject=${principal.subject} " +
                "aal=${principal.authenticatorAssuranceLevel} ${endpoint.method} ${endpoint.path}",
        )
        throw MfaRequiredException()
    }

    /**
     * Parse a `METHOD /path` allow-list entry. Throws (failing filter construction, and therefore
     * application start) on anything that is not exactly a method plus an absolute path — so a typo
     * cannot silently widen the single-factor surface.
     */
    private fun parseEndpoint(entry: String): Endpoint {
        val parts = entry.trim().split(WHITESPACE)
        require(parts.size == 2 && parts[0].isNotBlank() && parts[1].startsWith("/")) {
            "Invalid auth.mfa.aal1-allowed-endpoints entry '$entry': expected 'METHOD /path'"
        }
        return Endpoint(parts[0].uppercase(), parts[1])
    }

    /** An HTTP method + absolute request path, compared for exact equality. */
    data class Endpoint(val method: String, val path: String)

    private companion object {
        private val WHITESPACE = Regex("\\s+")
    }
}
