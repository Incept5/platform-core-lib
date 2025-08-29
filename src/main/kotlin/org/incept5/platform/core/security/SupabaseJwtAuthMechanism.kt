
package org.incept5.platform.core.security

import io.quarkus.security.identity.IdentityProviderManager
import io.quarkus.security.identity.SecurityIdentity
import io.quarkus.security.identity.request.AuthenticationRequest
import io.quarkus.security.runtime.QuarkusSecurityIdentity
import io.smallrye.mutiny.Uni
import jakarta.enterprise.context.ApplicationScoped
import jakarta.ws.rs.core.SecurityContext
import org.incept5.platform.core.model.UserRole
import java.security.Principal
import jakarta.ws.rs.core.HttpHeaders
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism
import io.quarkus.vertx.http.runtime.security.ChallengeData
import io.vertx.ext.web.RoutingContext
import jakarta.annotation.Priority
import jakarta.inject.Inject
import jakarta.ws.rs.Priorities
import org.jboss.logging.Logger
import java.util.UUID
import com.auth0.jwt.JWT

@ApplicationScoped
@Priority(Priorities.AUTHENTICATION-1) // <-- DO NOT REMOVE THIS LINE
class SupabaseJwtAuthMechanism @Inject constructor(
    private val jwtValidator: DualJwtValidator
) : HttpAuthenticationMechanism {
    private val log = Logger.getLogger(SupabaseJwtAuthMechanism::class.java)

    companion object {
        val SERVICE_ROLE_USER_ID = UUID.fromString("00000000-0000-0000-0000-000000000000")
    }

    override fun authenticate(
        context: RoutingContext,
        identityProviderManager: IdentityProviderManager
    ): Uni<SecurityIdentity> {
        // Skip authentication for health checks
        if ( context.request().path().startsWith("/health")) {
            return Uni.createFrom().nullItem()
        }

        log.debug("Authenticating request")
        val authHeader = context.request().getHeader(HttpHeaders.AUTHORIZATION)
        if (authHeader == null) {
            log.warn("Authentication failed: No Authorization header present for path: ${context.request().path()}")
            return Uni.createFrom().nullItem()
        }
        if (!authHeader.startsWith("Bearer ") && !authHeader.startsWith("bearer ")) {
            log.warn("Authentication failed: Authorization header does not start with 'Bearer ' for path: ${context.request().path()}")
            return Uni.createFrom().nullItem()
        }

        return try {
            val token = authHeader.substring(7)
            val validToken = jwtValidator.validateToken(token)

            log.debug("Valid token received with Role: ${validToken.userRole?.name}")

            val role = validToken.userRole

            if (role == UserRole.service_role) {
                createServiceRoleIdentity()
            } else {
                createUserIdentity(validToken)
            }
        } catch (e: Exception) {
            log.warn("Authentication failed: ${e.message}", e)
            Uni.createFrom().nullItem()
        }
    }

    private fun createServiceRoleIdentity(): Uni<SecurityIdentity> {
        val principal = ApiPrincipal(
            subject = SERVICE_ROLE_USER_ID.toString(),
            userRole = UserRole.platform_admin
        )
        val securityContext = SupabaseSecurityContext(principal)

        log.debug("Service role authentication successful")

        return Uni.createFrom().item(
            QuarkusSecurityIdentity.builder()
                .setPrincipal(securityContext.userPrincipal)
                .addRole(UserRole.platform_admin.name)
                .build()
        )
    }

    private fun createUserIdentity(validationResult: TokenValidationResult): Uni<SecurityIdentity> {


        val principal = ApiPrincipal(
            subject = validationResult.subject,
            userRole = validationResult.userRole,
            entityType = validationResult.entityType,
            entityId = validationResult.entityId,
            clientId = validationResult.clientId
        )
        val securityContext = SupabaseSecurityContext(principal)

        log.debug("User authentication successful for subject: ${principal.subject} with role: ${principal.userRole}")

        return Uni.createFrom().item(
            QuarkusSecurityIdentity.builder()
                .setPrincipal(securityContext.userPrincipal)
                .addRole(principal.userRole.name)
                .build()
        )
    }

    override fun getChallenge(context: RoutingContext): Uni<ChallengeData> {
        log.info("Sending authentication challenge - unauthorized request")
        return Uni.createFrom().item(
            ChallengeData(
                401,
                "WWW-Authenticate",
                "Bearer realm=\"Supabase\", charset=\"UTF-8\""
            )
        )
    }

    override fun getCredentialTypes(): Set<Class<out AuthenticationRequest>> = emptySet()
}

class SupabaseSecurityContext(
    private val principal: ApiPrincipal
) : SecurityContext {
    override fun getUserPrincipal(): Principal = principal

    override fun isUserInRole(role: String): Boolean {
        return principal.userRole.name == role
    }

    override fun isSecure(): Boolean = true

    override fun getAuthenticationScheme(): String = "Bearer"
}
