
package org.incept5.platform.core.auth

import jakarta.annotation.Priority
import jakarta.ws.rs.Priorities
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.ext.Provider
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.security.ApiPrincipal
import org.incept5.platform.core.security.AuthUtils
import org.jboss.logging.Logger

/**
 * Filter that enforces authentication and authorization based on the @Authenticated annotation.
 * This filter checks:
 * 1. If specific roles are required and the user has one of those roles
 * 2. If entity permission checking is required and the user has permission for the entity
 */
@Provider
@Authenticated
@Priority(Priorities.AUTHORIZATION)
class AuthenticationFilter : ContainerRequestFilter {
    private val log = Logger.getLogger(AuthenticationFilter::class.java)

    @Context
    private lateinit var resourceInfo: ResourceInfo

    override fun filter(requestContext: ContainerRequestContext) {
        val method = resourceInfo.resourceMethod
        val authenticated = method.getAnnotation(Authenticated::class.java)
            ?: resourceInfo.resourceClass.getAnnotation(Authenticated::class.java)
            ?: return

        val securityContext = requestContext.securityContext
        val principal = securityContext.userPrincipal as? ApiPrincipal
            ?: throw UnauthorizedException("Authentication required")

        log.debug("Checking authorization for user ${principal.subject} with role ${principal.userRole}")

        // Check if user has one of the allowed roles (if specified)
        if (authenticated.allowedRoles.isNotEmpty()) {
            val hasAllowedRole = authenticated.allowedRoles.any { role ->
                securityContext.isUserInRole(role)
            }

            if (!hasAllowedRole) {
                val roleNames = authenticated.allowedRoles.joinToString(", ")
                log.warn("Access denied: User ${principal.subject} with role ${principal.userRole} does not have any of the required roles: $roleNames")
                throw ForbiddenException("Access denied: User does not have the required permissions")
            }
        }

        // Check entity permissions if required
        if (authenticated.requiresEntityPermission && authenticated.entityIdParam.isNotBlank()) {
            val entityId = requestContext.uriInfo.pathParameters[authenticated.entityIdParam]
                ?: throw ForbiddenException("Entity ID parameter '${authenticated.entityIdParam}' not found in path parameters")

            log.debug("Checking entity permission for user ${principal.subject} with role ${principal.userRole}")
            log.debug("User entityId: ${(principal as? ApiPrincipal)?.entityId}, entityType: ${(principal as? ApiPrincipal)?.entityType}")
            log.debug("Required entityId: $entityId, entityType: ${authenticated.entityType}")

            val hasPermission = when (authenticated.entityType) {
                "partner" -> {
                    log.debug("Checking partner permission for user ${principal.subject}")
                    val result = AuthUtils.hasPermissionForPartner(securityContext, entityId.first())
                    log.debug("Partner permission check result: $result")
                    result
                }
                // Add more entity types as needed
                else -> {
                    log.debug("Using default partner permission check for entity type: ${authenticated.entityType}")
                    val result = AuthUtils.hasPermissionForPartner(securityContext, entityId.first())
                    log.debug("Default permission check result: $result")
                    result
                }
            }

            if (!hasPermission) {
                log.warn("Access denied: User ${principal.subject} with role ${principal.userRole} does not have permission for ${authenticated.entityType} $entityId")
                throw ForbiddenException("Access denied: User does not have the required permissions")
            } else {
                log.debug("User ${principal.subject} has permission for ${authenticated.entityType} $entityId")
            }
        }
    }
}
