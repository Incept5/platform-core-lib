
package org.incept5.platform.core.security

import jakarta.ws.rs.core.SecurityContext
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.jboss.logging.Logger

/**
 * Utility class for authorization checks.
 */
class AuthUtils {
    companion object {
        private val log = Logger.getLogger(AuthUtils::class.java)

        /**
         * Checks if the user has the platform_admin role.
         *
         * @param securityContext The security context
         * @return true if the user has the platform_admin role, false otherwise
         */
        fun isPlatformAdmin(securityContext: SecurityContext): Boolean {
            return securityContext.isUserInRole(UserRole.platform_admin.name)
        }

        /**
         * Checks if the user has the entity_admin role.
         *
         * @param securityContext The security context
         * @return true if the user has the entity_admin role, false otherwise
         */
        fun isEntityAdmin(securityContext: SecurityContext): Boolean {
            return securityContext.isUserInRole(UserRole.entity_admin.name)
        }

        /**
         * Checks if the user has the entity_admin role and belongs to the specified entity.
         *
         * @param securityContext The security context
         * @param entityId The entity ID to check against
         * @return true if the user is an admin of the specified entity, false otherwise
         */
        fun isEntityAdminForEntity(securityContext: SecurityContext, entityId: String): Boolean {
            if (!isEntityAdmin(securityContext)) {
                return false
            }

            val principal = securityContext.userPrincipal as? ApiPrincipal ?: return false
            return principal.entityId == entityId
        }

        /**
         * Checks if the user has the platform_admin role or is an admin of the specified entity.
         *
         * @param securityContext The security context
         * @param entityId The entity ID to check against
         * @return true if the user is a platform admin or an admin of the specified entity, false otherwise
         */
        fun isPlatformAdminOrEntityAdmin(securityContext: SecurityContext, entityId: String): Boolean {
            return isPlatformAdmin(securityContext) || isEntityAdminForEntity(securityContext, entityId)
        }

        /**
         * Checks if the user has permission to access the specified partner's resources.
         * User must be either a platform_admin or an entity_admin of the specified partner.
         *
         * @param securityContext The security context
         * @param partnerId The ID of the partner to check access for
         * @return true if the user has permission, false otherwise
         */
        fun hasPermissionForPartner(securityContext: SecurityContext, partnerId: String): Boolean {
            val principal = securityContext.userPrincipal as? ApiPrincipal
            val userRole = principal?.userRole
            val entityId = principal?.entityId
            val entityType = principal?.entityType

            log.info("Checking permission for partner: $partnerId")
            log.info("User details - Role: $userRole, EntityId: $entityId, EntityType: $entityType")

            // Check if user is a platform admin
            if (isPlatformAdmin(securityContext)) {
                log.info("User is platform admin, granting permission")
                return true
            }

            // Check if user is an entity admin for the specified partner
            if (isEntityAdmin(securityContext)) {
                log.info("User is entity admin, checking entity ID match")

                // Fix: Check if entityType is partner and entityId matches partnerId
                val hasPermission = entityType == EntityType.partner && entityId == partnerId
                log.info("Entity ID match result: $hasPermission (User EntityId: $entityId, EntityType: $entityType, Required PartnerId: $partnerId)")
                return hasPermission
            }

            log.info("User does not have required role, denying permission")
            return false
        }

        /**
         * Ensures that the user has permission to access the specified partner's resources.
         * Throws a ForbiddenException if the user does not have the required permissions.
         *
         * @param securityContext The security context
         * @param partnerId The ID of the partner to check access for
         * @throws ForbiddenException if the user does not have the required permissions
         */
        fun ensurePermissionForPartner(securityContext: SecurityContext, partnerId: String) {
            if (!hasPermissionForPartner(securityContext, partnerId)) {
                log.warn("Access denied: User ${securityContext.userPrincipal.name} attempted to access partner $partnerId without proper permissions")
                throw ForbiddenException("You do not have permission to perform this action")
            }

            log.debug("User ${securityContext.userPrincipal.name} authorized to access partner $partnerId")
        }

        /**
         * Ensures that the user has the platform_admin role or is an admin of the specified entity.
         * Throws a ForbiddenException if the user does not have the required permissions.
         *
         * @param securityContext The security context
         * @param entityId The entity ID to check against
         * @throws ForbiddenException if the user does not have the required permissions
         */
        fun ensurePlatformAdminOrEntityAdmin(securityContext: SecurityContext, entityId: String) {
            if (!isPlatformAdminOrEntityAdmin(securityContext, entityId)) {
                log.warn("Access denied: User ${securityContext.userPrincipal.name} attempted to access entity $entityId without proper permissions")
                throw ForbiddenException("You do not have permission to perform this action")
            }
        }

        /**
         * Ensures that the user has the platform_admin role.
         * Throws a ForbiddenException if the user does not have the required permissions.
         *
         * @param securityContext The security context
         * @throws ForbiddenException if the user is not a platform admin
         */
        fun ensurePlatformAdmin(securityContext: SecurityContext) {
            if (!isPlatformAdmin(securityContext)) {
                log.warn("Access denied: User ${securityContext.userPrincipal.name} attempted to perform a platform admin action")
                throw ForbiddenException("Only platform administrators can perform this action")
            }
        }

        /**
         * Gets the entity type of the current user.
         *
         * @param securityContext The security context
         * @return The entity type or null if not available
         */
        fun getEntityType(securityContext: SecurityContext): EntityType? {
            val principal = securityContext.userPrincipal as? ApiPrincipal ?: return null
            return principal.entityType
        }

        /**
         * Gets the entity ID of the current user.
         *
         * @param securityContext The security context
         * @return The entity ID or null if not available
         */
        fun getEntityId(securityContext: SecurityContext): String? {
            val principal = securityContext.userPrincipal as? ApiPrincipal ?: return null
            return principal.entityId
        }

        /**
         * Gets the user role of the current user.
         *
         * @param securityContext The security context
         * @return The user role or null if not available
         */
        fun getUserRole(securityContext: SecurityContext): UserRole? {
            val principal = securityContext.userPrincipal as? ApiPrincipal ?: return null
            return principal.userRole
        }
    }
}
