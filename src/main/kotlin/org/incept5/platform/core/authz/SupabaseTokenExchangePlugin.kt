package org.incept5.platform.core.authz

import jakarta.inject.Singleton
import org.incept5.authz.core.context.DefaultPrincipalContext
import org.incept5.authz.core.context.PrincipalContext
import org.incept5.authz.core.model.EntityRole
import org.incept5.authz.core.service.TokenExchangePlugin
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.security.DualJwtValidator
import org.incept5.platform.core.security.TokenValidationResult
import org.jboss.logging.Logger
import java.util.UUID

/**
 * Bridges the existing DualJwtValidator to authz-lib's PrincipalContext model.
 *
 * Validates the incoming JWT token using the existing validator and maps the
 * result to a PrincipalContext with appropriate global roles and entity roles.
 */
@Singleton
class SupabaseTokenExchangePlugin(
    private val dualJwtValidator: DualJwtValidator
) : TokenExchangePlugin {

    private val log = Logger.getLogger(SupabaseTokenExchangePlugin::class.java)

    override fun exchangeToken(token: String): PrincipalContext? {
        val result = try {
            dualJwtValidator.validateToken(token)
        } catch (e: Exception) {
            log.debug("Token validation failed: ${e.message}")
            return null
        }

        val principalId = try {
            UUID.fromString(result.subject)
        } catch (e: IllegalArgumentException) {
            // Some tokens (e.g., service_role) may not have a UUID subject.
            // Generate a deterministic UUID from the subject string.
            UUID.nameUUIDFromBytes(result.subject.toByteArray())
        }

        val globalRole = mapRole(result.userRole, result.entityType)
        val entityRoles = buildEntityRoles(result)

        log.debug("Token exchanged: subject=${result.subject}, globalRole=$globalRole, entityRoles=$entityRoles")

        return DefaultPrincipalContext(
            principalId = principalId,
            globalRoles = listOf(globalRole),
            entityRoles = entityRoles
        )
    }

    /**
     * Maps the existing UserRole + EntityType combination to an authz-lib role name.
     */
    internal fun mapRole(userRole: UserRole, entityType: EntityType?): String = when (userRole) {
        UserRole.platform_admin, UserRole.service_role -> "backoffice.admin"
        UserRole.entity_admin -> when (entityType) {
            EntityType.partner -> "partner.admin"
            EntityType.merchant -> "merchant.admin"
            else -> "partner.user"
        }
        UserRole.entity_user -> when (entityType) {
            EntityType.partner -> "partner.user"
            EntityType.merchant -> "merchant.user"
            else -> "partner.user"
        }
        UserRole.entity_readonly -> when (entityType) {
            EntityType.partner -> "partner.user"
            EntityType.merchant -> "merchant.user"
            else -> "partner.user"
        }
    }

    /**
     * Builds entity-scoped roles from the token validation result.
     * Only created when both entityType and entityId are present.
     */
    private fun buildEntityRoles(result: TokenValidationResult): List<EntityRole> {
        if (result.entityType == null || result.entityId == null) return emptyList()

        val roleName = mapRole(result.userRole, result.entityType)
        return listOf(
            EntityRole(
                type = result.entityType!!.name.lowercase(),
                roles = listOf(roleName),
                ids = listOf(result.entityId!!)
            )
        )
    }
}
