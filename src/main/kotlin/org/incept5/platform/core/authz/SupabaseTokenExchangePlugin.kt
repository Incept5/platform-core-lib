package org.incept5.platform.core.authz

import jakarta.inject.Singleton
import org.incept5.authz.core.context.DefaultPrincipalContext
import org.incept5.authz.core.context.PrincipalContext
import org.incept5.authz.core.model.EntityRole
import org.incept5.authz.core.service.TokenExchangePlugin
import org.incept5.platform.core.security.DualJwtValidator
import org.incept5.platform.core.security.TokenValidationResult
import org.jboss.logging.Logger
import java.util.UUID

/**
 * Bridges the existing DualJwtValidator to authz-lib's PrincipalContext model.
 *
 * Validates the incoming JWT token using the existing validator and maps the
 * result to a PrincipalContext with appropriate global roles and entity roles.
 *
 * Note: Legacy role mapping (platform_admin → backoffice.admin etc.) is now
 * handled by DualJwtValidator via UserRole.fromLegacy(). This plugin simply
 * converts the validated result to a PrincipalContext.
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
            UUID.nameUUIDFromBytes(result.subject.toByteArray())
        }

        val globalRole = result.userRole.value
        val entityRoles = buildEntityRoles(result)

        log.debug("Token exchanged: subject=${result.subject}, globalRole=$globalRole, entityRoles=$entityRoles")

        return DefaultPrincipalContext(
            principalId = principalId,
            globalRoles = listOf(globalRole),
            entityRoles = entityRoles
        )
    }

    /**
     * Builds entity-scoped roles from the token validation result.
     * Only created when both entityType and entityId are present.
     */
    private fun buildEntityRoles(result: TokenValidationResult): List<EntityRole> {
        if (result.entityType == null || result.entityId == null) return emptyList()

        return listOf(
            EntityRole(
                type = result.entityType!!.lowercase(),
                roles = listOf(result.userRole.value),
                ids = listOf(result.entityId!!)
            )
        )
    }
}
