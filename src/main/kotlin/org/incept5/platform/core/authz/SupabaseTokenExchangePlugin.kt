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

        val globalRole = mapRole(result.userRole.value, result.entityType)
        val entityRoles = buildEntityRoles(result)

        log.debug("Token exchanged: subject=${result.subject}, globalRole=$globalRole, entityRoles=$entityRoles")

        return DefaultPrincipalContext(
            principalId = principalId,
            globalRoles = listOf(globalRole),
            entityRoles = entityRoles
        )
    }

    /**
     * Maps JWT role string + entity type string to an authz-lib role name.
     * Handles both old role names (from Supabase JWT) and new role names (pass-through).
     */
    internal fun mapRole(userRole: String, entityType: String?): String = when (userRole) {
        "platform_admin", "service_role" -> "backoffice.admin"
        "entity_admin" -> when (entityType) {
            "partner" -> "partner.admin"
            "merchant" -> "merchant.admin"
            else -> "partner.user"
        }
        "entity_user" -> when (entityType) {
            "partner" -> "partner.user"
            "merchant" -> "merchant.user"
            else -> "partner.user"
        }
        "entity_readonly" -> when (entityType) {
            "partner" -> "partner.user"
            "merchant" -> "merchant.user"
            else -> "partner.user"
        }
        // Pass-through for new role names (already mapped)
        else -> userRole
    }

    /**
     * Builds entity-scoped roles from the token validation result.
     * Only created when both entityType and entityId are present.
     */
    private fun buildEntityRoles(result: TokenValidationResult): List<EntityRole> {
        if (result.entityType == null || result.entityId == null) return emptyList()

        val roleName = mapRole(result.userRole.value, result.entityType)
        return listOf(
            EntityRole(
                type = result.entityType!!.lowercase(),
                roles = listOf(roleName),
                ids = listOf(result.entityId!!)
            )
        )
    }
}
