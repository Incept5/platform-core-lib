package org.incept5.platform.core.authz

import jakarta.inject.Singleton
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
 * Legacy role mapping (platform_admin → backoffice.admin etc.) lives here
 * because the DualJwtValidator passes raw JWT role strings through without
 * interpretation — role name knowledge belongs in the consuming application,
 * not in the core library.
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

        val globalRole = mapRole(result.userRole.value, result.entityType)
        val entityRoles = buildEntityRoles(result, globalRole)

        log.debug("Token exchanged: subject=${result.subject}, globalRole=$globalRole, entityRoles=$entityRoles")

        return ApiPrincipal(
            subject = result.subject,
            userRole = result.userRole,
            entityType = result.entityType,
            entityId = result.entityId,
            scopes = result.scopes,
            clientId = result.clientId,
            principalId = principalId,
            globalRoles = listOf(globalRole),
            entityRoles = entityRoles
        )
    }

    /**
     * Maps JWT role strings to authz-lib role names.
     * Handles both legacy (platform_admin, entity_admin, etc.) and new role names (pass-through).
     */
    internal fun mapRole(role: String, entityType: String?): String = when (role) {
        "platform_admin" -> "backoffice.admin"
        "service_role" -> "service.admin"
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
        // New role names pass through unchanged
        else -> role
    }

    /**
     * Builds entity-scoped roles from the token validation result.
     * Only created when both entityType and entityId are present.
     */
    private fun buildEntityRoles(result: TokenValidationResult, mappedRole: String): List<EntityRole> {
        if (result.entityType == null || result.entityId == null) return emptyList()

        return listOf(
            EntityRole(
                type = result.entityType!!.lowercase(),
                roles = listOf(mappedRole),
                ids = listOf(result.entityId!!)
            )
        )
    }
}
