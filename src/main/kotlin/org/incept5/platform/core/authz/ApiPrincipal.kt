package org.incept5.platform.core.authz

import org.incept5.authz.core.context.AssuranceLevel
import org.incept5.authz.core.context.PrincipalContext
import org.incept5.authz.core.model.EntityRole
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import java.util.UUID

/**
 * Rich principal returned by the token exchange plugin.
 *
 * Implements [PrincipalContext] (which extends [java.security.Principal]) so it
 * is available from both the authz-lib principal service and the standard
 * JAX-RS [jakarta.ws.rs.core.SecurityContext.getUserPrincipal].
 */
data class ApiPrincipal(
    val subject: String,
    val userRole: UserRole,
    val entityType: EntityType?,
    val entityId: String?,
    val scopes: List<String>,
    val clientId: String?,
    private val principalId: UUID,
    private val globalRoles: List<String>,
    private val entityRoles: List<EntityRole> = emptyList(),
    /**
     * Session assurance, mapped from the Supabase `aal` claim by the validator. Defaulted to
     * [AssuranceLevel.SINGLE_FACTOR] so existing constructors (all in tests) keep compiling.
     */
    private val assuranceLevel: AssuranceLevel = AssuranceLevel.SINGLE_FACTOR,
    /** True for platform-issued (API-key / service) tokens; exempts them from MFA enforcement. */
    private val machinePrincipal: Boolean = false,
) : PrincipalContext {

    override fun getName(): String = subject

    override fun getPrincipalId(): UUID = principalId

    override fun getGlobalRoles(): List<String> = globalRoles

    override fun getEntityRoles(): List<EntityRole> = entityRoles

    override fun getAssuranceLevel(): AssuranceLevel = assuranceLevel

    override fun isMachinePrincipal(): Boolean = machinePrincipal
}
