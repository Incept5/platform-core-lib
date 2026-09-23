package org.incept5.platform.core.authz

import org.incept5.authz.core.context.PrincipalContext
import org.incept5.authz.core.model.EntityRole
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.security.TokenSource
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
     * Supabase `aal` claim ("aal1"/"aal2"), or null for platform tokens / a token without the
     * claim. Read by [AssuranceLevelFilter] to require a verified second factor for configured roles.
     * Defaulted so existing constructors (all in tests) keep compiling.
     */
    val authenticatorAssuranceLevel: String? = null,
    /** Which validator produced this principal; lets MFA enforcement exempt platform tokens. */
    val tokenSource: TokenSource? = null,
) : PrincipalContext {

    override fun getName(): String = subject

    override fun getPrincipalId(): UUID = principalId

    override fun getGlobalRoles(): List<String> = globalRoles

    override fun getEntityRoles(): List<EntityRole> = entityRoles
}
