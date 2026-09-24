
package org.incept5.platform.core.security

import org.incept5.authz.core.context.AssuranceLevel
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole

data class TokenValidationResult(
    val isValid: Boolean,
    val subject: String,
    val userRole: UserRole,
    val entityType: EntityType? = null,
    val entityId: String? = null,
    val scopes: List<String> = emptyList(),
    val clientId: String? = null,
    val errorMessage: String? = null,
    /**
     * Session assurance, provider-neutral. The validator maps the identity provider's own claim onto
     * this (Supabase `aal2` -> [AssuranceLevel.MULTI_FACTOR], otherwise [AssuranceLevel.SINGLE_FACTOR]);
     * it is carried onto [org.incept5.platform.core.authz.ApiPrincipal] so authz-lib's
     * `AssuranceLevelFilter` can enforce MFA without knowing any provider's claim names.
     */
    val assuranceLevel: AssuranceLevel = AssuranceLevel.SINGLE_FACTOR,
    /**
     * True for a platform-issued credential — an API key or service-to-service token. Such
     * principals are machine principals and are never subject to MFA, whatever roles they carry.
     */
    val machinePrincipal: Boolean = false,
) {
    companion object {
        fun valid(
            subject: String,
            userRole: UserRole,
            entityType: EntityType?,
            entityId: String?,
            scopes: List<String> = emptyList(),
            clientId: String? = null,
            assuranceLevel: AssuranceLevel = AssuranceLevel.SINGLE_FACTOR,
            machinePrincipal: Boolean = false,
        ) = TokenValidationResult(
            isValid = true,
            subject = subject,
            userRole = userRole,
            entityType = entityType,
            entityId = entityId,
            scopes = scopes,
            clientId = clientId,
            assuranceLevel = assuranceLevel,
            machinePrincipal = machinePrincipal,
        )
    }
}


enum class TokenSource {
    SUPABASE, PLATFORM
}
