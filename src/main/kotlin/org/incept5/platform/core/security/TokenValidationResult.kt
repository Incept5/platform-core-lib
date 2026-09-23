
package org.incept5.platform.core.security

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
     * Supabase authenticator assurance level (`aal` claim): `"aal1"` after a password grant,
     * `"aal2"` after a verified TOTP challenge. Null for platform (API-key/service) tokens, which
     * carry no `aal`, and for any Supabase token missing the claim. Consumed by
     * [org.incept5.platform.core.authz.AssuranceLevelFilter] to enforce server-side MFA.
     */
    val authenticatorAssuranceLevel: String? = null,
    /**
     * Which validator produced this result. Lets downstream enforcement exempt platform-issued
     * tokens (API keys, service) from user-session controls such as MFA.
     */
    val tokenSource: TokenSource? = null,
) {
    companion object {
        fun valid(
            subject: String,
            userRole: UserRole,
            entityType: EntityType?,
            entityId: String?,
            scopes: List<String> = emptyList(),
            clientId: String? = null,
            tokenSource: TokenSource,
            authenticatorAssuranceLevel: String? = null,
        ) = TokenValidationResult(
            isValid = true,
            subject = subject,
            userRole = userRole,
            entityType = entityType,
            entityId = entityId,
            scopes = scopes,
            clientId = clientId,
            authenticatorAssuranceLevel = authenticatorAssuranceLevel,
            tokenSource = tokenSource,
        )
    }
}


enum class TokenSource {
    SUPABASE, PLATFORM
}
