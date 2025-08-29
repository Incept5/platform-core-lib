
package org.incept5.platform.core.security

import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.model.EntityType

data class TokenValidationResult(
    val isValid: Boolean,
    val subject: String,
    val userRole: UserRole,
    val entityType: EntityType? = null,
    val entityId: String? = null,
    val scopes: List<String> = emptyList(),
    val clientId: String? = null,
    val errorMessage: String? = null
) {
    companion object {
        fun valid(
            subject: String,
            userRole: UserRole,
            entityType: EntityType?,
            entityId: String?,
            scopes: List<String> = emptyList(),
            clientId: String? = null,
            tokenSource: TokenSource
        ) = TokenValidationResult(
            isValid = true,
            subject = subject,
            userRole = userRole,
            entityType = entityType,
            entityId = entityId,
            scopes = scopes,
            clientId = clientId,
        )
    }
}


enum class TokenSource {
    SUPABASE, PLATFORM
}
