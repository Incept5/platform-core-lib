
package org.incept5.platform.core.security

import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.model.EntityType
import java.security.Principal

class ApiPrincipal(
    val subject: String,
    val userRole: UserRole,
    val entityType: EntityType? = null,
    val entityId: String? = null,
    val scopes: List<String> = emptyList(),
    val clientId: String? = ""
) : Principal {
    override fun getName(): String = subject

}
