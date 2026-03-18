
package org.incept5.platform.core.security

import org.incept5.platform.core.model.UserRole
import java.util.*

// use in tests
data class TestUser(
    val userRole: UserRole = UserRole.BACKOFFICE_ADMIN,
    val userId: UUID = UUID.randomUUID(),
    val firstName: String = "John",
    val lastName: String = "Doe",
    val entityId: String? = null,
    val entityType: String? = null
)
