
package org.incept5.platform.core.security

import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import java.util.*

// use in tests
data class TestUser(
    val userRole: UserRole = UserRole.of("backoffice.admin"),
    val userId: UUID = UUID.randomUUID(),
    val firstName: String = "John",
    val lastName: String = "Doe",
    val entityId: String? = null,
    val entityType: EntityType? = null
)
