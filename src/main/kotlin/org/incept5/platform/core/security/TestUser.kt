
package org.incept5.platform.core.security

import java.util.*

// use in tests
data class TestUser(
    val userRole: String = "platform_admin",
    val userId: UUID = UUID.randomUUID(),
    val firstName: String = "John",
    val lastName: String = "Doe",
    val entityId: String? = null,
    val entityType: String? = null
)
