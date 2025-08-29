
package org.incept5.platform.core.model

enum class UserRole {
    // super admin role
    platform_admin,
    service_role,

    // partner/customer/merchant etc
    entity_admin,
    entity_user,
    entity_readonly,
}
