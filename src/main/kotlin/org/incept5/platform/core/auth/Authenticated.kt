
package org.incept5.platform.core.auth

import jakarta.ws.rs.NameBinding
import org.incept5.platform.core.model.UserRole

/**
 * Annotation for securing endpoints with authentication and optional role-based authorization.
 *
 * @property allowedRoles The roles that are allowed to access the endpoint. If empty, any authenticated user can access.
 * @property requiresEntityPermission If true, the user must have permission for the entity specified in the path parameter.
 * @property entityIdParam The name of the path parameter that contains the entity ID to check permissions against.
 * @property entityType The type of entity to check permissions against (e.g., "partner", "merchant").
 */
@NameBinding
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
annotation class Authenticated(
    val allowedRoles: Array<String> = [],
    val requiresEntityPermission: Boolean = false,
    val entityIdParam: String = "",
    val entityType: String = ""
)
