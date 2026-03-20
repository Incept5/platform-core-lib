package org.incept5.platform.core.model

/**
 * Represents a user role in the platform.
 *
 * This is a simple interface wrapping a role name string. The platform-core-lib
 * does not define or care about specific role names — role definitions live in
 * the consuming application's YAML configuration (authz-lib).
 *
 * The library's responsibility is to extract the role string from JWTs and pass
 * it through. Any mapping of legacy role names to new ones is handled by the
 * consuming application (e.g., via UserRoleMapper in fanfair-platform).
 */
interface UserRole {
    val value: String

    companion object {
        /**
         * Creates a UserRole from a raw string value.
         */
        fun of(value: String): UserRole = SimpleUserRole(value)
    }
}

/**
 * Default implementation of [UserRole].
 */
private data class SimpleUserRole(override val value: String) : UserRole {
    override fun toString(): String = value
}
