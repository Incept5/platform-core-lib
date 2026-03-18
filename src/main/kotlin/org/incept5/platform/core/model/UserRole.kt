package org.incept5.platform.core.model

/**
 * Represents a user role in the platform. Roles are defined in the authz-lib YAML
 * configuration and mapped at runtime by [SupabaseTokenExchangePlugin].
 *
 * This is a value-type wrapper around a role name string, providing type safety
 * without hardcoding role definitions as an enum. Role names follow the
 * "domain.level" convention (e.g., partner.admin, merchant.user).
 *
 * Well-known constants are provided for roles referenced in code, but the system
 * accepts any role string from the configuration — new roles can be added to YAML
 * without code changes.
 */
data class UserRole(val value: String) {

    override fun toString(): String = value

    companion object {
        // New hierarchical role names (from authz-lib YAML config)
        val BACKOFFICE_ADMIN = UserRole("backoffice.admin")
        val PARTNER_ADMIN = UserRole("partner.admin")
        val PARTNER_USER = UserRole("partner.user")
        val MERCHANT_ADMIN = UserRole("merchant.admin")
        val MERCHANT_USER = UserRole("merchant.user")

        // Legacy role names (from Supabase JWT claims — mapped by SupabaseTokenExchangePlugin)
        val PLATFORM_ADMIN = UserRole("platform_admin")
        val SERVICE_ROLE = UserRole("service_role")
        val ENTITY_ADMIN = UserRole("entity_admin")
        val ENTITY_USER = UserRole("entity_user")
        val ENTITY_READONLY = UserRole("entity_readonly")

        /**
         * Creates a UserRole from a raw string value.
         * Accepts both legacy (platform_admin) and new (backoffice.admin) role names.
         */
        fun of(value: String) = UserRole(value)
    }
}
