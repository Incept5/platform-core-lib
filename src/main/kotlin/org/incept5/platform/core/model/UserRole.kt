package org.incept5.platform.core.model

/**
 * Represents a user role in the platform. Roles are defined in the authz-lib YAML
 * configuration and mapped at runtime by SupabaseTokenExchangePlugin.
 *
 * This is an interface so that role definitions are not hardcoded — the system
 * accepts any role populated from configuration. Role names follow the
 * "domain.level" convention (e.g., partner.admin, merchant.user).
 *
 * Well-known constants are provided for roles referenced in code, but new roles
 * can be added to YAML without code changes.
 */
interface UserRole {
    val value: String

    companion object {
        // New hierarchical role names (from authz-lib YAML config)
        val BACKOFFICE_ADMIN = of("backoffice.admin")
        val PARTNER_ADMIN = of("partner.admin")
        val PARTNER_USER = of("partner.user")
        val MERCHANT_ADMIN = of("merchant.admin")
        val MERCHANT_USER = of("merchant.user")

        // Legacy role names (from Supabase JWT claims — mapped by SupabaseTokenExchangePlugin)
        val PLATFORM_ADMIN = of("platform_admin")
        val SERVICE_ROLE = of("service_role")
        val ENTITY_ADMIN = of("entity_admin")
        val ENTITY_USER = of("entity_user")
        val ENTITY_READONLY = of("entity_readonly")

        /**
         * Creates a UserRole from a raw string value.
         * Accepts both legacy (platform_admin) and new (backoffice.admin) role names.
         */
        fun of(value: String): UserRole = SimpleUserRole(value)
    }
}

/**
 * Default implementation of [UserRole].
 * Uses data class for proper equals/hashCode/toString.
 */
private data class SimpleUserRole(override val value: String) : UserRole {
    override fun toString(): String = value
}
