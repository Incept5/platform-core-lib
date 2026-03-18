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
        val BACKOFFICE_ADMIN = of("backoffice.admin")
        val SERVICE_ADMIN = of("service.admin")
        val PARTNER_ADMIN = of("partner.admin")
        val PARTNER_USER = of("partner.user")
        val MERCHANT_ADMIN = of("merchant.admin")
        val MERCHANT_USER = of("merchant.user")

        /**
         * Creates a UserRole from a string value.
         */
        fun of(value: String): UserRole = SimpleUserRole(value)

        /**
         * Maps legacy Supabase JWT role names to new role names.
         * Used by DualJwtValidator when parsing JWT claims that still carry old names.
         */
        fun fromLegacy(legacyRole: String, entityType: String?): UserRole = when (legacyRole) {
            "platform_admin" -> BACKOFFICE_ADMIN
            "service_role" -> SERVICE_ADMIN
            "entity_admin" -> when (entityType) {
                "partner" -> PARTNER_ADMIN
                "merchant" -> MERCHANT_ADMIN
                else -> PARTNER_USER
            }
            "entity_user" -> when (entityType) {
                "partner" -> PARTNER_USER
                "merchant" -> MERCHANT_USER
                else -> PARTNER_USER
            }
            "entity_readonly" -> when (entityType) {
                "partner" -> PARTNER_USER
                "merchant" -> MERCHANT_USER
                else -> PARTNER_USER
            }
            // Already a new role name — pass through
            else -> of(legacyRole)
        }
    }
}

/**
 * Default implementation of [UserRole].
 * Uses data class for proper equals/hashCode/toString.
 */
private data class SimpleUserRole(override val value: String) : UserRole {
    override fun toString(): String = value
}
