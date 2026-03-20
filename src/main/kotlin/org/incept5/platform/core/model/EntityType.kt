package org.incept5.platform.core.model

/**
 * The type of entity making API requests.
 */
enum class EntityType(val value: String) {
    PARTNER("partner"),
    MERCHANT("merchant");

    companion object {
        /**
         * Resolves an [EntityType] from its string value (case-insensitive),
         * or returns null if the value does not match a known type.
         */
        fun fromValue(value: String): EntityType? =
            entries.firstOrNull { it.value.equals(value, ignoreCase = true) }
    }
}
