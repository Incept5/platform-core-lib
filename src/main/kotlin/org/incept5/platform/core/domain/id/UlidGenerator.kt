package org.incept5.platform.core.domain.id

import com.github.f4b6a3.ulid.UlidCreator

/**
 * ULID generator utility with static methods for entity field initialization
 * Maintains compatibility with existing entity usage patterns
 */
object UlidGenerator {

    /**
     * Generate a new ULID
     * @return A new ULID string
     */
    fun generate(): String = UlidCreator.getUlid().toString()

    /**
     * Generate a ULID with a specific prefix
     * @param prefix The prefix to prepend to the ULID
     * @return The prefixed ULID string
     */
    fun generateWithPrefix(prefix: String): String {
        return "${prefix}_${generate()}"
    }

    /**
     * Validate if a string is a valid ULID format
     * @param ulid The string to validate
     * @return true if valid ULID format, false otherwise
     */
    fun isValid(ulid: String): Boolean {
        // Basic ULID format validation: 26 characters, Crockford Base32
        if (ulid.length != 26) return false
        val validChars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        return ulid.all { it in validChars }
    }
}
