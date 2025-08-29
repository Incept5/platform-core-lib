package org.incept5.platform.core.domain.id

import jakarta.enterprise.context.ApplicationScoped

/**
 * CDI-injectable ULID generation service
 * Use this for dependency injection in services
 */
@ApplicationScoped
class UlidService : IdGenerator<String> {

    override fun generate(): String = UlidGenerator.generate()

    /**
     * Generate a ULID with a specific prefix
     * @param prefix The prefix to prepend to the ULID
     * @return The prefixed ULID string
     */
    fun generateWithPrefix(prefix: String): String = UlidGenerator.generateWithPrefix(prefix)

    /**
     * Validate if a string is a valid ULID format
     * @param ulid The string to validate
     * @return true if valid ULID format, false otherwise
     */
    fun isValid(ulid: String): Boolean = UlidGenerator.isValid(ulid)
}
