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
}
