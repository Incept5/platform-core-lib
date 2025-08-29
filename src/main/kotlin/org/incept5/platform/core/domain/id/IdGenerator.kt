package org.incept5.platform.core.domain.id

/**
 * Generic interface for ID generation strategies
 */
interface IdGenerator<T> {
    fun generate(): T
}
