package org.incept5.platform.core.domain.session

/**
 * Interface for secure session ID generation
 * Business-specific implementations should implement this interface
 */
interface SessionIdGenerator {
    fun generateSecureSessionId(): String
    suspend fun generateBatchAsync(count: Int): List<String>
}
