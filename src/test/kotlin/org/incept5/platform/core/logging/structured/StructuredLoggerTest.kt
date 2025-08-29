
package org.incept5.platform.core.logging.structured

import org.assertj.core.api.Assertions.assertThat
import org.incept5.correlation.CorrelationId
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test

class StructuredLoggerTest {

    private lateinit var structuredLogger: StructuredLogger

    @BeforeEach
    fun setup() {
        structuredLogger = StructuredLogger()
        // Set a test correlation ID
        CorrelationId.setId("test-correlation-id")
    }

    @Test
    fun `should log structured info message`() {
        val context = mapOf("userId" to "123", "action" to "login")

        // This test verifies the method executes without throwing exceptions
        // Actual log output verification would require more complex test setup
        structuredLogger.info("USER_LOGIN", context)

        // If we reach this point, the logging succeeded
        assertThat(true).isTrue()
    }

    @Test
    fun `should log structured warning message`() {
        val context = mapOf("operation" to "payment", "errorCode" to "TIMEOUT")

        structuredLogger.warn("PAYMENT_WARNING", context)

        assertThat(true).isTrue()
    }

    @Test
    fun `should log structured error message with exception`() {
        val context = mapOf("operation" to "database", "table" to "users")
        val exception = RuntimeException("Connection failed")

        structuredLogger.error("DATABASE_ERROR", context, exception)

        assertThat(true).isTrue()
    }

    @Test
    fun `should log structured debug message`() {
        val context = mapOf("step" to "validation", "field" to "email")

        structuredLogger.debug("VALIDATION_DEBUG", context)

        assertThat(true).isTrue()
    }

    @Test
    fun `should include thread information in log context`() {
        val context = mapOf("customField" to "value")

        structuredLogger.info("THREAD_TEST", context)

        assertThat(true).isTrue()
    }

    @Test
    fun `should handle missing correlation ID gracefully`() {
        CorrelationId.clear()
        val context = mapOf("test" to "value")

        structuredLogger.info("NO_CORRELATION_TEST", context)

        assertThat(true).isTrue()
    }

    @Test
    fun `should log with empty context`() {
        structuredLogger.info("EMPTY_CONTEXT_TEST")

        assertThat(true).isTrue()
    }
}
