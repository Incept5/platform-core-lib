
package org.incept5.platform.core.logging.util

/**
 * Utility class for masking sensitive data in logs and responses.
 * Provides methods to safely mask PII and sensitive information while preserving some readability.
 */
object SensitiveDataMasker {

    private val EMAIL_PATTERN = Regex("""([^@]+)@(.+)""")
    private val PHONE_PATTERN = Regex("""(\+?1?)?(\d{3})(\d{3})(\d{4})""")
    private val CARD_PATTERN = Regex("""(\d{4})(\d+)(\d{4})""")
    private val SSN_PATTERN = Regex("""(\d{3})(\d{2})(\d{4})""")

    /**
     * Masks an email address, showing first 2 characters of username and full domain.
     * Example: "user@example.com" -> "us***@example.com"
     */
    fun maskEmail(email: String): String {
        return EMAIL_PATTERN.replace(email) { matchResult ->
            val username = matchResult.groups[1]?.value ?: ""
            val domain = matchResult.groups[2]?.value ?: ""
            "${username.take(2)}***@${domain}"
        }
    }

    /**
     * Masks a phone number, showing country code, area code, and last 4 digits.
     * Example: "+1-555-123-4567" -> "+1-555-***-4567"
     */
    fun maskPhone(phone: String): String {
        return PHONE_PATTERN.replace(phone) { matchResult ->
            val country = matchResult.groups[1]?.value ?: ""
            val area = matchResult.groups[2]?.value ?: ""
            val last4 = matchResult.groups[4]?.value ?: ""
            "${country}${area}***${last4}"
        }
    }

    /**
     * Masks a credit card number, showing first 4 and last 4 digits.
     * Example: "4111111111111111" -> "4111****1111"
     */
    fun maskCardNumber(cardNumber: String): String {
        return CARD_PATTERN.replace(cardNumber) { matchResult ->
            val first4 = matchResult.groups[1]?.value ?: ""
            val last4 = matchResult.groups[3]?.value ?: ""
            "${first4}****${last4}"
        }
    }

    /**
     * Masks a Social Security Number, showing only last 4 digits.
     * Example: "123-45-6789" -> "***-**-6789"
     */
    fun maskSSN(ssn: String): String {
        return SSN_PATTERN.replace(ssn) { matchResult ->
            val last4 = matchResult.groups[3]?.value ?: ""
            "***-**-$last4"
        }
    }

    /**
     * Generic masking function that preserves specified number of characters at start and end.
     * Example: maskGeneric("sensitive123data", 2, 2) -> "se*********ta"
     */
    fun maskGeneric(value: String, visibleStart: Int = 2, visibleEnd: Int = 2): String {
        val maskedLength = value.length - visibleStart - visibleEnd
        return when {
            value.length <= visibleStart + visibleEnd || maskedLength < 2 -> "*".repeat(value.length)
            visibleEnd == 0 -> value.take(visibleStart) + "*".repeat(value.length - visibleStart)
            visibleStart == 0 -> "*".repeat(value.length - visibleEnd) + value.takeLast(visibleEnd)
            else -> {
                value.take(visibleStart) + "*".repeat(maskedLength) + value.takeLast(visibleEnd)
            }
        }
    }

    /**
     * Masks common sensitive field values based on field name patterns.
     * Automatically detects field types and applies appropriate masking.
     */
    fun maskSensitiveField(fieldName: String, value: Any?): String {
        if (value == null) return "null"

        val stringValue = value.toString()
        val lowerFieldName = fieldName.lowercase()

        return when {
            lowerFieldName.contains("email") -> {
                try {
                    maskEmail(stringValue)
                } catch (e: Exception) {
                    maskGeneric(stringValue)
                }
            }
            lowerFieldName.contains("phone") || lowerFieldName.contains("mobile") -> {
                try {
                    maskPhone(stringValue)
                } catch (e: Exception) {
                    maskGeneric(stringValue)
                }
            }
            lowerFieldName.contains("card") || lowerFieldName.contains("credit") || lowerFieldName.contains("debit") -> {
                try {
                    maskCardNumber(stringValue)
                } catch (e: Exception) {
                    maskGeneric(stringValue)
                }
            }
            lowerFieldName.contains("ssn") || lowerFieldName.contains("social") -> {
                try {
                    maskSSN(stringValue)
                } catch (e: Exception) {
                    maskGeneric(stringValue)
                }
            }
            lowerFieldName.contains("password") || lowerFieldName.contains("secret") || lowerFieldName.contains("token") ->
                "*".repeat(minOf(stringValue.length, 8))
            lowerFieldName.contains("address") || lowerFieldName.contains("street") -> maskGeneric(stringValue, 3, 0)
            isSensitiveField(fieldName) -> maskGeneric(stringValue) // fallback for other sensitive fields
            else -> stringValue // Don't mask non-sensitive fields
        }
    }

    /**
     * Masks sensitive data in a map of key-value pairs.
     * Useful for logging request/response data or context information.
     */
    fun maskSensitiveData(data: Map<String, Any?>): Map<String, Any?> {
        return data.mapValues { (key, value) ->
            when (value) {
                is String -> {
                    if (isSensitiveField(key)) {
                        maskSensitiveField(key, value)
                    } else {
                        value
                    }
                }
                is Map<*, *> -> maskMapSafely(value)
                is List<*> -> value.map { item ->
                    if (item is Map<*, *>) maskMapSafely(item) else item
                }
                else -> value
            }
        }
    }

    /**
     * Safely masks a map with unknown key types.
     * Only processes maps with String keys, returns original map otherwise.
     */
    private fun maskMapSafely(map: Map<*, *>): Any {
        return try {
            // Check if all keys are strings
            if (map.keys.all { it is String }) {
                @Suppress("UNCHECKED_CAST")
                maskSensitiveData(map as Map<String, Any?>)
            } else {
                // Return original map if keys are not all strings
                map
            }
        } catch (e: Exception) {
            // Return original map if casting fails
            map
        }
    }

    /**
     * Sensitive field patterns that should always be masked in logs.
     */
    val SENSITIVE_FIELD_PATTERNS = setOf(
        "password", "secret", "token", "key", "auth", "credential",
        "ssn", "social", "sin", "tax", "ein",
        "card", "credit", "debit", "account", "routing",
        "email", "phone", "mobile", "address", "street"
    )

    /**
     * Checks if a field name indicates sensitive data that should be masked.
     */
    fun isSensitiveField(fieldName: String): Boolean {
        val lowerFieldName = fieldName.lowercase()
        return SENSITIVE_FIELD_PATTERNS.any { pattern ->
            lowerFieldName.contains(pattern)
        }
    }
}
