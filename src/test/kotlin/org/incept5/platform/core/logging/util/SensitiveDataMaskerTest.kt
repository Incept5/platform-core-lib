
package org.incept5.platform.core.logging.util

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class SensitiveDataMaskerTest {

    @Test
    fun `should mask email addresses correctly`() {
        assertThat(SensitiveDataMasker.maskEmail("user@example.com"))
            .isEqualTo("us***@example.com")

        assertThat(SensitiveDataMasker.maskEmail("a@test.org"))
            .isEqualTo("a***@test.org")

        assertThat(SensitiveDataMasker.maskEmail("verylongusername@domain.co.uk"))
            .isEqualTo("ve***@domain.co.uk")
    }

    @Test
    fun `should mask phone numbers correctly`() {
        assertThat(SensitiveDataMasker.maskPhone("15551234567"))
            .isEqualTo("1555***4567")

        assertThat(SensitiveDataMasker.maskPhone("5551234567"))
            .isEqualTo("555***4567")

        assertThat(SensitiveDataMasker.maskPhone("+15551234567"))
            .isEqualTo("+1555***4567")
    }

    @Test
    fun `should mask card numbers correctly`() {
        assertThat(SensitiveDataMasker.maskCardNumber("4111111111111111"))
            .isEqualTo("4111****1111")

        assertThat(SensitiveDataMasker.maskCardNumber("5555555555554444"))
            .isEqualTo("5555****4444")

        assertThat(SensitiveDataMasker.maskCardNumber("378282246310005"))
            .isEqualTo("3782****0005")
    }

    @Test
    fun `should mask SSN correctly`() {
        assertThat(SensitiveDataMasker.maskSSN("123456789"))
            .isEqualTo("***-**-6789")

        assertThat(SensitiveDataMasker.maskSSN("987654321"))
            .isEqualTo("***-**-4321")
    }

    @Test
    fun `should mask generic values correctly`() {
        assertThat(SensitiveDataMasker.maskGeneric("sensitive123data", 2, 2))
            .isEqualTo("se************ta")

        assertThat(SensitiveDataMasker.maskGeneric("short", 2, 2))
            .isEqualTo("*****")

        assertThat(SensitiveDataMasker.maskGeneric("verylongvalue", 3, 0))
            .isEqualTo("ver**********")

        assertThat(SensitiveDataMasker.maskGeneric("verylongvalue", 0, 3))
            .isEqualTo("**********lue")
    }

    @Test
    fun `should identify sensitive fields correctly`() {
        assertThat(SensitiveDataMasker.isSensitiveField("password")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("userPassword")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("EMAIL")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("phoneNumber")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("creditCard")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("accessToken")).isTrue()
        assertThat(SensitiveDataMasker.isSensitiveField("socialSecurityNumber")).isTrue()

        assertThat(SensitiveDataMasker.isSensitiveField("userId")).isFalse()
        assertThat(SensitiveDataMasker.isSensitiveField("name")).isFalse()
        assertThat(SensitiveDataMasker.isSensitiveField("status")).isFalse()
    }

    @Test
    fun `should mask sensitive field values by field name`() {
        assertThat(SensitiveDataMasker.maskSensitiveField("email", "user@example.com"))
            .isEqualTo("us***@example.com")

        assertThat(SensitiveDataMasker.maskSensitiveField("phoneNumber", "5551234567"))
            .isEqualTo("555***4567")

        assertThat(SensitiveDataMasker.maskSensitiveField("cardNumber", "4111111111111111"))
            .isEqualTo("4111****1111")

        assertThat(SensitiveDataMasker.maskSensitiveField("password", "secretpassword"))
            .isEqualTo("********")

        assertThat(SensitiveDataMasker.maskSensitiveField("ssn", "123456789"))
            .isEqualTo("***-**-6789")

        assertThat(SensitiveDataMasker.maskSensitiveField("homeAddress", "123 Main Street"))
            .isEqualTo("123************")

        // Non-sensitive field should not be masked
        assertThat(SensitiveDataMasker.maskSensitiveField("userId", "12345"))
            .isEqualTo("12345")
    }

    @Test
    fun `should mask sensitive data in maps`() {
        val data = mapOf(
            "userId" to "12345",
            "email" to "user@example.com",
            "phoneNumber" to "5551234567",
            "password" to "secretpassword",
            "address" to mapOf(
                "street" to "123 Main Street",
                "email" to "contact@company.com"
            ),
            "items" to listOf(
                mapOf("cardNumber" to "4111111111111111", "name" to "John Doe"),
                mapOf("phone" to "5559876543", "id" to "item-123")
            )
        )

        val maskedData = SensitiveDataMasker.maskSensitiveData(data)

        assertThat(maskedData["userId"]).isEqualTo("12345") // Not masked
        assertThat(maskedData["email"]).isEqualTo("us***@example.com")
        assertThat(maskedData["phoneNumber"]).isEqualTo("555***4567")
        assertThat(maskedData["password"]).isEqualTo("********")

        @Suppress("UNCHECKED_CAST")
        val maskedAddress = maskedData["address"] as Map<String, Any?>
        assertThat(maskedAddress["street"]).isEqualTo("123************")
        assertThat(maskedAddress["email"]).isEqualTo("co***@company.com")

        @Suppress("UNCHECKED_CAST")
        val maskedItems = maskedData["items"] as List<Map<String, Any?>>
        assertThat((maskedItems[0])["cardNumber"]).isEqualTo("4111****1111")
        assertThat((maskedItems[0])["name"]).isEqualTo("John Doe") // Not masked
        assertThat((maskedItems[1])["phone"]).isEqualTo("555***6543")
        assertThat((maskedItems[1])["id"]).isEqualTo("item-123") // Not masked
    }

    @Test
    fun `should handle null values gracefully`() {
        assertThat(SensitiveDataMasker.maskSensitiveField("email", null))
            .isEqualTo("null")

        val dataWithNulls = mapOf(
            "email" to null,
            "phone" to "5551234567"
        )

        val masked = SensitiveDataMasker.maskSensitiveData(dataWithNulls)
        assertThat(masked["email"]).isNull()
        assertThat(masked["phone"]).isEqualTo("555***4567")
    }
}
