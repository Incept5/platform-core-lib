package org.incept5.platform.core.domain.id

import org.junit.jupiter.api.Test
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach

class UlidGeneratorTest {

    @Test
    fun `should generate valid ULID`() {
        val ulid = UlidGenerator.generate()

        assertThat(ulid).hasSize(26)
        assertThat(UlidGenerator.isValid(ulid)).isTrue()
    }

    @Test
    fun `should generate ULID with prefix`() {
        val ulid = UlidGenerator.generateWithPrefix("TEST")

        assertThat(ulid).startsWith("TEST_")
        assertThat(ulid).hasSize(31) // TEST_ + 26
    }

    @Test
    fun `should validate ULID format correctly`() {
        // Valid ULIDs
        assertThat(UlidGenerator.isValid("01ARZ3NDEKTSV4RRFFQ69G5FAV")).isTrue()

        // Invalid ULIDs
        assertThat(UlidGenerator.isValid("")).isFalse()
        assertThat(UlidGenerator.isValid("too_short")).isFalse()
        assertThat(UlidGenerator.isValid("01ARZ3NDEKTSV4RRFFQ69G5FAVI")).isFalse() // too long
        assertThat(UlidGenerator.isValid("01ARZ3NDEKTSV4RRFFQ69G5FAl")).isFalse() // invalid character 'l'
    }

    @Test
    fun `should generate different ULIDs on multiple calls`() {
        val ulid1 = UlidGenerator.generate()
        val ulid2 = UlidGenerator.generate()

        assertThat(ulid1).isNotEqualTo(ulid2)
        assertThat(UlidGenerator.isValid(ulid1)).isTrue()
        assertThat(UlidGenerator.isValid(ulid2)).isTrue()
    }
}
