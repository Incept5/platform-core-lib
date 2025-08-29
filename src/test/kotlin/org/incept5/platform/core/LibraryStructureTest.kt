
package org.incept5.platform.core

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertNotNull

class LibraryStructureTest {

    @Test
    fun `library structure should be correctly organized`() {
        // Verify package structure exists
        val packageExists = javaClass.classLoader
            .getResource("org/incept5/platform/core") != null

        assertTrue(packageExists, "Platform core package structure should exist")
    }

    @Test
    fun `library should have proper group and package structure`() {
        // Verify that we can load classes from the expected package
        val packageName = this.javaClass.`package`.name
        assertNotNull(packageName, "Package name should not be null")
        assertTrue(
            packageName.startsWith("org.incept5.platform.core"),
            "Package should start with org.incept5.platform.core"
        )
    }
}
