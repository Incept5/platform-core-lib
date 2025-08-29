
package org.incept5.platform.core.security

import jakarta.ws.rs.core.SecurityContext
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.Mockito.*
import java.security.Principal

class AuthUtilsTest {

    @Test
    fun `isPlatformAdmin should return true for platform admin`() {
        // Given
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)

        // When
        val result = AuthUtils.isPlatformAdmin(securityContext)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
    }

    @Test
    fun `isPlatformAdmin should return false for non-platform admin`() {
        // Given
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)

        // When
        val result = AuthUtils.isPlatformAdmin(securityContext)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
    }

    @Test
    fun `isEntityAdmin should return true for entity admin`() {
        // Given
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)

        // When
        val result = AuthUtils.isEntityAdmin(securityContext)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
    }

    @Test
    fun `isEntityAdmin should return false for non-entity admin`() {
        // Given
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(false)

        // When
        val result = AuthUtils.isEntityAdmin(securityContext)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
    }

    @Test
    fun `isEntityAdminForEntity should return true for entity admin of the specified entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = entityId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.isEntityAdminForEntity(securityContext, entityId)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `isEntityAdminForEntity should return false for entity admin of a different entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.isEntityAdminForEntity(securityContext, entityId)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `isEntityAdminForEntity should return false for non-entity admin`() {
        // Given
        val entityId = "test-entity-id"
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(false)

        // When
        val result = AuthUtils.isEntityAdminForEntity(securityContext, entityId)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, never()).userPrincipal
    }

    @Test
    fun `isPlatformAdminOrEntityAdmin should return true for platform admin`() {
        // Given
        val entityId = "test-entity-id"
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)

        // When
        val result = AuthUtils.isPlatformAdminOrEntityAdmin(securityContext, entityId)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext, never()).isUserInRole(UserRole.entity_admin.name)
    }

    @Test
    fun `isPlatformAdminOrEntityAdmin should return true for entity admin of the specified entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = entityId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.isPlatformAdminOrEntityAdmin(securityContext, entityId)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `isPlatformAdminOrEntityAdmin should return false for entity admin of a different entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.isPlatformAdminOrEntityAdmin(securityContext, entityId)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `ensurePlatformAdminOrEntityAdmin should not throw exception for platform admin`() {
        // Given
        val entityId = "test-entity-id"
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)

        // When/Then - No exception should be thrown
        AuthUtils.ensurePlatformAdminOrEntityAdmin(securityContext, entityId)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
    }

    @Test
    fun `ensurePlatformAdminOrEntityAdmin should not throw exception for entity admin of the specified entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = entityId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then - No exception should be thrown
        AuthUtils.ensurePlatformAdminOrEntityAdmin(securityContext, entityId)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `ensurePlatformAdminOrEntityAdmin should throw exception for entity admin of a different entity`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ForbiddenException> {
            AuthUtils.ensurePlatformAdminOrEntityAdmin(securityContext, entityId)
        }
        assertEquals("You do not have permission to perform this action", exception.message)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }

    @Test
    fun `ensurePlatformAdminOrEntityAdmin should throw exception for non-admin user`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = entityId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(false)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ForbiddenException> {
            AuthUtils.ensurePlatformAdminOrEntityAdmin(securityContext, entityId)
        }
        assertEquals("You do not have permission to perform this action", exception.message)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }

    @Test
    fun `ensurePlatformAdmin should not throw exception for platform admin`() {
        // Given
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)

        // When/Then - No exception should be thrown
        AuthUtils.ensurePlatformAdmin(securityContext)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
    }

    @Test
    fun `ensurePlatformAdmin should throw exception for non-platform admin`() {
        // Given
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "test-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ForbiddenException> {
            AuthUtils.ensurePlatformAdmin(securityContext)
        }
        assertEquals("Only platform administrators can perform this action", exception.message)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }

    @Test
    fun `getEntityType should return entity type from principal`() {
        // Given
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "test-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getEntityType(securityContext)

        // Then
        assertEquals(EntityType.partner, result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `getEntityType should return null for non-ApiPrincipal`() {
        // Given
        val principal = mock(Principal::class.java)
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getEntityType(securityContext)

        // Then
        assertNull(result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `getEntityId should return entity ID from principal`() {
        // Given
        val entityId = "test-entity-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = entityId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getEntityId(securityContext)

        // Then
        assertEquals(entityId, result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `getEntityId should return null for non-ApiPrincipal`() {
        // Given
        val principal = mock(Principal::class.java)
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getEntityId(securityContext)

        // Then
        assertNull(result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `getUserRole should return user role from principal`() {
        // Given
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "test-entity-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getUserRole(securityContext)

        // Then
        assertEquals(UserRole.entity_admin, result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `getUserRole should return null for non-ApiPrincipal`() {
        // Given
        val principal = mock(Principal::class.java)
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.getUserRole(securityContext)

        // Then
        assertNull(result)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `hasPermissionForPartner should return true for platform admin`() {
        // Given
        val partnerId = "test-partner-id"
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)

        // When
        val result = AuthUtils.hasPermissionForPartner(securityContext, partnerId)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext, never()).isUserInRole(UserRole.entity_admin.name)
    }

    @Test
    fun `hasPermissionForPartner should return true for entity admin of the specified partner`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = partnerId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.hasPermissionForPartner(securityContext, partnerId)

        // Then
        assertTrue(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `hasPermissionForPartner should return false for entity admin of a different partner`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-partner-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.hasPermissionForPartner(securityContext, partnerId)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext).userPrincipal
    }

    @Test
    fun `hasPermissionForPartner should return false for entity user`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = partnerId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(false)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When
        val result = AuthUtils.hasPermissionForPartner(securityContext, partnerId)

        // Then
        assertFalse(result)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
    }

    @Test
    fun `ensurePermissionForPartner should not throw exception for platform admin`() {
        // Given
        val partnerId = "test-partner-id"
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(mock(Principal::class.java))

        // When/Then - No exception should be thrown
        AuthUtils.ensurePermissionForPartner(securityContext, partnerId)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
    }

    @Test
    fun `ensurePermissionForPartner should not throw exception for entity admin of the specified partner`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = partnerId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then - No exception should be thrown
        AuthUtils.ensurePermissionForPartner(securityContext, partnerId)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }

    @Test
    fun `ensurePermissionForPartner should throw exception for entity admin of a different partner`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-partner-id"
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ForbiddenException> {
            AuthUtils.ensurePermissionForPartner(securityContext, partnerId)
        }
        assertEquals("You do not have permission to perform this action", exception.message)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }

    @Test
    fun `ensurePermissionForPartner should throw exception for entity user`() {
        // Given
        val partnerId = "test-partner-id"
        val principal = ApiPrincipal(
            subject = "test-subject",
            userRole = UserRole.entity_user,
            entityType = EntityType.partner,
            entityId = partnerId
        )
        val securityContext = mock(SecurityContext::class.java)
        `when`(securityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        `when`(securityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(false)
        `when`(securityContext.userPrincipal).thenReturn(principal)

        // When/Then
        val exception = assertThrows<ForbiddenException> {
            AuthUtils.ensurePermissionForPartner(securityContext, partnerId)
        }
        assertEquals("You do not have permission to perform this action", exception.message)
        verify(securityContext).isUserInRole(UserRole.platform_admin.name)
        verify(securityContext).isUserInRole(UserRole.entity_admin.name)
        verify(securityContext, atLeastOnce()).userPrincipal
    }
}
