
package org.incept5.platform.core.auth

import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.SecurityContext
import jakarta.ws.rs.core.UriInfo
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.security.ApiPrincipal
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import io.kotest.matchers.shouldBe
import java.lang.reflect.Method
import jakarta.ws.rs.core.MultivaluedHashMap

class AuthenticationFilterTest {

    private lateinit var authenticationFilter: AuthenticationFilter
    private val mockRequestContext = mock<ContainerRequestContext>()
    private val mockResourceInfo = mock<ResourceInfo>()
    private val mockSecurityContext = mock<SecurityContext>()
    private val mockUriInfo = mock<UriInfo>()
    private val mockMethod = mock<Method>()
    private val mockResourceClass = mock<Class<*>>()

    @BeforeEach
    fun setup() {
        authenticationFilter = AuthenticationFilter()
        // Set the ResourceInfo using reflection since it's injected via @Context
        val resourceInfoField = AuthenticationFilter::class.java.getDeclaredField("resourceInfo")
        resourceInfoField.isAccessible = true
        resourceInfoField.set(authenticationFilter, mockResourceInfo)

        whenever(mockRequestContext.securityContext).thenReturn(mockSecurityContext)
        whenever(mockRequestContext.uriInfo).thenReturn(mockUriInfo)
        whenever(mockResourceInfo.resourceMethod).thenReturn(mockMethod)
        whenever(mockResourceInfo.resourceClass).thenReturn(mockResourceClass)
    }

    @Test
    fun `should pass when no authentication annotation is present`() {
        // Given
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(null)
        whenever(mockResourceClass.getAnnotation(Authenticated::class.java)).thenReturn(null)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        // Verify no interaction with security context
        verify(mockSecurityContext, never()).userPrincipal
    }

    @Test
    fun `should throw UnauthorizedException when no principal present`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation()
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(null)

        // When/Then
        assertThrows<UnauthorizedException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should throw UnauthorizedException when principal is not ApiPrincipal`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation()
        val mockPrincipal = mock<java.security.Principal>()
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(mockPrincipal)

        // When/Then
        assertThrows<UnauthorizedException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should pass when user has required role`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            allowedRoles = arrayOf("entity_admin", "platform_admin")
        )
        val principal = createApiPrincipal(UserRole.entity_admin)
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("entity_admin")).thenReturn(true)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockSecurityContext).isUserInRole("entity_admin")
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should abort request when user lacks required role`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            allowedRoles = arrayOf("platform_admin")
        )
        val principal = createApiPrincipal(UserRole.entity_user)
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("platform_admin")).thenReturn(false)

        // When
        authenticationFilter.filter(mockRequestContext)

        // Then
        val responseCaptor = argumentCaptor<Response>()
        verify(mockRequestContext).abortWith(responseCaptor.capture())
        
        val response = responseCaptor.firstValue
        response.status shouldBe 403
        val entity = response.entity as Map<*, *>
        entity["error"] shouldBe "You do not have the required role to perform this action"
    }

    @Test
    fun `should pass when multiple roles allowed and user has one of them`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            allowedRoles = arrayOf("entity_admin", "platform_admin", "entity_user")
        )
        val principal = createApiPrincipal(UserRole.entity_user)
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("entity_admin")).thenReturn(false)
        whenever(mockSecurityContext.isUserInRole("platform_admin")).thenReturn(false)
        whenever(mockSecurityContext.isUserInRole("entity_user")).thenReturn(true)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should check entity permission when requiresEntityPermission is true and user has permission`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            requiresEntityPermission = true,
            entityIdParam = "partnerId",
            entityType = "partner"
        )
        val principal = createApiPrincipal(
            userRole = UserRole.platform_admin,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should abort request when entity permission required but user lacks permission`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            requiresEntityPermission = true,
            entityIdParam = "partnerId",
            entityType = "partner"
        )
        val principal = createApiPrincipal(
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-partner-456"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        whenever(mockSecurityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When
        authenticationFilter.filter(mockRequestContext)

        // Then
        val responseCaptor = argumentCaptor<Response>()
        verify(mockRequestContext).abortWith(responseCaptor.capture())
        
        val response = responseCaptor.firstValue
        response.status shouldBe 403
        val entity = response.entity as Map<*, *>
        entity["error"] shouldBe "You do not have permission to perform this action"
    }

    @Test
    fun `should allow entity admin access to their own entity`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            requiresEntityPermission = true,
            entityIdParam = "partnerId",
            entityType = "partner"
        )
        val principal = createApiPrincipal(
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(false)
        whenever(mockSecurityContext.isUserInRole(UserRole.entity_admin.name)).thenReturn(true)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should throw IllegalStateException when entity ID parameter not found`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            requiresEntityPermission = true,
            entityIdParam = "missingParam",
            entityType = "partner"
        )
        val principal = createApiPrincipal(UserRole.entity_admin)
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When/Then
        assertThrows<IllegalStateException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should use class-level annotation when method-level annotation not present`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            allowedRoles = arrayOf("platform_admin")
        )
        val principal = createApiPrincipal(UserRole.platform_admin)
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(null)
        whenever(mockResourceClass.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("platform_admin")).thenReturn(true)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should pass when no roles specified in annotation`() {
        // Given
        val authenticatedAnnotation = createAuthenticatedAnnotation(
            allowedRoles = arrayOf()
        )
        val principal = createApiPrincipal(UserRole.entity_user)
        
        whenever(mockMethod.getAnnotation(Authenticated::class.java)).thenReturn(authenticatedAnnotation)
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
        // Should not check any roles when none are specified
        verify(mockSecurityContext, never()).isUserInRole(any())
    }

    // Helper methods for creating test objects

    private fun createAuthenticatedAnnotation(
        allowedRoles: Array<String> = arrayOf(),
        requiresEntityPermission: Boolean = false,
        entityIdParam: String = "",
        entityType: String = ""
    ): Authenticated {
        val mockAnnotation = mock<Authenticated>()
        whenever(mockAnnotation.allowedRoles).thenReturn(allowedRoles)
        whenever(mockAnnotation.requiresEntityPermission).thenReturn(requiresEntityPermission)
        whenever(mockAnnotation.entityIdParam).thenReturn(entityIdParam)
        whenever(mockAnnotation.entityType).thenReturn(entityType)
        return mockAnnotation
    }

    private fun createApiPrincipal(
        userRole: UserRole,
        entityType: EntityType? = null,
        entityId: String? = null
    ): ApiPrincipal {
        return ApiPrincipal(
            subject = "test-user-123",
            userRole = userRole,
            entityType = entityType,
            entityId = entityId
        )
    }
}
