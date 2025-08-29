
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

// Test classes with various annotation configurations
@Authenticated(allowedRoles = ["platform_admin"])
class TestControllerWithClassAnnotation {
    fun methodWithoutAnnotation() {}
    
    @Authenticated(allowedRoles = ["entity_admin"])
    fun methodWithAnnotation() {}
}

class TestControllerWithoutClassAnnotation {
    fun methodWithoutAnnotation() {}
    
    @Authenticated(allowedRoles = ["entity_admin", "platform_admin"])
    fun methodWithMultipleRoles() {}
    
    @Authenticated(allowedRoles = [])
    fun methodWithNoRoles() {}
    
    @Authenticated(
        requiresEntityPermission = true,
        entityIdParam = "partnerId",
        entityType = "partner",
        allowedRoles = ["entity_admin", "platform_admin"]
    )
    fun methodWithEntityPermission() {}
    
    @Authenticated(
        requiresEntityPermission = true,
        entityIdParam = "missingParam",
        entityType = "partner"
    )
    fun methodWithMissingParam() {}
}

class AuthenticationFilterTest {

    private lateinit var authenticationFilter: AuthenticationFilter
    private val mockRequestContext = mock<ContainerRequestContext>()
    private val mockResourceInfo = mock<ResourceInfo>()
    private val mockSecurityContext = mock<SecurityContext>()
    private val mockUriInfo = mock<UriInfo>()
    // We'll use real methods and classes from our test controllers

    @BeforeEach
    fun setup() {
        authenticationFilter = AuthenticationFilter()
        // Set the ResourceInfo using reflection since it's injected via @Context
        val resourceInfoField = AuthenticationFilter::class.java.getDeclaredField("resourceInfo")
        resourceInfoField.isAccessible = true
        resourceInfoField.set(authenticationFilter, mockResourceInfo)

        whenever(mockRequestContext.securityContext).thenReturn(mockSecurityContext)
        whenever(mockRequestContext.uriInfo).thenReturn(mockUriInfo)
    }
    
    private fun setupMethodAndClass(methodName: String, controllerClass: Class<*>) {
        val method = controllerClass.getMethod(methodName)
        whenever(mockResourceInfo.resourceMethod).thenReturn(method)
        whenever(mockResourceInfo.resourceClass).thenReturn(controllerClass)
    }

    @Test
    fun `should pass when no authentication annotation is present`() {
        // Given - method without annotation on class without annotation
        setupMethodAndClass("methodWithoutAnnotation", TestControllerWithoutClassAnnotation::class.java)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        // Verify no interaction with security context
        verify(mockSecurityContext, never()).userPrincipal
    }

    @Test
    fun `should throw UnauthorizedException when no principal present`() {
        // Given - method with annotation but no principal
        setupMethodAndClass("methodWithMultipleRoles", TestControllerWithoutClassAnnotation::class.java)
        whenever(mockSecurityContext.userPrincipal).thenReturn(null)

        // When/Then
        assertThrows<UnauthorizedException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should throw UnauthorizedException when principal is not ApiPrincipal`() {
        // Given - method with annotation but wrong principal type
        setupMethodAndClass("methodWithMultipleRoles", TestControllerWithoutClassAnnotation::class.java)
        val mockPrincipal = mock<java.security.Principal>()
        whenever(mockSecurityContext.userPrincipal).thenReturn(mockPrincipal)

        // When/Then
        assertThrows<UnauthorizedException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should pass when user has required role`() {
        // Given - method with multiple allowed roles, user has one of them
        setupMethodAndClass("methodWithMultipleRoles", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.entity_admin)
        
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("entity_admin")).thenReturn(true)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockSecurityContext).isUserInRole("entity_admin")
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should abort request when user lacks required role`() {
        // Given - use class annotation that requires platform_admin, user is entity_user
        setupMethodAndClass("methodWithoutAnnotation", TestControllerWithClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.entity_user)
        
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
        // Given - method allows multiple roles, user has entity_user
        setupMethodAndClass("methodWithMultipleRoles", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.entity_user)
        
        // First create a test controller with entity_user role included
        val testMethod = object {
            @Authenticated(allowedRoles = ["entity_admin", "platform_admin", "entity_user"])
            fun methodWithEntityUserRole() {}
        }.javaClass.getMethod("methodWithEntityUserRole")
        
        whenever(mockResourceInfo.resourceMethod).thenReturn(testMethod)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestControllerWithoutClassAnnotation::class.java)
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
        // Given - method requires entity permission, platform admin should have access
        setupMethodAndClass("methodWithEntityPermission", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(
            userRole = UserRole.platform_admin,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole(UserRole.platform_admin.name)).thenReturn(true)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should abort request when entity permission required but user lacks permission`() {
        // Given - entity admin trying to access different partner's resources
        setupMethodAndClass("methodWithEntityPermission", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "different-partner-456"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
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
        // Given - entity admin accessing their own partner's resources
        setupMethodAndClass("methodWithEntityPermission", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(
            userRole = UserRole.entity_admin,
            entityType = EntityType.partner,
            entityId = "partner-123"
        )
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
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
        // Given - method expects missingParam but pathParams has partnerId
        setupMethodAndClass("methodWithMissingParam", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.entity_admin)
        val pathParams = MultivaluedHashMap<String, String>().apply {
            add("partnerId", "partner-123")
        }
        
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockUriInfo.pathParameters).thenReturn(pathParams)

        // When/Then
        assertThrows<IllegalStateException> {
            authenticationFilter.filter(mockRequestContext)
        }
    }

    @Test
    fun `should use class-level annotation when method-level annotation not present`() {
        // Given - method without annotation on class with annotation
        setupMethodAndClass("methodWithoutAnnotation", TestControllerWithClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.platform_admin)
        
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)
        whenever(mockSecurityContext.isUserInRole("platform_admin")).thenReturn(true)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
    }

    @Test
    fun `should pass when no roles specified in annotation`() {
        // Given - method with empty roles array
        setupMethodAndClass("methodWithNoRoles", TestControllerWithoutClassAnnotation::class.java)
        val principal = createApiPrincipal(UserRole.entity_user)
        
        whenever(mockSecurityContext.userPrincipal).thenReturn(principal)

        // When/Then - Should not throw any exception
        authenticationFilter.filter(mockRequestContext)
        
        verify(mockRequestContext, never()).abortWith(any())
        // Should not check any roles when none are specified
        verify(mockSecurityContext, never()).isUserInRole(any())
    }

    // Helper method for creating test objects

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
