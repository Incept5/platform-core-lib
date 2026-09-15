
package org.incept5.platform.core.auth

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.kotest.matchers.string.shouldContain
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ResourceInfo
import jakarta.ws.rs.core.SecurityContext
import jakarta.ws.rs.core.UriInfo
import org.incept5.platform.core.authz.ApiPrincipal
import org.incept5.platform.core.error.ForbiddenException
import org.incept5.platform.core.error.UnauthorizedException
import org.incept5.platform.core.model.UserRole
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.*
import java.lang.reflect.Method
import java.security.Principal
import java.time.Instant
import java.util.*

/**
 * The filter reads scopes and client id from the [ApiPrincipal] that authz-lib's AuthzFilter builds
 * from a verified token; it never decodes the Authorization header. These tests therefore stub the
 * principal on the SecurityContext, and the header-based cases assert the header is *not* read.
 */
class ScopeAuthorizationFilterTest {

    private lateinit var scopeFilter: ScopeAuthorizationFilter
    private val mockRequestContext = mock<ContainerRequestContext>()
    private val mockResourceInfo = mock<ResourceInfo>()
    private val mockMethod = mock<Method>()
    private val algorithm = Algorithm.HMAC256("test-secret-key-that-is-long-enough-for-hmac256-algorithm")

    @BeforeEach
    fun setup() {
        scopeFilter = ScopeAuthorizationFilter()
        val resourceInfoField = ScopeAuthorizationFilter::class.java.getDeclaredField("resourceInfo")
        resourceInfoField.isAccessible = true
        resourceInfoField.set(scopeFilter, mockResourceInfo)

        whenever(mockResourceInfo.resourceMethod).thenReturn(mockMethod)

        // The fail-closed branch logs uriInfo.path; give every test a path so that log line is safe.
        val uriInfo = mock<UriInfo>()
        whenever(uriInfo.path).thenReturn("/api/v1/payment-sessions/ps_TEST/enhanced")
        whenever(mockRequestContext.uriInfo).thenReturn(uriInfo)
    }

    // 1
    @Test
    fun `passes when no RequireScope annotation is present, without touching the context`() {
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(null)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithoutAnnotation::class.java)

        scopeFilter.filter(mockRequestContext)
        // No exception = pass. securityContext is never consulted.
        verify(mockRequestContext, never()).securityContext
    }

    // 2 — the review exploit, at library level: a scope-guarded endpoint reached with no verified
    // principal must fail closed, even with a plausible signed token in the header.
    @Test
    fun `throws Unauthorized when no verified principal, even with a signed-looking token in the header`() {
        setupRequireScope("service.payment.session:read", scopeOnlyAuthorization = true)
        setNoPrincipal()
        // A header is present but must be irrelevant.
        whenever(mockRequestContext.getHeaderString(any()))
            .thenThrow(AssertionError("the filter must not read the Authorization header"))

        assertThrows<UnauthorizedException> { scopeFilter.filter(mockRequestContext) }
    }

    // 3 — an alg:none forged token carrying the required scope and a client_id still gets nowhere.
    @Test
    fun `throws Unauthorized when no verified principal, even for an alg none token claiming the scope`() {
        setupRequireScope("service.payment.session:read", scopeOnlyAuthorization = true)
        setNoPrincipal()
        whenever(mockRequestContext.getHeaderString(any()))
            .thenThrow(AssertionError("the filter must not read the Authorization header"))

        assertThrows<UnauthorizedException> { scopeFilter.filter(mockRequestContext) }
    }

    // 4
    @Test
    fun `throws Forbidden when scopeOnlyAuthorization and principal has no clientId`() {
        setupRequireScope("service.payment.reporting:read", scopeOnlyAuthorization = true)
        setPrincipal(apiPrincipal(clientId = null))

        val ex = assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
        ex.message shouldContain "only accessible with API Key"
    }

    // 5
    @Test
    fun `passes for a verified user principal (no clientId) on a non-scope-only endpoint`() {
        setupRequireScope("payment:read")
        setPrincipal(apiPrincipal(clientId = null))

        scopeFilter.filter(mockRequestContext)
    }

    // 6
    @Test
    fun `passes when principal has a clientId and the required scope`() {
        setupRequireScope("payment:read")
        setPrincipal(apiPrincipal(clientId = "client-123", scopes = listOf("payment:read", "payment:write")))

        scopeFilter.filter(mockRequestContext)
    }

    // 7
    @Test
    fun `throws Forbidden when principal has a clientId but lacks the required scope`() {
        setupRequireScope("payment:write")
        setPrincipal(apiPrincipal(clientId = "client-123", scopes = listOf("payment:read")))

        val ex = assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
        ex.message shouldContain "Missing required scope"
    }

    // 8 — proves the header is never read: the principal lacks the scope, the header token claims it,
    // and the request is still refused.
    @Test
    fun `refuses on the principal scopes and ignores a header token that claims the scope`() {
        setupRequireScope("payment:write")
        setPrincipal(apiPrincipal(clientId = "client-123", scopes = listOf("payment:read")))
        whenever(mockRequestContext.getHeaderString(any()))
            .thenThrow(AssertionError("the filter must not read the Authorization header"))

        assertThrows<ForbiddenException> { scopeFilter.filter(mockRequestContext) }
    }

    // 9
    @Test
    fun `throws Unauthorized when the principal is not an ApiPrincipal`() {
        setupRequireScope("payment:read")
        setPrincipal(Principal { "some-non-api-principal" })

        assertThrows<UnauthorizedException> { scopeFilter.filter(mockRequestContext) }
    }

    // --- Helper methods ---

    private fun setupRequireScope(scope: String, scopeOnlyAuthorization: Boolean = false) {
        val annotation = mock<RequireScope>()
        whenever(annotation.value).thenReturn(scope)
        whenever(annotation.scopeOnlyAuthorization).thenReturn(scopeOnlyAuthorization)
        whenever(mockMethod.getAnnotation(RequireScope::class.java)).thenReturn(annotation)
        whenever(mockResourceInfo.resourceClass).thenReturn(TestResourceWithoutAnnotation::class.java)
    }

    private fun setPrincipal(principal: Principal) {
        val sc = mock<SecurityContext>()
        whenever(sc.userPrincipal).thenReturn(principal)
        whenever(mockRequestContext.securityContext).thenReturn(sc)
    }

    private fun setNoPrincipal() {
        val sc = mock<SecurityContext>()
        whenever(sc.userPrincipal).thenReturn(null)
        whenever(mockRequestContext.securityContext).thenReturn(sc)
    }

    private fun apiPrincipal(
        clientId: String?,
        scopes: List<String> = emptyList(),
        role: String = if (clientId == null) "backoffice.admin" else "partner.admin",
    ): ApiPrincipal = ApiPrincipal(
        subject = clientId ?: UUID.randomUUID().toString(),
        userRole = UserRole.of(role),
        entityType = null,
        entityId = null,
        scopes = scopes,
        clientId = clientId,
        principalId = UUID.randomUUID(),
        globalRoles = emptyList(),
        entityRoles = emptyList(),
    )

    // Kept so the class still documents the shape of a valid token, though the filter no longer
    // decodes one. Used by no assertions directly; retained for readers reproducing a forged header.
    @Suppress("unused")
    private fun signedToken(clientId: String?, scopes: List<String>): String =
        JWT.create()
            .withSubject(clientId ?: UUID.randomUUID().toString())
            .withClaim("role", if (clientId == null) "backoffice.admin" else "partner.admin")
            .apply { clientId?.let { withClaim("client_id", it) } }
            .withClaim("scopes", scopes)
            .withExpiresAt(Date.from(Instant.now().plusSeconds(3600)))
            .sign(algorithm)

    // Test resource classes for annotation testing
    class TestResourceWithoutAnnotation
}
