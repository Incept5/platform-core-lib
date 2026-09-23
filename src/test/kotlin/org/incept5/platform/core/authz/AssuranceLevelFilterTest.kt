package org.incept5.platform.core.authz

import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.core.SecurityContext
import jakarta.ws.rs.core.UriInfo
import org.incept5.authz.core.model.EntityRole
import org.incept5.platform.core.model.UserRole
import org.incept5.platform.core.security.TokenSource
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.security.Principal
import java.util.UUID

/**
 * Unit tests for [AssuranceLevelFilter]. Like [org.incept5.platform.core.auth.ScopeAuthorizationFilter]
 * this filter only reads the [ApiPrincipal] that authz-lib's `AuthzFilter` has already installed on
 * the `SecurityContext`, so the tests stub that principal directly rather than minting tokens.
 *
 * The matrix: {required roles empty / set} × {SUPABASE / PLATFORM} × {aal1 / aal2 / null} ×
 * {global / entity role} × {allow-listed / not} × {no principal}. A refusal is expected only for a
 * SUPABASE token holding a required role that is neither aal2 nor on the allow-list.
 */
class AssuranceLevelFilterTest {

    private val backofficeRequired = config(
        roles = listOf("backoffice.admin"),
        allowed = listOf("GET /api/v1/users/profile"),
    )

    // AC1 — a verified second factor passes untouched.
    @Test
    fun `aal2 backoffice token passes`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = "aal2")))
    }

    // AC5 — the H5 exploit: a single-factor back-office token is refused.
    @Test
    fun `aal1 backoffice token is refused`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        assertThrows<MfaRequiredException> {
            filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = "aal1")))
        }
    }

    // AC6 — a missing aal claim counts as single-factor and is refused.
    @Test
    fun `backoffice token with no aal claim is refused`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        assertThrows<MfaRequiredException> {
            filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = null)))
        }
    }

    // AC7 — the legacy platform_admin maps to backoffice.admin before this filter runs, so an
    // aal1 principal carrying the mapped global role is refused just like a new-style one.
    @Test
    fun `aal1 principal with the mapped legacy role is refused`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        assertThrows<MfaRequiredException> {
            filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = "aal1")))
        }
    }

    // AC3 — a single-factor user may still reach an explicitly allow-listed endpoint.
    @Test
    fun `aal1 backoffice token reaches an allow-listed endpoint`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        filter.filter(
            request(
                principal(globalRoles = listOf("backoffice.admin"), aal = "aal1"),
                method = "GET",
                path = "api/v1/users/profile",
            ),
        )
    }

    // AC3 — the allow-list is method-specific: same path, different method, still refused.
    @Test
    fun `allow-list does not match a different method on the same path`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        assertThrows<MfaRequiredException> {
            filter.filter(
                request(
                    principal(globalRoles = listOf("backoffice.admin"), aal = "aal1"),
                    method = "POST",
                    path = "api/v1/users/profile",
                ),
            )
        }
    }

    // AC8 — a PLATFORM (API-key/service) token is exempt, even holding a required role at aal1.
    @Test
    fun `platform-sourced token is never refused`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        filter.filter(
            request(
                principal(
                    globalRoles = listOf("backoffice.admin"),
                    aal = "aal1",
                    tokenSource = TokenSource.PLATFORM,
                ),
            ),
        )
    }

    // A principal whose roles are not in the required set is unaffected.
    @Test
    fun `aal1 principal without a required role passes`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        filter.filter(request(principal(globalRoles = listOf("partner.user"), aal = "aal1")))
    }

    // AC2 — with no roles configured the filter changes nothing, even for an aal1 back-office token.
    @Test
    fun `empty required roles disables enforcement`() {
        val filter = AssuranceLevelFilter(config(roles = emptyList(), allowed = emptyList()))
        filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = "aal1")))
    }

    // AC9 — a request with no verified principal (public/ignored path) is never refused.
    @Test
    fun `no principal passes`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        val ctx = mock<ContainerRequestContext>()
        val sc = mock<SecurityContext>()
        whenever(sc.userPrincipal).thenReturn(null)
        whenever(ctx.securityContext).thenReturn(sc)
        filter.filter(ctx)
    }

    // A non-ApiPrincipal on the context is treated like no principal — never refused.
    @Test
    fun `non-ApiPrincipal passes`() {
        val filter = AssuranceLevelFilter(backofficeRequired)
        val ctx = mock<ContainerRequestContext>()
        val sc = mock<SecurityContext>()
        whenever(sc.userPrincipal).thenReturn(Principal { "not-an-api-principal" })
        whenever(ctx.securityContext).thenReturn(sc)
        filter.filter(ctx)
    }

    // An entity role (e.g. partner.admin) can be a required role too, and is refused at aal1.
    @Test
    fun `aal1 principal with a required entity role is refused`() {
        val filter = AssuranceLevelFilter(config(roles = listOf("partner.admin"), allowed = emptyList()))
        val principal = principal(
            globalRoles = emptyList(),
            aal = "aal1",
            entityRoles = listOf(EntityRole(type = "partner", roles = listOf("partner.admin"), ids = listOf("P1"))),
        )
        assertThrows<MfaRequiredException> { filter.filter(request(principal)) }
    }

    // Config validation: a malformed allow-list entry fails filter construction (and app start).
    @Test
    fun `malformed allow-list entry fails filter construction`() {
        val ex = assertThrows<IllegalArgumentException> {
            AssuranceLevelFilter(config(roles = listOf("backoffice.admin"), allowed = listOf("not-a-valid-entry")))
        }
        ex.message!!.contains("expected 'METHOD /path'")
    }

    // A blank default (from an unset @WithDefault("")) yields no required roles, not a blank role.
    @Test
    fun `blank config entries are ignored`() {
        val filter = AssuranceLevelFilter(config(roles = listOf("", "  "), allowed = listOf("")))
        // No required roles -> passes even an aal1 back-office token.
        filter.filter(request(principal(globalRoles = listOf("backoffice.admin"), aal = "aal1")))
    }

    // --- helpers ---

    private fun config(roles: List<String>, allowed: List<String>) = object : MfaEnforcementConfig {
        override fun aal2RequiredRoles(): List<String> = roles
        override fun aal1AllowedEndpoints(): List<String> = allowed
    }

    private fun principal(
        globalRoles: List<String>,
        aal: String?,
        tokenSource: TokenSource? = TokenSource.SUPABASE,
        entityRoles: List<EntityRole> = emptyList(),
    ) = ApiPrincipal(
        subject = UUID.randomUUID().toString(),
        userRole = UserRole.of(globalRoles.firstOrNull() ?: "backoffice.admin"),
        entityType = null,
        entityId = null,
        scopes = emptyList(),
        clientId = null,
        principalId = UUID.randomUUID(),
        globalRoles = globalRoles,
        entityRoles = entityRoles,
        authenticatorAssuranceLevel = aal,
        tokenSource = tokenSource,
    )

    private fun request(
        principal: Principal,
        method: String = "GET",
        path: String = "api/v1/users",
    ): ContainerRequestContext {
        val ctx = mock<ContainerRequestContext>()
        val sc = mock<SecurityContext>()
        whenever(sc.userPrincipal).thenReturn(principal)
        whenever(ctx.securityContext).thenReturn(sc)
        whenever(ctx.method).thenReturn(method)
        val uriInfo = mock<UriInfo>()
        whenever(uriInfo.path).thenReturn(path)
        whenever(ctx.uriInfo).thenReturn(uriInfo)
        return ctx
    }
}
