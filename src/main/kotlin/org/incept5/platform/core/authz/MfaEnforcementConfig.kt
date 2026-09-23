package org.incept5.platform.core.authz

import io.quarkus.runtime.annotations.StaticInitSafe
import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault
import io.smallrye.config.WithName

/**
 * Configuration for server-side MFA (AAL2) enforcement, read by [AssuranceLevelFilter].
 *
 * Both keys default to empty, so the library is behaviour-neutral until a consuming application
 * opts in — no principal is ever refused unless [aal2RequiredRoles] is non-empty.
 *
 * `List<String>` with a blank `@WithDefault` (rather than `Optional<List<String>>`) follows the
 * `@WithDefault` precedent in `RateLimitConfig`; an unset key resolves to an empty/blank list which
 * the filter treats as "no enforcement". Entries are comma-separated (SmallRye's list convention),
 * so an allow-list value like `GET /api/v1/users/profile` — which contains a space but no comma —
 * is a single entry.
 */
@ConfigMapping(prefix = "auth.mfa")
@StaticInitSafe
interface MfaEnforcementConfig {

    /**
     * Mapped role names (e.g. `backoffice.admin`) whose Supabase user tokens must be `aal2`
     * (password **+** verified TOTP). Empty disables enforcement entirely. Compared against the
     * principal's mapped global and entity roles, so the legacy `platform_admin` — which the token
     * exchange maps to `backoffice.admin` — is covered by listing `backoffice.admin` alone.
     */
    @WithName("aal2-required-roles")
    @WithDefault("")
    fun aal2RequiredRoles(): List<String>

    /**
     * Exact `METHOD /path` entries a single-factor (`aal1`/no-`aal`) user holding a required role
     * may still reach — e.g. `GET /api/v1/users/profile` for the invite flow's pre-enrolment
     * profile load. Exact matches only, no wildcards, so the single-factor surface is explicit and
     * reviewable. A malformed entry fails filter construction (see [AssuranceLevelFilter]).
     */
    @WithName("aal1-allowed-endpoints")
    @WithDefault("")
    fun aal1AllowedEndpoints(): List<String>
}
