
package org.incept5.platform.core.auth

import jakarta.ws.rs.NameBinding

/**
 * Annotation for requiring specific OAuth scopes to access an endpoint.
 * This annotation works in conjunction with the ScopeAuthorizationFilter to enforce
 * scope-based authorization on REST endpoints.
 *
 * @property value The required scope for accessing the endpoint
 * @property scopeOnlyAuthorization If true then only scoped authentication is allowed
 * This means only tokens issued with API Keys are considered valid
 */
@NameBinding
@Target(AnnotationTarget.FUNCTION, AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
annotation class RequireScope(val value: String,
    val scopeOnlyAuthorization: Boolean = false)
