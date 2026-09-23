package org.incept5.platform.core.authz

import org.incept5.error.CoreException
import org.incept5.error.Error
import org.incept5.error.ErrorCategory

/**
 * Thrown by [AssuranceLevelFilter] when a configured-role user presents a single-factor token for a
 * non-allow-listed endpoint.
 *
 * Extends [CoreException] directly (not `ApiException`) so the machine-readable error code is the
 * specific `MFA_REQUIRED` rather than the generic category name — error-lib's `RestErrorHandler`
 * surfaces `errors[0].code == "MFA_REQUIRED"` in the response body. [ErrorCategory.AUTHORIZATION]
 * maps to **HTTP 403** (deliberately not 401: consuming portals sign the user out on 401, so a 403
 * lets them route to a TOTP challenge instead of a full logout).
 */
class MfaRequiredException : CoreException(
    category = ErrorCategory.AUTHORIZATION,
    errors = listOf(Error("MFA_REQUIRED")),
    message = "A multi-factor authenticated session is required for this role",
)
