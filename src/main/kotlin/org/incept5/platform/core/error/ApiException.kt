
package org.incept5.platform.core.error

import org.incept5.error.CoreException
import org.incept5.error.Error
import org.incept5.error.ErrorCategory

/**
 * Base exception class for API-related errors that extends CoreException.
 * This class provides a convenient way to wrap CoreException with specific error categories.
 *
 * @param message The detailed error message
 * @param errorCategory The category of the error from ErrorCategory enum
 * @param cause The original cause of the exception (optional)
 */
open class ApiException(
    message: String,
    errorCategory: ErrorCategory,
    cause: Throwable? = null
) : CoreException(errorCategory, listOf(Error(errorCategory.name)), message, cause)

/**
 * Exception thrown when a user is not authorized to perform an action.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class ForbiddenException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.AUTHORIZATION, cause)

/**
 * Exception thrown when authentication is required and is not provided or has failed.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class UnauthorizedException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.AUTHENTICATION, cause)

/**
 * Exception thrown when a requested resource cannot be found.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class NotFoundException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.NOT_FOUND, cause)

/**
 * Exception thrown when the request is invalid or contains validation errors.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class InvalidRequestException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.VALIDATION, cause)

/**
 * Exception thrown when a specific resource cannot be found in the system.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class ResourceNotFoundException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.NOT_FOUND, cause)

/**
 * Exception thrown when there is a conflict in updating a resource due to concurrent modifications.
 * This typically occurs in optimistic locking scenarios where the resource has been modified
 * by another user since it was last retrieved.
 *
 * @param message The detailed error message (defaults to "Resource has been modified by another user")
 * @param cause The original cause of the exception (optional)
 */
class OptimisticLockException(
    message: String = "Resource has been modified by another user",
    cause: Throwable? = null
) : ApiException(message, ErrorCategory.CONFLICT, cause)

/**
 * Exception thrown when there is a conflict with the request, such as a duplicate resource.
 *
 * @param message The detailed error message
 * @param cause The original cause of the exception (optional)
 */
class ConflictException(message: String, cause: Throwable? = null) :
    ApiException(message, ErrorCategory.CONFLICT, cause)
