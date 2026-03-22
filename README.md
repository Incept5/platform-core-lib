
# Platform Core Library

[![Build and Publish](https://github.com/incept5/platform-core-lib/actions/workflows/build-and-publish.yml/badge.svg)](https://dl.circleci.com/status-badge/redirect/gh/incept5/platform-core-lib/tree/main)
[![](https://jitpack.io/v/incept5/platform-core-lib.svg)](https://jitpack.io/#incept5/platform-core-lib)

Shared Kotlin library for Quarkus applications providing JWT validation, token exchange, scope-based authorization, rate limiting, and platform utilities.

## Installation

```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.incept5:platform-core-lib:1.0.X")
}
```

> Replace `1.0.X` with the latest version from [JitPack](https://jitpack.io/#incept5/platform-core-lib).

## Package Structure

```
org.incept5.platform.core/
├── auth/           # Scope-based authorization (@RequireScope)
├── authz/          # Token exchange plugin and ApiPrincipal
├── config/         # Configuration utilities and startup logging
├── domain/id/      # ULID generation
├── error/          # Core exception types (ApiException)
├── logging/        # HTTP request logging and correlation IDs
├── model/          # Core models (UserRole)
├── ratelimit/      # Rate limiting (@RateLimit annotation)
└── security/       # JWT validation (DualJwtValidator)
```

## ApiPrincipal

The `ApiPrincipal` is the rich principal returned by the `SupabaseTokenExchangePlugin` after JWT validation. It implements `PrincipalContext` (from authz-lib) which extends `java.security.Principal`, making it available from the standard JAX-RS `SecurityContext`.

```kotlin
data class ApiPrincipal(
    val subject: String,        // user ID or client ID
    val userRole: UserRole,     // role from the JWT
    val entityType: String?,    // e.g. "partner", "merchant"
    val entityId: String?,      // entity ID
    val scopes: List<String>,   // OAuth scopes (API key tokens)
    val clientId: String?,      // OAuth client ID
    // ... plus PrincipalContext fields (principalId, globalRoles, entityRoles)
)
```

### Accessing ApiPrincipal in endpoints

**Via JAX-RS SecurityContext:**

```kotlin
@Path("/api/users")
class UserResource {

    @GET
    @Path("/me")
    fun me(@Context securityContext: SecurityContext): Response {
        val principal = securityContext.userPrincipal as ApiPrincipal
        return Response.ok(
            mapOf(
                "userId" to principal.subject,
                "role" to principal.userRole.value,
                "entityType" to principal.entityType,
                "entityId" to principal.entityId,
                "scopes" to principal.scopes
            )
        ).build()
    }
}
```

**Via CDI-injected PrincipalService:**

```kotlin
@ApplicationScoped
class ProfileService(
    private val principalService: RequestScopePrincipalService
) {
    fun getCurrentProfile(): UserProfile {
        val principal = principalService.ensurePrincipal() as ApiPrincipal
        return buildProfile(principal.subject, principal.entityType, principal.entityId)
    }
}
```

### UserRole

`UserRole` is a simple interface wrapping a role name string. Role values come directly from the JWT and are passed through without interpretation by this library. Role-to-permission mapping is handled by authz-lib configuration in the consuming application.

```kotlin
val role: UserRole = UserRole.of("partner.admin")
role.value // "partner.admin"
```

## Token Exchange

The `SupabaseTokenExchangePlugin` implements authz-lib's `TokenExchangePlugin` interface. It validates incoming JWTs using `DualJwtValidator` and returns an `ApiPrincipal` with mapped roles and entity context.

The plugin handles legacy role name mapping (e.g. `platform_admin` to `backoffice.admin`) during the transition period. This mapping will be removed in a future release once all tokens use the new role names directly.

## Scope Authorization

Use `@RequireScope` to enforce OAuth scope checks on endpoints. This is designed for API key tokens that carry explicit scopes.

```kotlin
@GET
@Path("/transactions")
@RequireScope("transactions:read")
fun listTransactions(): List<Transaction> {
    // Only API key tokens with 'transactions:read' scope can access
}

@POST
@Path("/webhooks")
@RequireScope("webhooks:manage", scopeOnlyAuthorization = true)
fun createWebhook(request: WebhookRequest): Response {
    // scopeOnlyAuthorization = true means ONLY API key tokens are allowed
    // (user tokens are rejected even if authenticated)
}
```

User tokens (without a `clientId`) bypass scope checks since scopes only apply to API key tokens.

## Rate Limiting

Apply rate limits to endpoints using the `@RateLimit` annotation:

```kotlin
@POST
@Path("/contact")
@RateLimit(requestsPerMinute = 10, key = "contact-form")
fun submitContact(form: ContactForm): Response {
    // Limited to 10 requests per minute per IP
}
```

## ULID Generation

Inject `UlidService` for time-sortable unique ID generation:

```kotlin
@ApplicationScoped
class OrderService(private val ulidService: UlidService) {
    fun createOrder(): Order {
        val orderId = ulidService.generate()
        return Order(id = orderId)
    }
}
```

## JWT Validation Configuration

The `DualJwtValidator` validates tokens from two sources: Supabase and Platform OAuth. It supports RSA (recommended) and HMAC signature verification.

### Required Properties

```yaml
supabase:
  jwt:
    secret: your-base64-encoded-jwt-secret

api:
  base:
    url: https://your-api-domain.com
```

### RSA Verification (Optional)

```yaml
rsa-jwt:
  enabled: true
  # Option 1: JWKS endpoint (recommended for production)
  jwks-url: https://your-api-domain.com/.well-known/jwks.json
  # Option 2: Explicit public key (PEM format, base64 encoded)
  public-key: your-base64-encoded-public-key
  # HMAC fallback during migration (default: false)
  hmac-fallback:
    enabled: false
```

**Configuration priority:** JWKS URL > Explicit Public Key > HMAC Fallback

For HMAC-only setups (simplest configuration), set `rsa-jwt.enabled=false` and `rsa-jwt.hmac-fallback.enabled=true`. No RSA properties needed.

See [OPTIONAL_RSA_CONFIG.md](OPTIONAL_RSA_CONFIG.md) for detailed configuration scenarios.

### Optional Properties

```yaml
auth:
  supabase:
    path: /auth/v1              # default
  platform:
    oauth:
      path: /api/v1/oauth/token # default
```

### Token Formats

**Supabase tokens** contain: `sub` (user ID), `role` (user role), and optionally `app_metadata.entity_type` and `app_metadata.entity_id`.

**Platform tokens** contain: `sub` (client ID), `role` (user role), `scopes` (array), and optionally `app_metadata.entity_type` and `app_metadata.entity_id`.

Token source is detected automatically from the `issuer` claim.

## Protecting Endpoints

This library works with [authz-lib](https://github.com/incept5/authz-lib) to provide annotation-driven access control. Protection starts at the controller level and works in layers.

### Step 1: Annotate the Controller

Mark the class with `@Authorized` and each method with `@AuthzCheck`:

```kotlin
@Path("/api/v1/users")
@Authorized
class UserController {

    @Inject
    lateinit var userService: UserService

    @GET
    @Path("/{userId}")
    @AuthzCheck(ReadUserAccessControl::class)
    fun getUser(@PathParam("userId") userId: UUID): UserResponse {
        return userService.getUser(userId)
    }

    @POST
    @AuthzCheck(CreateUserAccessControl::class)
    fun createUser(request: CreateUserRequest): UserResponse {
        return userService.createUser(request)
    }
}
```

Both annotations are required — `@Authorized` activates the interceptor, `@AuthzCheck` binds the access control logic.

### Step 2: Write an AccessControl Class

Use `ctx.authz()` to access the `AuthzContext` helper methods. The general pattern is:

- **Backoffice users** have global permissions and typically get full access — check with `principalHasGlobalPermission()`
- **Entity users** (partners, merchants) are restricted to their domain — match entity IDs against the principal's allowed IDs
- If the entity ID is **in the path** (e.g. `/partner/{partnerId}`), validate in `before()` using the method arguments
- If the entity ID is **only in the result**, validate in `after()` by inspecting the returned object
- If the entity ID is **not directly available**, inject a repository to look it up

### Simple Case: Entity ID in the Path

When the entity ID comes from the request (path param, request body):

```kotlin
class CreateUserAccessControl : BaseEntityAccessControl(
    permission = Permission.of("users:create"),
    entityType = "org",
    extractEntityId = { ctx -> ctx.firstOfType(CreateUserRequest::class.java).orgId }
)
```

### Full Example: Entity ID Only in the Result

When the entity ID is not in the request, enforce scoping in `after()`:

```kotlin
class ReadUserAccessControl : AccessControl<Any?> {

    private val permission = Permission.of("user:read")

    override fun before(ctx: DefaultAccessControlContext) {
        // Pre-check: principal has the permission at all (global or entity-level)
        ctx.authz().ensureOperationAllowedForPrincipal(permission)
    }

    override fun after(result: Any?, ctx: DefaultAccessControlContext): Any? {
        if (result !is UserResponse) return result

        val targetEntityId = result.entityId ?: return result

        // Backoffice users have global permission — allow access to any user
        if (ctx.authz().principalHasGlobalPermission(permission)) {
            return result
        }

        // Partner-scoped: target user's entityId must match principal's partner IDs
        if (ctx.authz().principalHasEntityRole("partner")) {
            val allowedIds = ctx.authz().specificEntityIds(permission, "partner")
            if (targetEntityId !in allowedIds) {
                throw AuthzException(
                    AuthzErrorCodes.PERMISSION_DENIED,
                    "User access denied: principal does not have access to user in entity $targetEntityId"
                )
            }
            return result
        }

        // Merchant-scoped: target user's entityId must match principal's merchant IDs
        if (ctx.authz().principalHasEntityRole("merchant")) {
            val allowedIds = ctx.authz().specificEntityIds(permission, "merchant")
            if (targetEntityId !in allowedIds) {
                throw AuthzException(
                    AuthzErrorCodes.PERMISSION_DENIED,
                    "User access denied: principal does not have access to user in entity $targetEntityId"
                )
            }
            return result
        }

        throw AuthzException(
            AuthzErrorCodes.PERMISSION_DENIED,
            "User access denied: principal has no entity scope for user in entity $targetEntityId"
        )
    }
}
```

### Repository Lookup: Entity ID Not in Path or Result

When you need to resolve entity ownership from another source (e.g. a transaction ID in the path), make the `AccessControl` class a CDI bean and inject a repository:

```kotlin
@ApplicationScoped
class ReadTransactionAccessControl : AccessControl<Any?> {

    @Inject
    lateinit var transactionRepository: TransactionRepository

    private val permission = Permission.of("transaction:read")

    override fun before(ctx: DefaultAccessControlContext) {
        ctx.authz().ensureOperationAllowedForPrincipal(permission)

        // Backoffice can access anything
        if (ctx.authz().principalHasGlobalPermission(permission)) return

        // Look up the transaction to find which entity owns it
        val transactionId = ctx.firstArg<String>()
        val transaction = transactionRepository.findById(transactionId)
            ?: throw AuthzException(AuthzErrorCodes.PERMISSION_DENIED, "Transaction not found")

        // Check partner access
        if (ctx.authz().principalHasEntityRole("partner")) {
            val allowedIds = ctx.authz().specificEntityIds(permission, "partner")
            if (transaction.partnerId !in allowedIds) {
                throw AuthzException(AuthzErrorCodes.PERMISSION_DENIED, "Access denied to transaction")
            }
            return
        }

        // Check merchant access
        if (ctx.authz().principalHasEntityRole("merchant")) {
            val allowedIds = ctx.authz().specificEntityIds(permission, "merchant")
            if (transaction.merchantId !in allowedIds) {
                throw AuthzException(AuthzErrorCodes.PERMISSION_DENIED, "Access denied to transaction")
            }
            return
        }

        throw AuthzException(AuthzErrorCodes.PERMISSION_DENIED, "No entity scope for transaction")
    }
}
```

### Configuring Roles and Permissions

Define roles in the consuming application's `application.yaml`:

```yaml
incept5:
  authz:
    roles:
      - name: backoffice.admin
        permissions:
          - ".*:all"              # wildcard — full access to everything
      - name: partner.user
        permissions:
          - partner:read
          - webhook:read
      - name: partner.admin
        extends-role: partner.user  # inherits partner.user permissions
        permissions:
          - partner:update
          - webhook:create
      - name: merchant.user
        permissions:
          - merchant:read
      - name: merchant.admin
        extends-role: merchant.user
        permissions:
          - merchant:update
```

The `SupabaseTokenExchangePlugin` maps JWT claims to these roles automatically. The authz framework resolves role inheritance and permission matching at runtime.

### AuthzContext Helper Methods

| Method | Use |
|--------|-----|
| `ensureOperationAllowedForPrincipal(perm)` | Pre-check: principal has the permission globally or for any entity |
| `principalHasGlobalPermission(perm)` | Check if backoffice-level (global) access — if true, skip entity checks |
| `principalHasEntityRole(type)` | Check if the principal has any role for an entity type (e.g. "partner") |
| `specificEntityIds(perm, type)` | Get the list of entity IDs the principal can access for a permission + type |
| `ensurePrincipalHasPermission(perm, type, entityId)` | All-in-one: checks global OR entity-scoped access for a specific entity ID |
| `principalHasPermission(perm, type, entityId)` | Boolean version of the above |

## Development

```bash
./gradlew build   # Build
./gradlew test    # Run tests
```

## Requirements

- Java 21+
- Quarkus 3.22.2+
- Kotlin 2.1.0+
