
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

## Development

```bash
./gradlew build   # Build
./gradlew test    # Run tests
```

## Requirements

- Java 21+
- Quarkus 3.22.2+
- Kotlin 2.1.0+
