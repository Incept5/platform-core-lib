
# Platform Core Library

[![Build and Publish](https://github.com/incept5/platform-core-lib/actions/workflows/build-and-publish.yml/badge.svg)](https://dl.circleci.com/status-badge/redirect/gh/incept5/platform-core-lib/tree/main)
[![](https://jitpack.io/v/incept5/platform-core-lib.svg)](https://jitpack.io/#incept5/platform-core-lib)

Standalone Kotlin library providing platform-level utilities and components for Quarkus applications.

## Overview

This library contains reusable platform utilities and components designed for Quarkus applications:

- **Authentication & Authorization**: JWT validation, security filters, scope-based access control
- **Configuration**: Shared configuration utilities and startup logging
- **Domain Utilities**: ULID generation and ID services
- **Rate Limiting**: Comprehensive rate limiting with annotations and interceptors
- **Security**: Authentication mechanisms, JWT validation, API principals
- **Basic Error Handling**: Core exception types and security exception mapping
- **HTTP Logging**: Request logging and correlation ID management

## Installation

### Add JitPack Repository

Add the JitPack repository to your build configuration:

**Gradle (Kotlin DSL)**
```kotlin
repositories {
    mavenCentral()
    maven { url = uri("https://jitpack.io") }
}

dependencies {
    implementation("com.github.incept5:platform-core-lib:1.0.X")
}
```

**Gradle (Groovy)**
```groovy
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'com.github.incept5:platform-core-lib:1.0.X'
}
```

**Maven**
```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>

<dependencies>
    <dependency>
        <groupId>com.github.incept5</groupId>
        <artifactId>platform-core-lib</artifactId>
        <version>1.0.X</version>
    </dependency>
</dependencies>
```

> **Note**: Replace `1.0.X` with the latest version from the [releases page](https://github.com/incept5/platform-core-lib/releases) or use `main-SNAPSHOT` for the latest development version.

## Package Structure

```
org.incept5.platform.core/
├── auth/           # Authentication & authorization (@Authenticated, @RequireScope)
├── config/         # Configuration utilities and startup logging
├── domain/         # ID generation (ULID)
├── error/          # Basic exception handling (ApiException)
├── logging/        # HTTP request logging and correlation ID management
├── model/          # Core data models (UserRole, EntityType)
├── ratelimit/      # Rate limiting (@RateLimit annotation and services)
└── security/       # JWT validation, ApiPrincipal, security utilities
```

## Usage Examples

### Authentication & Authorization

```kotlin
@RestController
@Path("/api/users")
class UserController {

    @GET
    @Authenticated
    @RequireScope("user:read")
    fun getUsers(principal: ApiPrincipal): List<User> {
        // Only authenticated users with 'user:read' scope can access
        return userService.findAll()
    }

    @POST
    @Authenticated(allowedRoles = ["platform_admin", "entity_admin"])
    fun createUser(user: CreateUserRequest, principal: ApiPrincipal): User {
        // Only admins can create users
        return userService.create(user)
    }
}
```

### ULID Generation

```kotlin
@ApplicationScoped
class OrderService {
    
    @Inject
    lateinit var ulidGenerator: UlidGenerator
    
    fun createOrder(): Order {
        val orderId = ulidGenerator.generateWithPrefix("ORDER")
        return Order(id = orderId, ...)
    }
}
```

### Rate Limiting

```kotlin
@RestController
@Path("/api/public")
class PublicController {

    @GET
    @Path("/search")
    @RateLimit(maxRequests = 100, windowSeconds = 3600) // 100 requests per hour
    fun search(@QueryParam("q") query: String): SearchResults {
        return searchService.search(query)
    }

    @POST
    @Path("/contact")
    @RateLimit(maxRequests = 5, windowSeconds = 300) // 5 requests per 5 minutes
    fun submitContact(contactForm: ContactForm): Response {
        contactService.processContact(contactForm)
        return Response.ok().build()
    }
}
```

### Basic Error Handling

```kotlin
@ApplicationScoped
class UserService {
    
    fun findUserById(id: String): User {
        return userRepository.findById(id) 
            ?: throw ApiException("User not found with id: $id")
    }
}
```

### Accessing User Information

```kotlin
@ApplicationScoped
class ProfileService {
    
    fun getCurrentUserProfile(principal: ApiPrincipal): UserProfile {
        return when (principal.userRole) {
            UserRole.PLATFORM_ADMIN -> getAdminProfile(principal.subject)
            UserRole.ENTITY_ADMIN -> getEntityAdminProfile(principal.subject, principal.entityId)
            UserRole.ENTITY_USER -> getUserProfile(principal.subject, principal.entityId)
            else -> throw ApiException("Insufficient permissions")
        }
    }
}
```

## Configuration

### Required Dependencies

This library requires Quarkus 3.22.2+ and Java 21+. It automatically integrates with:
- Quarkus CDI for dependency injection
- Quarkus Security for authentication
- JAX-RS for REST endpoints

### JWT Validation Configuration

The `DualJwtValidator` supports validation of tokens from two sources: Supabase and Platform OAuth. It supports both RSA (recommended) and HMAC signature verification.

> **📝 Note**: RSA configuration properties (`rsa-jwt.public-key` and `rsa-jwt.jwks-url`) are **truly optional**. Your application will start successfully even if these properties are not defined. See [OPTIONAL_RSA_CONFIG.md](OPTIONAL_RSA_CONFIG.md) for detailed configuration scenarios.

#### Required Properties

```yaml
# JWT secret for HMAC token validation (base64 encoded)
supabase:
  jwt:
    secret: your-base64-encoded-jwt-secret

# Base API URL for token issuer validation
api:
  base:
    url: https://your-api-domain.com
```

#### RSA Verification (Optional - Recommended for Platform Tokens)

```yaml
# Enable RSA verification (default: true)
rsa-jwt:
  enabled: true
  
  # Option 1: Use JWKS endpoint (recommended for production)
  # ⚠️ OPTIONAL - omit if not using RSA
  jwks-url: https://your-api-domain.com/.well-known/jwks.json
  
  # Option 2: Use explicit public key (PEM format, base64 encoded)
  # ⚠️ OPTIONAL - omit if not using RSA
  public-key: your-base64-encoded-public-key
  
  # HMAC fallback for platforms not yet migrated (default: false)
  hmac-fallback:
    enabled: false
```

> **💡 Tip**: If you only need Supabase token validation or Platform tokens with HMAC, you can completely omit the `rsa-jwt.public-key` and `rsa-jwt.jwks-url` properties. Set `rsa-jwt.enabled=false` and `rsa-jwt.hmac-fallback.enabled=true` instead.

**Configuration Priority:**
1. **JWKS URL** (highest priority) - Fetches public keys from a JWKS endpoint
2. **Explicit Public Key** - Uses a configured RSA public key
3. **HMAC Fallback** (lowest priority) - Falls back to HMAC256 if enabled

#### Optional Properties

```yaml
# Supabase auth path (default: /auth/v1)
auth:
  supabase:
    path: /auth/v1
  # Platform OAuth path (default: /api/v1/oauth/token)
  platform:
    oauth:
      path: /api/v1/oauth/token
```

#### Token Source Detection

The validator automatically detects token sources based on the `issuer` claim:

- **Supabase tokens**: `issuer` = `{api.base.url}{auth.supabase.path}`
- **Platform tokens**: `issuer` = `{api.base.url}{auth.platform.oauth.path}`

#### Supabase Token Format

Supabase tokens should contain:
- `sub`: User subject ID
- `role`: User role (maps to `UserRole` enum)
- `app_metadata`: Object containing:
  - `entity_type`: Optional entity type (maps to `EntityType` enum)
  - `entity_id`: Optional entity ID

#### Platform Token Format

Platform tokens should contain:
- `sub`: Client ID (for client_credentials flow)
- `role`: User role (maps to `UserRole` enum) 
- `scopes`: Array of explicit scopes
- `app_metadata`: Object containing:
  - `entity_type`: Optional entity type
  - `entity_id`: Optional entity ID

#### Example Configurations

**Production Configuration (RSA with JWKS)**
```yaml
supabase:
  jwt:
    secret: eW91ci1iYXNlNjQtZW5jb2RlZC1qd3Qtc2VjcmV0

api:
  base:
    url: https://api.yourcompany.com

rsa-jwt:
  enabled: true
  jwks-url: https://api.yourcompany.com/.well-known/jwks.json

auth:
  supabase:
    path: /auth/v1
  platform:
    oauth:
      path: /api/v1/oauth/token
```

**Migration Configuration (RSA with HMAC Fallback)**
```yaml
supabase:
  jwt:
    secret: eW91ci1iYXNlNjQtZW5jb2RlZC1qd3Qtc2VjcmV0

api:
  base:
    url: https://api.yourcompany.com

rsa-jwt:
  enabled: true
  public-key: LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K...
  hmac-fallback:
    enabled: true  # Allows HMAC tokens during migration

auth:
  supabase:
    path: /auth/v1
  platform:
    oauth:
      path: /api/v1/oauth/token
```

**Simple Configuration (HMAC Only - No RSA Properties Needed)**
```yaml
supabase:
  jwt:
    secret: eW91ci1iYXNlNjQtZW5jb2RlZC1qd3Qtc2VjcmV0

api:
  base:
    url: https://api.yourcompany.com

rsa-jwt:
  enabled: false
  hmac-fallback:
    enabled: true
  # ✨ No need to specify public-key or jwks-url!

auth:
  supabase:
    path: /auth/v1
  platform:
    oauth:
      path: /api/v1/oauth/token
```

> **✅ This is the simplest configuration** - perfect for services that only use Supabase tokens or Platform tokens with HMAC signing. No RSA properties required!

For more configuration scenarios and details, see [OPTIONAL_RSA_CONFIG.md](OPTIONAL_RSA_CONFIG.md).

### CDI Bean Discovery

All components use standard CDI annotations (`@ApplicationScoped`, `@Inject`) and are automatically discoverable by Quarkus applications. No additional configuration is needed.

## Core Components

### User Roles

The library defines a comprehensive role hierarchy:

```kotlin
enum class UserRole {
    PLATFORM_ADMIN,     // Full platform access
    SERVICE_ROLE,       // Service-to-service communication
    ENTITY_ADMIN,       // Entity administration
    ENTITY_USER,        // Standard entity user
    ENTITY_READONLY     // Read-only entity access
}
```

### Entity Types

Support for different entity contexts:

```kotlin
enum class EntityType {
    PARTNER,
    MERCHANT
}
```

### API Principal

Access authenticated user information:

```kotlin
class ApiPrincipal(
    val subject: String,
    val userRole: UserRole,
    val entityType: EntityType?,
    val entityId: String?,
    val scopes: List<String>,
    val clientId: String?
)
```

## Development

### Building from Source

```bash
git clone https://github.com/incept5/platform-core-lib.git
cd platform-core-lib
./gradlew build
```

### Running Tests

```bash
./gradlew test
```

### Publishing to Local Maven

```bash
./gradlew publishToMavenLocal
```

## Requirements

- **Java**: 21+
- **Quarkus**: 3.22.2+
- **Kotlin**: 2.1.0+

## Dependencies

### Core Dependencies
- **Quarkus Platform**: CDI, REST, Security, Hibernate Validator
- **Authentication**: JWT validation (java-jwt)
- **ID Generation**: ULID Creator
- **Rate Limiting**: Bucket4j
- **HTTP Logging**: Zalando Logbook
- **Cryptography**: BCrypt, Apache Commons Codec

### External Incept5 Libraries
- **Incept5 Correlation**: Request correlation utilities  
- **Incept5 Error Library**: Enhanced error handling for Quarkus
- **Incept5 Cryptography**: Cryptographic utilities

## Architecture Principles

### What's Included ✅
- Cross-cutting concerns (HTTP logging, correlation)
- Authentication and security infrastructure
- Shared configuration and utilities  
- Common domain utilities (ID generation)
- Rate limiting infrastructure
- Platform-level components reused across applications

### What's Excluded ❌
- Business domain logic
- Application-specific utilities
- Database entities (except base classes)
- API endpoints or controllers
- Complex error handling and structured logging
- Session management

## Versioning

This library follows semantic versioning:
- **Major version**: Breaking API changes
- **Minor version**: New features, backward compatible
- **Patch version**: Bug fixes

Released versions are available on [JitPack](https://jitpack.io/#incept5/platform-core-lib).

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Ensure all tests pass (`./gradlew test`)
5. Commit your changes (`git commit -am 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## License

This project is licensed under the Apache License, Version 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/incept5/platform-core-lib/issues)
- **Documentation**: This README and inline code documentation
- **Latest Version**: [![JitPack](https://jitpack.io/v/incept5/platform-core-lib.svg)](https://jitpack.io/#incept5/platform-core-lib)

---

Built with ❤️ for the Quarkus ecosystem by [Incept5](https://github.com/incept5)
