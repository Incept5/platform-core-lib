# Platform Core Library

[![CircleCI](https://dl.circleci.com/status-badge/img/gh/incept5/platform-core-lib/tree/main.svg?style=svg)](https://dl.circleci.com/status-badge/redirect/gh/incept5/platform-core-lib/tree/main)
[![](https://jitpack.io/v/incept5/platform-core-lib.svg)](https://jitpack.io/#incept5/platform-core-lib)

Standalone Kotlin library providing platform-level utilities and components for Quarkus applications.

## Overview

This library contains reusable platform utilities and components designed for Quarkus applications:

- **Authentication & Authorization**: JWT validation, security filters, scope-based access control
- **Configuration**: Shared configuration utilities and startup logging
- **Domain Utilities**: ULID generation, ID services, session management
- **Error Handling**: Global exception mappers, structured error responses
- **Logging**: Correlation ID management, structured logging, audit logging, sensitive data masking
- **Rate Limiting**: Comprehensive rate limiting with annotations and interceptors
- **Security**: Authentication mechanisms, JWT validation, API principals

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
├── domain/         # ID generation (ULID), session management
├── error/          # Global exception mapping and error responses
├── logging/        # Correlation ID, structured logging, audit logging
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
}
```

### Structured Logging

```kotlin
@ApplicationScoped
class PaymentService {
    
    @Inject
    lateinit var structuredLogger: StructuredLogger
    
    @Inject 
    lateinit var auditLogger: AuditLogger
    
    fun processPayment(payment: Payment) {
        structuredLogger.info("Processing payment") {
            put("paymentId", payment.id)
            put("amount", payment.amount)
            put("currency", payment.currency)
        }
        
        // Process payment...
        
        auditLogger.logPaymentProcessed(payment.id, payment.amount)
    }
}
```

### Error Handling

The library provides automatic global exception handling. Simply throw `ApiException` or let validation exceptions bubble up:

```kotlin
@ApplicationScoped
class UserService {
    
    fun findUserById(id: String): User {
        return userRepository.findById(id) 
            ?: throw ApiException.notFound("User not found with id: $id")
    }
}
```

## Configuration

### Required Dependencies

This library requires Quarkus 3.22.2+ and Java 21+. It automatically integrates with:
- Quarkus CDI for dependency injection
- Quarkus Security for authentication
- Quarkus Logging for structured logging
- JAX-RS for REST endpoints

### JWT Validation Configuration

The `DualJwtValidator` supports validation of tokens from two sources: Supabase and Platform OAuth. Configure the following properties in your `application.properties` or `application.yml`:

#### Required Properties

```properties
# JWT secret for token validation (base64 encoded)
supabase.jwt.secret=your-base64-encoded-jwt-secret

# Base API URL for token issuer validation
api.base.url=https://your-api-domain.com
```

#### Optional Properties

```properties
# Supabase auth path (default: /auth/v1)
auth.supabase.path=/auth/v1

# Platform OAuth path (default: /api/v1/oauth/token)
auth.platform.oauth.path=/api/v1/oauth/token
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

#### Example Configuration

**application.properties**
```properties
supabase.jwt.secret=eW91ci1iYXNlNjQtZW5jb2RlZC1qd3Qtc2VjcmV0
api.base.url=https://api.yourcompany.com
auth.supabase.path=/auth/v1
auth.platform.oauth.path=/api/v1/oauth/token
```

**application.yml**
```yaml
supabase:
  jwt:
    secret: eW91ci1iYXNlNjQtZW5jb2RlZC1qd3Qtc2VjcmV0

api:
  base:
    url: https://api.yourcompany.com

auth:
  supabase:
    path: /auth/v1
  platform:
    oauth:
      path: /api/v1/oauth/token
```

### CDI Bean Discovery

All components use standard CDI annotations (`@ApplicationScoped`, `@Inject`) and are automatically discoverable by Quarkus applications. No additional configuration is needed.

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
- **Reactive HTTP**: Spring WebFlux, Reactor Netty

### External Libraries
- **Incept5 Correlation**: Request correlation utilities  
- **Incept5 Error Handling**: Quarkus error handling extensions
- **Incept5 Cryptography**: Cryptographic utilities

## Architecture Principles

### What's Included ✅
- Cross-cutting concerns (logging, correlation, error handling)
- Authentication and security infrastructure
- Shared configuration and utilities  
- Common domain utilities (ID generation, validation)
- Platform-level components reused across applications

### What's Excluded ❌
- Business domain logic
- Application-specific utilities
- Database entities (except base classes)
- API endpoints or controllers
- Payment/Partner/Merchant specific code

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
