
# Platform Core Library (Internal)

Internal shared core functionality library for platform applications, extracted from quarkus-api core modules.

## Overview

This library contains platform-level utilities and components that are shared across platform applications:

- **Authentication**: JWT validation, security filters, annotations
- **Configuration**: Shared configuration beans and utilities
- **Domain**: Common utilities (ULID generation, validation, base entities)
- **Error Handling**: Global exception mappers and error responses
- **Logging**: Correlation ID management and structured logging
- **Model**: Core data models (UserRole, EntityType)
- **Rate Limiting**: Business logic for API rate limiting
- **Security**: Authentication and authorization utilities

## Package Structure

```
org.incept5.platform.core/
├── auth/           # Authentication & authorization filters, annotations
├── config/         # Application-wide configuration beans
├── domain/         # Shared domain utilities (ULID generation, etc.)
├── error/          # Global exception mappers and error handling
├── logging/        # Correlation ID and request/response logging
├── model/          # Core data models (UserRole, EntityType)
├── ratelimit/      # Rate limiting infrastructure and business logic
└── security/       # JWT validation, ApiPrincipal, security utilities
```

## Package Migration

This library represents a package migration from:
- **From**: `org.incept5.api.core.*`
- **To**: `org.incept5.platform.core.*`

This change enables clear separation between platform concerns and application-specific business logic.

## Usage within Monorepo

### Adding Dependency

```kotlin
// In consuming module's build.gradle.kts
dependencies {
    implementation(project(":backend:libs:platform-core-lib"))
}
```

### Example Usage

```kotlin
import org.incept5.platform.core.auth.annotation.Authenticated
import org.incept5.platform.core.security.principal.ApiPrincipal
import org.incept5.platform.core.domain.id.UlidGenerator

@ApplicationScoped
class MyService {
    
    @Inject
    lateinit var ulidGenerator: UlidGenerator
    
    @Authenticated
    fun secureOperation(principal: ApiPrincipal): String {
        val id = ulidGenerator.generateWithPrefix("TEST")
        return "Operation completed with ID: $id"
    }
}
```

## Development

### Building

```bash
# From project root
./gradlew :backend:libs:platform-core-lib:build
./gradlew :backend:libs:platform-core-lib:test
```

### Integration

This library is automatically built as part of the monorepo build process.
All components use CDI and are automatically discoverable by Quarkus applications.

## Design Principles

### What Belongs in Platform Core Library
- 🟢 Authentication and security infrastructure shared across Quarkus apps
- 🟢 Global error handling and exception mapping patterns
- 🟢 Shared configuration beans and utilities
- 🟢 Common domain utilities (ULID generation, validation)
- 🟢 Cross-cutting concerns (logging, correlation)
- 🟢 Base models used across multiple domains

### What Does NOT Belong in Platform Core Library
- 🔴 Business domain logic specific to applications
- 🔴 Application-specific utilities
- 🔴 Database entities (except base classes)
- 🔴 Module-specific configuration
- 🔴 API endpoints or controllers
- 🔴 Payment/Partner/Merchant specific code

## Dependencies

This library depends on:
- **Quarkus Platform**: Core Quarkus dependencies for CDI, REST, security
- **Incept5 Libraries**: External libraries for correlation, error handling, cryptography
- **Utility Libraries**: ULID generation, JWT handling, rate limiting
- **Testing**: JUnit 5, Kotest, Mockito for comprehensive test coverage

## Future

This internal library is designed for eventual extraction to an external repository
for reuse across other Incept5 projects. The current internal structure enables
validation and testing before external publishing.

## Integration with Existing Codebase

### CDI Bean Discovery
All beans in this library use standard CDI annotations and are automatically
discoverable by consuming Quarkus applications.

### Configuration
Configuration beans in this library integrate seamlessly with Quarkus's
configuration system and can be customized by consuming applications.

### Testing
The library includes comprehensive test coverage and integrates with the
existing test infrastructure of consuming projects.

---

*This library establishes the foundational architecture required for the Payment Transaction Management Epic's modularized monolith approach using a proven internal-first methodology.*
