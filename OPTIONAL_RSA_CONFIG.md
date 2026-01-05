# Optional RSA JWT Configuration

## Problem

When the Platform Core Library is used by services, some RSA JWT configuration properties may not be provided. Previously, using `@ConfigProperty` with empty `defaultValue = ""` caused Quarkus to fail at startup with errors like:

```
Missing value for property rsa-jwt.public-key
Missing value for property rsa-jwt.jwks-url
```

Even though these properties had default values specified, Quarkus still validated their presence, causing application startup failures when RSA authentication was not needed.

## Solution

The RSA-related configuration properties have been changed from `String` to `Optional<String>`, which properly signals to Quarkus that these properties are truly optional and the application can start without them.

### Changed Properties

```kotlin
// Before (caused startup failures)
@ConfigProperty(name = "rsa-jwt.public-key", defaultValue = "")
private val rsaPublicKey: String = ""

@ConfigProperty(name = "rsa-jwt.jwks-url", defaultValue = "")
private val jwksUrl: String = ""

// After (properly optional)
@ConfigProperty(name = "rsa-jwt.public-key")
private val rsaPublicKey: Optional<String>

@ConfigProperty(name = "rsa-jwt.jwks-url")
private val jwksUrl: Optional<String>
```

## Configuration Scenarios

### 1. RSA Disabled (Simplest Configuration)

When your service only uses Supabase tokens or Platform tokens with HMAC:

```properties
# application.properties
supabase.jwt.secret=your-jwt-secret
api.base.url=https://api.example.com

# Disable RSA and enable HMAC fallback for Platform tokens
rsa-jwt.enabled=false
rsa-jwt.hmac-fallback.enabled=true
```

**Note:** You don't need to specify `rsa-jwt.public-key` or `rsa-jwt.jwks-url` at all.

### 2. RSA with Explicit Public Key

When you want to validate Platform tokens signed with RSA using an explicit public key:

```properties
supabase.jwt.secret=your-jwt-secret
api.base.url=https://api.example.com

# Enable RSA with explicit public key
rsa-jwt.enabled=true
rsa-jwt.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
# No need to specify jwks-url
```

### 3. RSA with JWKS URL

When you want to validate Platform tokens using JWKS endpoint:

```properties
supabase.jwt.secret=your-jwt-secret
api.base.url=https://api.example.com

# Enable RSA with JWKS
rsa-jwt.enabled=true
rsa-jwt.jwks-url=https://your-auth-server.com/.well-known/jwks.json
# No need to specify public-key
```

### 4. RSA with HMAC Fallback

When you want to support both RSA and HMAC Platform tokens:

```properties
supabase.jwt.secret=your-jwt-secret
api.base.url=https://api.example.com

# Enable RSA with fallback to HMAC
rsa-jwt.enabled=true
rsa-jwt.public-key=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
rsa-jwt.hmac-fallback.enabled=true
```

## Algorithm Selection Priority

The `DualJwtValidator` uses the following priority when validating Platform tokens:

1. **JWKS Provider** (if `rsa-jwt.jwks-url` is configured and RSA is enabled)
2. **Explicit Public Key** (if `rsa-jwt.public-key` is configured and RSA is enabled)
3. **HMAC Fallback** (if `rsa-jwt.hmac-fallback.enabled=true`)
4. **Error** - If none of the above are configured and RSA is enabled

Supabase tokens always use HMAC256 with the `supabase.jwt.secret`.

## Migration Guide

If you're using an older version of this library, update your service configuration:

### Before (Required Configuration)

You had to specify all properties even if you didn't use them:

```properties
rsa-jwt.enabled=false
rsa-jwt.public-key=
rsa-jwt.jwks-url=
```

### After (Optional Configuration)

Simply omit the properties you don't need:

```properties
rsa-jwt.enabled=false
# That's it! No need to specify empty values
```

## Testing

The `OptionalConfigTest` class verifies that:

1. The validator can be created without RSA properties
2. Supabase tokens work regardless of RSA configuration
3. Platform tokens work with HMAC fallback when RSA is disabled
4. Appropriate errors are thrown when RSA is enabled but not properly configured
5. Blank RSA properties (empty strings) are handled gracefully

## Technical Details

### Why Optional<String> Works

Using `Optional<String>` instead of `String` with a default value tells MicroProfile Config (used by Quarkus) that:

- The property is truly optional and may not be present in the configuration
- No validation error should be thrown if the property is missing
- The application can start successfully without the property being defined

### Backward Compatibility

This change is **backward compatible** for services that:
- Already provide the RSA configuration properties
- Use the library's CDI injection (properties are injected by Quarkus)

Services need to update their **test code** if they manually construct `DualJwtValidator` instances:

```kotlin
// Update test instantiation
val validator = DualJwtValidator(
    jwtSecret = jwtSecret,
    baseApiUrl = baseApiUrl,
    rsaPublicKey = Optional.of(publicKey),  // Wrap in Optional
    jwksUrl = Optional.empty()              // Or use empty()
)
```

## Related Files

- `src/main/kotlin/org/incept5/platform/core/security/DualJwtValidator.kt` - Main implementation
- `src/test/kotlin/org/incept5/platform/core/security/OptionalConfigTest.kt` - Tests for optional configuration
- `src/test/kotlin/org/incept5/platform/core/security/DualJwtValidatorTest.kt` - Updated test fixtures
