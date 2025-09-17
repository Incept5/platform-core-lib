
package org.incept5.platform.core.security

import io.quarkus.test.junit.QuarkusTest
import io.restassured.RestAssured.given
import io.restassured.http.ContentType
import jakarta.ws.rs.GET
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import org.hamcrest.Matchers.*
import org.junit.jupiter.api.Test
import org.incept5.platform.core.model.EntityType
import org.incept5.platform.core.model.UserRole
import jakarta.inject.Inject
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import org.eclipse.microprofile.config.inject.ConfigProperty
import java.time.Instant
import java.util.*
import jakarta.annotation.security.RolesAllowed
import jakarta.enterprise.context.ApplicationScoped
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.SecurityContext
import jakarta.ws.rs.core.Response

/**
 * Integration test for authentication failure handling.
 * This test verifies that authentication failures result in proper error responses.
 * 
 * The test focuses on verifying that:
 * 1. Expired tokens are properly rejected
 * 2. Malformed tokens are properly rejected  
 * 3. Missing Authorization headers are properly handled
 * 4. Valid tokens are properly accepted
 * 5. The CustomAuthenticationFailureHandler processes errors correctly
 */
@QuarkusTest
class AuthenticationFailureIntegrationTest {

    @Inject
    lateinit var testJwtGenerator: TestJwtGenerator

    @ConfigProperty(name = "supabase.jwt.secret")
    lateinit var jwtSecret: String

    @ConfigProperty(name = "api.base.url")
    lateinit var apiBaseUrl: String

    @Test
    fun `should return 401 for expired token and demonstrate custom error handling`() {
        // Generate an expired token (expired 1 minute ago)
        val expiredToken = generateExpiredToken()

        given()
            .header("Authorization", "Bearer $expiredToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
            // The response should be JSON formatted (indicating custom handler processed it)
            .contentType(contentTypeMatches("application/json.*"))
    }

    @Test
    fun `should return 401 for malformed token and demonstrate custom error handling`() {
        val malformedToken = "invalid.jwt.token"

        given()
            .header("Authorization", "Bearer $malformedToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
            // The response should be JSON formatted (indicating custom handler processed it)
            .contentType(contentTypeMatches("application/json.*"))
    }

    @Test
    fun `should return 401 for token with invalid issuer and demonstrate custom error handling`() {
        // Generate a token with invalid issuer
        val invalidIssuerToken = generateTokenWithInvalidIssuer()

        given()
            .header("Authorization", "Bearer $invalidIssuerToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
            // The response should be JSON formatted (indicating custom handler processed it)
            .contentType(contentTypeMatches("application/json.*"))
    }

    @Test
    fun `should return 401 for token with invalid signature and demonstrate custom error handling`() {
        // Generate a token with a different secret (invalid signature)
        val invalidSignatureToken = generateTokenWithInvalidSignature()

        given()
            .header("Authorization", "Bearer $invalidSignatureToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
            // The response should be JSON formatted (indicating custom handler processed it)
            .contentType(contentTypeMatches("application/json.*"))
    }

    @Test
    fun `should return 401 when no Authorization header is provided`() {
        given()
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
    }

    @Test
    fun `should return 401 for invalid Authorization header format`() {
        given()
            .header("Authorization", "Basic dXNlcjpwYXNz") // Basic auth instead of Bearer
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(401)
    }

    @Test
    fun `should successfully authenticate with valid token`() {
        // Generate a valid token
        val validToken = testJwtGenerator.generateUserToken(
            TestUser(
                userId = UUID.fromString("12345678-1234-1234-1234-123456789012"),
                userRole = UserRole.entity_user,
                entityType = EntityType.partner,
                entityId = "partner-456"
            )
        )

        given()
            .header("Authorization", "Bearer $validToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/protected")
            .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("message", equalTo("Access granted"))
            .body("userId", equalTo("12345678-1234-1234-1234-123456789012"))
            .body("role", equalTo("entity_user"))
    }

    @Test
    fun `should return 403 for insufficient role permissions`() {
        // Generate a token with entity_user role trying to access admin endpoint
        val userToken = testJwtGenerator.generateUserToken(
            TestUser(
                userId = UUID.fromString("12345678-1234-1234-1234-123456789012"),
                userRole = UserRole.entity_user,
                entityType = EntityType.partner,
                entityId = "partner-456"
            )
        )

        given()
            .header("Authorization", "Bearer $userToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/admin-only")
            .then()
            .statusCode(403)
    }

    @Test
    fun `should successfully access admin endpoint with admin role`() {
        // Generate a token with platform_admin role
        val adminToken = testJwtGenerator.generateUserToken(
            TestUser(
                userId = UUID.fromString("87654321-4321-4321-4321-210987654321"),
                userRole = UserRole.platform_admin,
                entityType = null,
                entityId = null
            )
        )

        given()
            .header("Authorization", "Bearer $adminToken")
            .contentType(ContentType.JSON)
            .`when`()
            .get("/test/auth/admin-only")
            .then()
            .statusCode(200)
            .contentType(ContentType.JSON)
            .body("message", equalTo("Admin access granted"))
            .body("userId", equalTo("87654321-4321-4321-4321-210987654321"))
            .body("role", equalTo("platform_admin"))
    }

    /**
     * Generate an expired token for testing
     */
    private fun generateExpiredToken(): String {
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        val now = Instant.now()
        val expiredTime = now.minusSeconds(60) // 1 minute ago

        val appMetadata = mapOf(
            "entity_type" to EntityType.partner.name,
            "entity_id" to "test-partner-123"
        )

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(expiredTime.minusSeconds(3600))) // 1 hour before expiration
            .withExpiresAt(Date.from(expiredTime)) // Already expired
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("$apiBaseUrl/auth/v1")
            .withClaim("email", "test-user-123@test.com")
            .withClaim("app_metadata", appMetadata)
            .sign(algorithm)
    }

    /**
     * Generate a token with invalid issuer for testing
     */
    private fun generateTokenWithInvalidIssuer(): String {
        val algorithm = Algorithm.HMAC256(Base64.getDecoder().decode(jwtSecret))
        val now = Instant.now()

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(3600)))
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("https://invalid-issuer.com/auth/v1") // Invalid issuer
            .withClaim("email", "test-user-123@test.com")
            .sign(algorithm)
    }

    /**
     * Generate a token with invalid signature for testing
     */
    private fun generateTokenWithInvalidSignature(): String {
        val invalidSecret = "invalid-secret-key-that-does-not-match"
        val algorithm = Algorithm.HMAC256(invalidSecret.toByteArray())
        val now = Instant.now()

        val appMetadata = mapOf(
            "entity_type" to EntityType.partner.name,
            "entity_id" to "test-partner-123"
        )

        return JWT.create()
            .withSubject("12345678-1234-1234-1234-123456789012")
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plusSeconds(3600)))
            .withClaim("role", UserRole.entity_user.name)
            .withClaim("aud", "authenticated")
            .withIssuer("$apiBaseUrl/auth/v1") // Correct issuer
            .withClaim("email", "test-user-123@test.com")
            .withClaim("app_metadata", appMetadata)
            .sign(algorithm) // Signed with wrong secret
    }

    /**
     * Helper function to match content type patterns
     */
    private fun contentTypeMatches(pattern: String) = matchesPattern(pattern)
}

/**
 * Test controller for authentication testing
 */
@Path("/test/auth")
@Produces(MediaType.APPLICATION_JSON)
@ApplicationScoped
class TestAuthController {

    @GET
    @Path("/protected")
    @RolesAllowed("entity_user", "entity_admin", "platform_admin")
    fun protectedEndpoint(@Context securityContext: SecurityContext): Response {
        try {
            val principal = securityContext.userPrincipal as ApiPrincipal
            val response = mapOf(
                "message" to "Access granted",
                "userId" to principal.subject,
                "role" to principal.userRole.name,
                "entityType" to (principal.entityType?.name ?: "null"),
                "entityId" to (principal.entityId ?: "null")
            )
            return Response.ok(response).build()
        } catch (e: Exception) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(mapOf("error" to e.message)).build()
        }
    }

    @GET
    @Path("/admin-only")
    @RolesAllowed("platform_admin")
    fun adminOnlyEndpoint(@Context securityContext: SecurityContext): Response {
        try {
            val principal = securityContext.userPrincipal as ApiPrincipal
            val response = mapOf(
                "message" to "Admin access granted",
                "userId" to principal.subject,
                "role" to principal.userRole.name
            )
            return Response.ok(response).build()
        } catch (e: Exception) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(mapOf("error" to e.message)).build()
        }
    }

    @GET
    @Path("/public")
    fun publicEndpoint(): Response {
        val response = mapOf(
            "message" to "Public access - no authentication required"
        )
        return Response.ok(response).build()
    }
}
